"""
Fleet Tracker - LocaTag → Turso (libSQL) Pusher
Polls Google's FMD network, writes location straight to Turso over HTTP.
The app then reads from Turso — no laptop dependency at runtime.

Usage:
  python fleet_supabase_pusher.py --once          # Single poll
  python fleet_supabase_pusher.py --loop 300      # Poll every 60s for 300s (GitHub Actions mode)
  python fleet_supabase_pusher.py --interval 60   # Continuous (local dev)
"""

import sys
import os
import time
import json
import argparse
import hashlib
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(__file__))

from NovaApi.ExecuteAction.LocateTracker.location_request import (
    create_action_request, generate_random_uuid, NOVA_ACTION_API_SCOPE,
)
from NovaApi.ExecuteAction.LocateTracker.decrypt_locations import retrieve_identity_key
from NovaApi.nova_request import nova_request
from Auth.fcm_receiver import FcmReceiver
from ProtoDecoders import DeviceUpdate_pb2, Common_pb2
from ProtoDecoders.decoder import parse_device_update_protobuf
from FMDNCrypto.foreign_tracker_cryptor import decrypt as fmdn_decrypt
from KeyBackup.cloud_key_decryptor import decrypt_aes_gcm
import traceback
import requests

import turso_client as db

LOCATAG_CANONIC_ID = os.environ.get("LOCATAG_CANONIC_ID", "")
LOCATAG_NAME = "LocaTag"

# Empty-string env vars must fall back to the default (GitHub injects "" for
# secrets that don't exist, and "" is falsy — os.environ.get alone would keep it).
ORG_ID = os.environ.get("ORG_ID") or "00000000-0000-0000-0000-000000000001"

# Discovered trackers: list of (device_name, canonic_id).
# Populated once per process run via the FMD device-list API (same technique
# used to read tracker 1). Tracker 1's canonic_id is always included as a
# fallback so behaviour is identical to before if discovery fails.
DISCOVERED_TRACKERS: list = []


def discover_trackers():
    """List all trackers on the linked Google FMD account.

    Returns a list of (device_name, canonic_id) tuples using the same
    Google Find My Device device-list API that reads tracker 1.
    """
    try:
        from NovaApi.ListDevices.nbe_list_devices import request_device_list
        from ProtoDecoders.decoder import parse_device_list_protobuf, get_canonic_ids
        result_hex = request_device_list()
        device_list = parse_device_list_protobuf(result_hex)
        canonic_ids = get_canonic_ids(device_list)
        if canonic_ids:
            print(f"  [+] Discovered {len(canonic_ids)} tracker(s) on account:")
            for name, cid in canonic_ids:
                print(f"      - {name}: {cid}")
            return canonic_ids
    except Exception as e:
        print(f"  [-] Device discovery failed: {e}")
    # Fallback: if discovery fails and a canonic ID was supplied via env, keep
    # that single tracker working. Otherwise return no trackers.
    if LOCATAG_CANONIC_ID:
        return [(LOCATAG_NAME, LOCATAG_CANONIC_ID)]
    return []


def get_trackers():
    """Return cached discovered trackers, discovering once if needed."""
    global DISCOVERED_TRACKERS
    if not DISCOVERED_TRACKERS:
        DISCOVERED_TRACKERS = discover_trackers()
    return DISCOVERED_TRACKERS


def resolve_vehicle_id(canonic_id):
    """Look up the Turso vehicle id for a tracker (by tracker_id)."""
    try:
        row = db.query_one(
            "SELECT id FROM vehicles WHERE tracker_id = ? AND org_id = ?",
            [canonic_id, ORG_ID],
        )
        if row:
            return row[0]
    except Exception:
        pass
    return None


def locate_tracker(canonic_id):
    """Locate a LocaTag (by canonic_id) via Google's FMD network.
    Fast mode: skip sound trigger (LocaTag has no speaker),
    just send locateTracker and grab the first FCM response.
    """
    try:
        request_uuid = generate_random_uuid()
        result = [None]

        def handle_response(response_hex):
            device_update = parse_device_update_protobuf(response_hex)
            if device_update.fcmMetadata.requestUuid == request_uuid:
                result[0] = device_update

        fcm_token = FcmReceiver().register_for_location_updates(handle_response)

        # Send locateTracker directly (skip sound - LocaTag has no speaker)
        print("  [~] Sending locateTracker (fast mode, no sound)...")
        action_request = create_action_request(canonic_id, fcm_token, request_uuid)
        action_request.action.locateTracker.lastHighTrafficEnablingTime.seconds = int(time.time()) - (5 * 3600)
        action_request.action.locateTracker.contributorType = 2  # FMDN_ALL_LOCATIONS (matches BSkando HA integration)

        hex_payload = action_request.SerializeToString().hex()
        nova_request(NOVA_ACTION_API_SCOPE, hex_payload)

        # Wait for FCM response - first one is usually fresh enough
        timeout = 20
        start = time.time()

        while time.time() - start < timeout:
            if result[0] is not None:
                print(f"  [+] Got response in {time.time() - start:.1f}s")
                break
            time.sleep(0.3)

        if result[0] is None:
            print("  [-] Timeout")
            return None

        device_update = result[0]
        device_registration = device_update.deviceMetadata.information.deviceRegistration
        identity_key = retrieve_identity_key(device_registration)
        locations_proto = device_update.deviceMetadata.information.locationInformation.reports.recentLocationAndNetworkLocations
        locations = []

        if locations_proto.HasField("recentLocation"):
            loc = locations_proto.recentLocation
            time_val = locations_proto.recentLocationTimestamp
            if loc.status != Common_pb2.Status.SEMANTIC:
                encrypted_location = loc.geoLocation.encryptedReport.encryptedLocation
                public_key_random = loc.geoLocation.encryptedReport.publicKeyRandom
                # Official GoogleFindMyTools logic: empty publicKeyRandom means
                # this is the device's own GPS report (AES-GCM w/ identity key
                # hash); a non-empty value means it was relayed by the FMDN
                # network and must be decrypted with the FMDN foreign-tracker
                # cryptor instead.
                if public_key_random == b"":
                    identity_key_hash = hashlib.sha256(identity_key).digest()
                    decrypted = decrypt_aes_gcm(identity_key_hash, encrypted_location)
                else:
                    time_offset = loc.geoLocation.deviceTimeOffset
                    decrypted = fmdn_decrypt(identity_key, encrypted_location, public_key_random, time_offset)
                proto_loc = DeviceUpdate_pb2.Location()
                proto_loc.ParseFromString(decrypted)
                locations.append({
                    "latitude": proto_loc.latitude / 1e7,
                    "longitude": proto_loc.longitude / 1e7,
                    "accuracy_m": loc.geoLocation.accuracy,
                    "captured_at": datetime.fromtimestamp(int(time_val.seconds), tz=timezone.utc).isoformat(),
                })

        for loc, time_val in zip(locations_proto.networkLocations, locations_proto.networkLocationTimestamps):
            if loc.status == Common_pb2.Status.SEMANTIC:
                continue
            try:
                decrypted = fmdn_decrypt(
                    identity_key,
                    loc.geoLocation.encryptedReport.encryptedLocation,
                    loc.geoLocation.encryptedReport.publicKeyRandom,
                    loc.geoLocation.deviceTimeOffset,
                )
                proto_loc = DeviceUpdate_pb2.Location()
                proto_loc.ParseFromString(decrypted)
                locations.append({
                    "latitude": proto_loc.latitude / 1e7,
                    "longitude": proto_loc.longitude / 1e7,
                    "accuracy_m": loc.geoLocation.accuracy,
                    "captured_at": datetime.fromtimestamp(int(time_val.seconds), tz=timezone.utc).isoformat(),
                })
            except Exception as e:
                print(f"  [-] Decrypt error: {e}")

        if not locations:
            print("  [-] No locations decoded")
            return None

        return max(locations, key=lambda x: x["captured_at"])

    except Exception as e:
        print(f"  [-] Error: {e}")
        traceback.print_exc()
        return None


def push_to_turso(location, canonic_id, tracker_name=None):
    """Upsert vehicle + insert location log straight into Turso.

    Returns the vehicle_id.
    """
    try:
        now = datetime.now(timezone.utc).isoformat()
        captured_at = location.get("captured_at") or now
        lat = location["latitude"]
        lon = location["longitude"]
        accuracy = location.get("accuracy_m")

        rows = db.query(
            "SELECT id FROM vehicles WHERE tracker_id = ? AND org_id = ?",
            [canonic_id, ORG_ID],
        )
        if rows:
            vehicle_id = rows[0][0]
            if tracker_name:
                db.run(
                    "UPDATE vehicles SET name = COALESCE(?, name) WHERE id = ?",
                    [tracker_name, vehicle_id],
                )
        else:
            vehicle_id = db.new_id()
            db.run(
                "INSERT INTO vehicles (id, org_id, name, tracker_type, tracker_id, status,"
                " last_lat, last_lon, last_fix_at) VALUES (?, ?, ?, 'findmy', ?, 'parked', ?, ?, ?)",
                [vehicle_id, ORG_ID, tracker_name or "LocaTag", canonic_id, lat, lon, captured_at],
            )

        db.execute([
            (
                "UPDATE vehicles SET last_lat = ?, last_lon = ?, last_fix_at = ?,"
                " status = 'parked', updated_at = ? WHERE id = ?",
                [lat, lon, captured_at, now, vehicle_id],
            ),
            (
                "INSERT INTO location_logs (id, vehicle_id, org_id, lat, lon, accuracy_m,"
                " captured_at, source) VALUES (?, ?, ?, ?, ?, ?, ?, 'fmd-poller')",
                [db.new_id(), vehicle_id, ORG_ID, lat, lon, accuracy, captured_at],
            ),
        ])
        print(f"  [+] Pushed to Turso")
        return vehicle_id
    except Exception as e:
        print(f"  [-] Push error: {e}")
        return None


def haversine_m(lat1, lon1, lat2, lon2):
    """Distance in meters between two lat/lon points."""
    import math
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def insert_vehicle_event(event_type, vehicle_id, lat=None, lon=None, event_data=None):
    """Insert an event into vehicle_events table."""
    try:
        db.run(
            "INSERT INTO vehicle_events (id, vehicle_id, org_id, event_type, lat, lon, event_data)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                db.new_id(), vehicle_id, ORG_ID, event_type, lat, lon,
                json.dumps(event_data or {}),
            ],
        )
        print(f"  [!] Event: {event_type}")
    except Exception as e:
        print(f"  [-] Event insert error: {e}")


def get_last_movement_event(vehicle_id):
    """Get the last movement event type and timestamp for this vehicle."""
    try:
        row = db.query_one(
            "SELECT event_type, created_at FROM vehicle_events"
            " WHERE vehicle_id = ? AND event_type IN ('moving','idle','parked','offline')"
            " ORDER BY created_at DESC LIMIT 1",
            [vehicle_id],
        )
        if row:
            return row[0], row[1]
    except Exception:
        pass
    return None, None


def get_last_event_by_type(event_type, vehicle_id):
    """Get the last event timestamp for a specific event type."""
    try:
        row = db.query_one(
            "SELECT created_at FROM vehicle_events"
            " WHERE vehicle_id = ? AND event_type = ?"
            " ORDER BY created_at DESC LIMIT 1",
            [vehicle_id, event_type],
        )
        if row:
            return row[0]
    except Exception:
        pass
    return None


def can_insert_event(event_type, vehicle_id):
    """Check if we should insert this event (5 min cooldown per type)."""
    last_ts = get_last_event_by_type(event_type, vehicle_id)
    if last_ts is None:
        return True
    try:
        last_dt = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
        if (datetime.now(timezone.utc) - last_dt).total_seconds() < 300:
            return False
    except:
        pass
    return True


def get_last_location_time(vehicle_id):
    """Get the timestamp of the last successful location push."""
    try:
        row = db.query_one(
            "SELECT captured_at FROM location_logs WHERE vehicle_id = ?"
            " ORDER BY captured_at DESC LIMIT 1",
            [vehicle_id],
        )
        if row:
            return datetime.fromisoformat(row[0].replace("Z", "+00:00"))
    except Exception:
        pass
    return None


def get_recent_locations(vehicle_id, limit=5):
    """Get the most recent location points for a vehicle."""
    try:
        return db.query(
            "SELECT lat, lon, captured_at FROM location_logs WHERE vehicle_id = ?"
            " ORDER BY captured_at DESC LIMIT ?",
            [vehicle_id, limit],
        )
    except Exception:
        return []


RETENTION_MONTHS = int(os.environ.get("RETENTION_MONTHS", "6"))
_retention_last_run = 0.0


def enforce_retention():
    """Delete location_logs and vehicle_events older than RETENTION_MONTHS.

    Runs at most once per hour per process; best-effort (failures are logged
    and skipped — data is deleted on the next successful sweep).
    """
    global _retention_last_run
    now = time.time()
    if now - _retention_last_run < 3600:
        return
    _retention_last_run = now
    try:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=30 * RETENTION_MONTHS)
        ).isoformat()
        r1 = db.run("DELETE FROM location_logs WHERE captured_at < ?", [cutoff])
        r2 = db.run("DELETE FROM vehicle_events WHERE created_at < ?", [cutoff])
        if r1 or r2:
            print(f"  [~] Retention: deleted {r1} location logs, {r2} events older than {RETENTION_MONTHS} months")
    except Exception as e:
        print(f"  [-] Retention error: {e}")


def get_last_geofence_state(geofence_id, vehicle_id):
    """Get last geofence event type for a specific vehicle+geofence."""
    try:
        row = db.query_one(
            "SELECT type FROM geofence_events WHERE vehicle_id = ? AND geofence_id = ?"
            " ORDER BY occurred_at DESC LIMIT 1",
            [vehicle_id, geofence_id],
        )
        if row:
            return row[0]
    except Exception:
        pass
    return None


def check_geofences(lat, lon, vehicle_id):
    """Check geofence entry/exit and insert events only on state change."""
    try:
        geofences = db.query(
            "SELECT id, name, center_lat, center_lon, radius_meters, notify_on_enter, notify_on_exit"
            " FROM geofences WHERE deleted_at IS NULL"
        )
        if not geofences:
            return False

        inside_any = False
        for gf in geofences:
            gf_id, gf_name, c_lat, c_lon, radius = gf[0], gf[1], gf[2], gf[3], gf[4]
            notify_enter = gf[5] if gf[5] is not None else 1
            notify_exit = gf[6] if gf[6] is not None else 1
            dist = haversine_m(lat, lon, c_lat, c_lon)
            is_inside = dist <= radius

            last_type = get_last_geofence_state(gf_id, vehicle_id)

            event_type = None
            if last_type is None and is_inside:
                event_type = "enter"
            elif last_type == "exit" and is_inside:
                event_type = "enter"
            elif last_type == "enter" and not is_inside:
                event_type = "exit"

            if is_inside:
                inside_any = True

            if event_type is None:
                continue

            if event_type == "enter" and not notify_enter:
                continue
            if event_type == "exit" and not notify_exit:
                continue

            db.run(
                "INSERT INTO geofence_events (id, org_id, vehicle_id, geofence_id, type, occurred_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                [db.new_id(), ORG_ID, vehicle_id, gf_id, event_type, datetime.now(timezone.utc).isoformat()],
            )

            last_gf_event = get_last_geofence_state(gf_id, vehicle_id)
            new_gf_event = f"geofence_{event_type}"
            if last_gf_event != new_gf_event:
                insert_vehicle_event(new_gf_event, vehicle_id, lat, lon, {"zone": gf_name, "distance_m": round(dist)})
                print(f"  [!] Geofence '{gf_name}': {event_type.upper()} (distance: {dist:.0f}m)")

        return inside_any

    except Exception as e:
        print(f"  [-] Geofence check error: {e}")
        return False


def check_movement_status(lat, lon, vehicle_id, inside_any):
    """Determine navigating/idle/parked/offline based on time since last position."""
    try:
        last_event, _ = get_last_movement_event(vehicle_id)
        last_loc = get_last_location_time(vehicle_id)
        if not last_loc:
            return

        minutes_since = (datetime.now(timezone.utc) - last_loc).total_seconds() / 60
        hours_since = minutes_since / 60

        new_status = None
        if hours_since >= 2:
            new_status = "offline"
        elif minutes_since >= 20:
            new_status = "parked"
        elif minutes_since >= 5:
            new_status = "idle"
        else:
            # Last seen <5 min ago — check if actually moved (≥100m = genuine movement, not GPS drift)
            points = get_recent_locations(vehicle_id, 5)
            if len(points) >= 2:
                dist_old = haversine_m(points[0][0], points[0][1], points[-1][0], points[-1][1])
                if dist_old >= 100:
                    new_status = "moving"

        if new_status and new_status != last_event:
            insert_vehicle_event(new_status, vehicle_id, lat, lon, {} if new_status == "moving" else {"last_seen_min": round(minutes_since)})
            print(f"  [!] {new_status.title()}: last seen {minutes_since:.0f}min ago")

    except Exception as e:
        print(f"  [-] Movement check error: {e}")


def poll_once():
    """Poll every discovered tracker once and push to Turso.

    Returns True if at least one tracker was located and pushed successfully.
    """
    enforce_retention()
    trackers = get_trackers()
    any_ok = False

    for (name, canonic_id) in trackers:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Locating {name} ({canonic_id})...")
        loc = locate_tracker(canonic_id)
        if loc:
            print(f"  [+] {loc['latitude']:.6f}, {loc['longitude']:.6f}")
            vehicle_id = push_to_turso(loc, canonic_id, tracker_name=name)
            if vehicle_id:
                any_ok = True
                inside_any = check_geofences(loc["latitude"], loc["longitude"], vehicle_id)
                check_movement_status(loc["latitude"], loc["longitude"], vehicle_id, inside_any)
        else:
            print("  [-] Tracker not found")
            vehicle_id = resolve_vehicle_id(canonic_id)
            if vehicle_id:
                last_loc = get_last_location_time(vehicle_id)
                if last_loc:
                    minutes_since = (datetime.now(timezone.utc) - last_loc).total_seconds() / 60
                    hours_since = minutes_since / 60
                    last_event, _ = get_last_movement_event(vehicle_id)
                    new_status = None
                    if hours_since >= 2:
                        new_status = "offline"
                    elif minutes_since >= 20:
                        new_status = "parked"
                    elif minutes_since >= 5:
                        new_status = "idle"
                    if new_status and new_status != last_event:
                        insert_vehicle_event(new_status, vehicle_id, None, None, {"last_seen_min": round(minutes_since)})
                        print(f"  [!] {new_status.title()}: last seen {minutes_since:.0f}min ago")
                    elif new_status is None:
                        print(f"  [-] Skip: last seen {minutes_since:.0f}min ago (< 5min)")
                else:
                    if can_insert_event("offline", vehicle_id):
                        insert_vehicle_event("offline", vehicle_id, None, None, {"reason": "tracker_not_found"})
            else:
                print("  [-] No vehicle row yet for this tracker; will create on next successful locate")

    return any_ok


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fleet Tracker - Turso Pusher")
    parser.add_argument("--interval", type=int, default=45, help="Poll interval in seconds (default: 45)")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--loop", type=int, default=0, help="Run in loop mode for N seconds (e.g. 280 for GitHub Actions)")
    args = parser.parse_args()

    print("=" * 50)
    print("Fleet Tracker to Turso")
    print("=" * 50)
    print(f"Turso URL: {os.environ.get('TURSO_DATABASE_URL', '(not set)')}")
    print()

    if args.once:
        poll_once()
    elif args.loop > 0:
        # GitHub Actions mode: poll every 60s for up to N seconds
        start = time.time()
        poll_count = 0
        success_count = 0
        print(f"[*] Loop mode: polling every {args.interval}s for {args.loop}s")
        while time.time() - start < args.loop:
            poll_count += 1
            if poll_once():
                success_count += 1
            remaining = int(args.loop - (time.time() - start))
            if remaining > args.interval:
                print(f"[*] Next poll in {args.interval}s... ({remaining}s remaining)")
                time.sleep(args.interval)
            else:
                break
        elapsed = int(time.time() - start)
        print(f"\n[*] Done: {success_count}/{poll_count} polls successful in {elapsed}s")
    else:
        print("[*] Starting continuous push (Ctrl+C to stop)...")
        while True:
            poll_once()
            print(f"[*] Next in {args.interval}s...")
            time.sleep(args.interval)
