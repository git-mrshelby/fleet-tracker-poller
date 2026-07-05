"""
Fleet Tracker - LocaTag Poller
Polls Google's Find My Device network for your LocaTag location
and pushes decrypted coordinates to Supabase in real-time.

Usage: python fleet_poller.py [--interval 120]
"""

import sys
import os
import time
import json
import argparse
import requests
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))

from NovaApi.ExecuteAction.LocateTracker.location_request import get_location_data_for_device
from NovaApi.ExecuteAction.LocateTracker.decrypt_locations import retrieve_identity_key
from NovaApi.ListDevices.nbe_list_devices import request_device_list
from NovaApi.ExecuteAction.LocateTracker.location_request import create_action_request, generate_random_uuid
from Auth.fcm_receiver import FcmReceiver
from NovaApi.nova_request import nova_request
from NovaApi.ExecuteAction.LocateTracker.location_request import NOVA_ACTION_API_SCOPE
from ProtoDecoders import DeviceUpdate_pb2
from ProtoDecoders.decoder import parse_device_update_protobuf, get_canonic_ids
from SpotApi.CreateBleDevice.util import flip_bits

# Supabase config
SUPABASE_URL = "https://sctpsakdkwyojcqxwvsj.supabase.co"
SUPABASE_ANON_KEY = "sb_publishable_26NwdXByyYdQ0JNh6sFiDQ_CZfnV1jS"

# Track the LocaTag canonic ID
LOCATAG_CANONIC_ID = "6a26bdae-0000-2c8c-8057-d43a2cf67e9f"
LOCATAG_NAME = "LocaTag"


def locate_and_push(supabase_token=None):
    """Locate the LocaTag and push to Supabase."""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Locating LocaTag...")

    try:
        request_uuid = generate_random_uuid()
        result = [None]

        def handle_location_response(response_hex):
            device_update = parse_device_update_protobuf(response_hex)
            if device_update.fcmMetadata.requestUuid == request_uuid:
                result[0] = device_update

        fcm_token = FcmReceiver().register_for_location_updates(handle_location_response)

        action_request = create_action_request(LOCATAG_CANONIC_ID, fcm_token, request_uuid)
        action_request.action.locateTracker.lastHighTrafficEnablingTime.seconds = int(time.time()) - (5 * 3600)
        action_request.action.locateTracker.contributorType = 2  # FMDN_ALL_LOCATIONS

        from ProtoDecoders import Common_pb2
        hex_payload = action_request.SerializeToString().hex()
        nova_request(NOVA_ACTION_API_SCOPE, hex_payload)

        timeout = 120
        start = time.time()
        while result[0] is None and time.time() - start < timeout:
            time.sleep(0.5)

        if result[0] is None:
            print("  [-] Timeout waiting for location response")
            return None

        device_update = result[0]
        device_registration = device_update.deviceMetadata.information.deviceRegistration
        identity_key = retrieve_identity_key(device_registration)

        locations_proto = device_update.deviceMetadata.information.locationInformation.reports.recentLocationAndNetworkLocations

        locations = []

        # Own reports (AES-GCM with SHA256 of identity key)
        if locations_proto.HasField("recentLocation"):
            loc = locations_proto.recentLocation
            time_val = locations_proto.recentLocationTimestamp

            if loc.status != Common_pb2.Status.SEMANTIC:
                from KeyBackup.cloud_key_decryptor import decrypt_aes_gcm
                import hashlib

                encrypted_location = loc.geoLocation.encryptedReport.encryptedLocation
                identity_key_hash = hashlib.sha256(identity_key).digest()
                decrypted = decrypt_aes_gcm(identity_key_hash, encrypted_location)

                proto_loc = DeviceUpdate_pb2.Location()
                proto_loc.ParseFromString(decrypted)

                locations.append({
                    "latitude": proto_loc.latitude / 1e7,
                    "longitude": proto_loc.longitude / 1e7,
                    "accuracy_m": loc.geoLocation.accuracy,
                    "captured_at": datetime.fromtimestamp(int(time_val.seconds), tz=timezone.utc).isoformat(),
                    "is_own_report": True,
                })

        # Crowd-sourced reports (ECDH + AES-EAX)
        from FMDNCrypto.foreign_tracker_cryptor import decrypt as fmdn_decrypt
        from ProtoDecoders import Common_pb2

        network_locations = list(locations_proto.networkLocations)
        network_times = list(locations_proto.networkLocationTimestamps)

        for loc, time_val in zip(network_locations, network_times):
            if loc.status == Common_pb2.Status.SEMANTIC:
                continue

            try:
                encrypted_location = loc.geoLocation.encryptedReport.encryptedLocation
                public_key_random = loc.geoLocation.encryptedReport.publicKeyRandom
                time_offset = loc.geoLocation.deviceTimeOffset

                decrypted = fmdn_decrypt(identity_key, encrypted_location, public_key_random, time_offset)

                proto_loc = DeviceUpdate_pb2.Location()
                proto_loc.ParseFromString(decrypted)

                locations.append({
                    "latitude": proto_loc.latitude / 1e7,
                    "longitude": proto_loc.longitude / 1e7,
                    "accuracy_m": loc.geoLocation.accuracy,
                    "captured_at": datetime.fromtimestamp(int(time_val.seconds), tz=timezone.utc).isoformat(),
                    "is_own_report": False,
                })
            except Exception as e:
                print(f"  [-] Failed to decrypt report: {e}")

        if not locations:
            print("  [-] No locations decoded")
            return None

        # Use the most recent location
        latest = max(locations, key=lambda x: x["captured_at"])
        print(f"  [+] Location: {latest['latitude']:.6f}, {latest['longitude']:.6f}")
        print(f"  [+] Time: {latest['captured_at']}")
        print(f"  [+] Accuracy: {latest.get('accuracy_m', 'N/A')}m")
        print(f"  [+] https://www.google.com/maps/search/?api=1&query={latest['latitude']},{latest['longitude']}")

        # Push to Supabase
        if supabase_token:
            push_to_supabase(latest, supabase_token)

        return latest

    except Exception as e:
        print(f"  [-] Error: {e}")
        import traceback
        traceback.print_exc()
        return None


def push_to_supabase(location, token):
    """Push location to Supabase vehicles + location_logs tables."""
    try:
        headers = {
            "apikey": SUPABASE_ANON_KEY,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates,return=representation",
        }

        # Get user's org_id from profiles
        profile_resp = requests.get(
            f"{SUPABASE_URL}/rest/v1/profiles?select=org_id&id=eq.{get_user_id(token)}",
            headers=headers,
        )
        org_id = None
        if profile_resp.status_code == 200 and profile_resp.json():
            org_id = profile_resp.json()[0].get("org_id")
        if not org_id:
            org_id = "00000000-0000-0000-0000-000000000001"
            print(f"  [!] Using default org_id: {org_id}")

        # Upsert vehicle
        vehicle_data = {
            "org_id": org_id,
            "name": "LocaTag",
            "tracker_type": "findmy",
            "tracker_id": LOCATAG_CANONIC_ID,
            "status": "parked",
            "last_lat": location["latitude"],
            "last_lon": location["longitude"],
            "last_fix_at": location["captured_at"],
        }

        resp = requests.post(
            f"{SUPABASE_URL}/rest/v1/vehicles",
            headers={**headers, "Prefer": "resolution=merge-duplicates"},
            json=vehicle_data,
        )

        if resp.status_code in (200, 201):
            print(f"  [+] Upserted vehicle")
        else:
            print(f"  [-] vehicles error: {resp.status_code} {resp.text[:200]}")
            return

        # Get vehicle ID
        v_resp = requests.get(
            f"{SUPABASE_URL}/rest/v1/vehicles?select=id&tracker_id=eq.{LOCATAG_CANONIC_ID}&org_id=eq.{org_id}",
            headers=headers,
        )
        vehicle_id = None
        if v_resp.status_code == 200 and v_resp.json():
            vehicle_id = v_resp.json()[0]["id"]

        if not vehicle_id:
            print(f"  [-] Could not find vehicle ID")
            return

        # Insert location_log using PostGIS ST_Point
        lat = location["latitude"]
        lon = location["longitude"]
        log_data = {
            "vehicle_id": vehicle_id,
            "org_id": org_id,
            "captured_at": location["captured_at"],
            "accuracy_m": location.get("accuracy_m"),
            "source": "fmd-poller",
        }

        # Use RPC to insert with geography
        rpc_resp = requests.post(
            f"{SUPABASE_URL}/rest/v1/rpc/insert_location_log",
            headers=headers,
            json={
                "p_vehicle_id": vehicle_id,
                "p_org_id": org_id,
                "p_lat": lat,
                "p_lon": lon,
                "p_captured_at": location["captured_at"],
                "p_accuracy_m": location.get("accuracy_m"),
            },
        )

        if rpc_resp.status_code in (200, 201):
            print(f"  [+] Inserted location log")
        else:
            # Fallback: insert directly without geography column
            print(f"  [!] RPC failed ({rpc_resp.status_code}), trying direct insert...")
            log_data["geog"] = f"SRID=4326;POINT({lon} {lat})"
            resp2 = requests.post(
                f"{SUPABASE_URL}/rest/v1/location_logs",
                headers=headers,
                json=log_data,
            )
            if resp2.status_code in (200, 201):
                print(f"  [+] Inserted location log (direct)")
            else:
                print(f"  [-] location_logs error: {resp2.status_code} {resp2.text[:200]}")

    except Exception as e:
        print(f"  [-] Supabase push error: {e}")


def get_user_id(token):
    """Extract user ID from JWT."""
    import base64
    try:
        parts = token.split(".")
        if len(parts) == 3:
            payload = parts[1]
            # Add padding
            payload += "=" * (4 - len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload)
            data = json.loads(decoded)
            return data.get("sub", "")
    except:
        pass
    return ""


def get_supabase_token(email, password):
    """Get Supabase auth token."""
    try:
        resp = requests.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
            headers={
                "apikey": SUPABASE_ANON_KEY,
                "Content-Type": "application/json",
            },
            json={"email": email, "password": password},
        )
        data = resp.json()
        if "access_token" in data:
            return data["access_token"]
        else:
            print(f"[-] Auth failed: {data}")
            return None
    except Exception as e:
        print(f"[-] Auth error: {e}")
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fleet Tracker - LocaTag Poller")
    parser.add_argument("--interval", type=int, default=120, help="Poll interval in seconds (default: 120)")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--email", default="[email protected]", help="Supabase email")
    parser.add_argument("--password", default="airtag@5", help="Supabase password")
    args = parser.parse_args()

    print("=" * 50)
    print("Fleet Tracker - LocaTag Poller")
    print("=" * 50)
    print(f"Poll interval: {args.interval}s")
    print(f"Supabase: {SUPABASE_URL}")
    print()

    # Authenticate with Supabase
    print("[*] Authenticating with Supabase...")
    token = get_supabase_token(args.email, args.password)
    if token:
        print("[+] Authenticated")
    else:
        print("[-] Auth failed, continuing without Supabase push")
        token = None

    if args.once:
        locate_and_push(token)
    else:
        print(f"\n[*] Starting continuous polling (Ctrl+C to stop)...")
        while True:
            locate_and_push(token)
            print(f"[*] Next poll in {args.interval}s...")
            time.sleep(args.interval)
