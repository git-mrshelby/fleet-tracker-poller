"""
Fleet Tracker - LocaTag → Supabase Pusher
Polls Google's FMD network, pushes location to Supabase via Edge Function.
The app then reads from Supabase Realtime — no laptop dependency at runtime.

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
from datetime import datetime, timezone

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

LOCATAG_CANONIC_ID = "6a26bdae-0000-2c8c-8057-d43a2cf67e9f"
LOCATAG_NAME = "LocaTag"

SUPABASE_URL = "https://sctpsakdkwyojcqxwvsj.supabase.co"
EDGE_FUNCTION_URL = f"{SUPABASE_URL}/functions/v1/push-location"
SUPABASE_ANON_KEY = "sb_publishable_26NwdXByyYdQ0JNh6sFiDQ_CZfnV1jS"


def locate_tracker():
    """Locate the LocaTag via Google's FMD network."""
    try:
        request_uuid = generate_random_uuid()
        result = [None]

        def handle_response(response_hex):
            device_update = parse_device_update_protobuf(response_hex)
            if device_update.fcmMetadata.requestUuid == request_uuid:
                result[0] = device_update

        fcm_token = FcmReceiver().register_for_location_updates(handle_response)
        action_request = create_action_request(LOCATAG_CANONIC_ID, fcm_token, request_uuid)
        action_request.action.locateTracker.contributorType = 2

        hex_payload = action_request.SerializeToString().hex()
        nova_request(NOVA_ACTION_API_SCOPE, hex_payload)

        timeout = 90
        start = time.time()
        while result[0] is None and time.time() - start < timeout:
            time.sleep(0.5)

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
                identity_key_hash = hashlib.sha256(identity_key).digest()
                decrypted = decrypt_aes_gcm(identity_key_hash, encrypted_location)
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


def push_to_supabase(location):
    """Push location to Supabase via Edge Function."""
    try:
        resp = requests.post(
            EDGE_FUNCTION_URL,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
            },
            json={
                "tracker_id": LOCATAG_CANONIC_ID,
                "name": LOCATAG_NAME,
                "latitude": location["latitude"],
                "longitude": location["longitude"],
                "captured_at": location["captured_at"],
                "accuracy_m": location.get("accuracy_m"),
            },
            timeout=10,
        )
        if resp.status_code == 200:
            print(f"  [+] Pushed to Supabase")
            return True
        else:
            print(f"  [-] Edge Function error: {resp.status_code} {resp.text[:200]}")
            return False
    except Exception as e:
        print(f"  [-] Push error: {e}")
        return False


def poll_once():
    """Poll location once and push to Supabase. Returns True if successful."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Locating...")
    loc = locate_tracker()
    if loc:
        print(f"  [+] {loc['latitude']:.6f}, {loc['longitude']:.6f}")
        return push_to_supabase(loc)
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fleet Tracker - Supabase Pusher")
    parser.add_argument("--interval", type=int, default=60, help="Poll interval (default: 60s)")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--loop", type=int, default=0, help="Run in loop mode for N seconds (e.g. 280 for GitHub Actions)")
    args = parser.parse_args()

    print("=" * 50)
    print("Fleet Tracker to Supabase")
    print("=" * 50)
    print(f"Edge Function: {EDGE_FUNCTION_URL}")
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
