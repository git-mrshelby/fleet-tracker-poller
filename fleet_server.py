"""
Fleet Tracker - LocaTag Poller + Supabase Pusher
Polls Google's Find My Device network for your LocaTag location
and pushes to Supabase via Edge Function so the app shows live locations.

Usage: python fleet_poller_supabase.py [--interval 60]
"""

import sys
import os
import time
import json
import argparse
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(__file__))

from NovaApi.ExecuteAction.LocateTracker.location_request import (
    get_location_data_for_device,
    create_action_request,
    generate_random_uuid,
    NOVA_ACTION_API_SCOPE,
)
from NovaApi.ExecuteAction.LocateTracker.decrypt_locations import retrieve_identity_key
from NovaApi.ListDevices.nbe_list_devices import request_device_list
from NovaApi.nova_request import nova_request
from Auth.fcm_receiver import FcmReceiver
from ProtoDecoders import DeviceUpdate_pb2, Common_pb2
from ProtoDecoders.decoder import parse_device_update_protobuf, get_canonic_ids
from FMDNCrypto.foreign_tracker_cryptor import decrypt as fmdn_decrypt
from KeyBackup.cloud_key_decryptor import decrypt_aes_gcm

LOCATAG_CANONIC_ID = "6a26bdae-0000-2c8c-8057-d43a2cf67e9f"
LOCATAG_NAME = "LocaTag"

latest_location = {
    "latitude": None,
    "longitude": None,
    "accuracy_m": None,
    "captured_at": None,
    "trackers": [],
    "last_update": None,
    "error": None,
}
location_lock = threading.Lock()


def locate_tracker():
    """Locate the LocaTag and update shared state."""
    global latest_location

    try:
        request_uuid = generate_random_uuid()
        result = [None]

        def handle_location_response(response_hex):
            device_update = parse_device_update_protobuf(response_hex)
            if device_update.fcmMetadata.requestUuid == request_uuid:
                result[0] = device_update

        fcm_token = FcmReceiver().register_for_location_updates(handle_location_response)

        action_request = create_action_request(LOCATAG_CANONIC_ID, fcm_token, request_uuid)
        action_request.action.locateTracker.contributorType = 2

        hex_payload = action_request.SerializeToString().hex()
        nova_request(NOVA_ACTION_API_SCOPE, hex_payload)

        timeout = 90
        start = time.time()
        while result[0] is None and time.time() - start < timeout:
            time.sleep(0.5)

        if result[0] is None:
            with location_lock:
                latest_location["error"] = "Timeout waiting for location"
            print(f"  [-] Timeout")
            return

        device_update = result[0]
        device_registration = device_update.deviceMetadata.information.deviceRegistration
        identity_key = retrieve_identity_key(device_registration)

        locations_proto = device_update.deviceMetadata.information.locationInformation.reports.recentLocationAndNetworkLocations
        locations = []

        if locations_proto.HasField("recentLocation"):
            loc = locations_proto.recentLocation
            time_val = locations_proto.recentLocationTimestamp
            if loc.status != Common_pb2.Status.SEMANTIC:
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
                print(f"  [-] Decrypt error: {e}")

        if locations:
            latest = max(locations, key=lambda x: x["captured_at"])
            with location_lock:
                latest_location["latitude"] = latest["latitude"]
                latest_location["longitude"] = latest["longitude"]
                latest_location["accuracy_m"] = latest.get("accuracy_m")
                latest_location["captured_at"] = latest["captured_at"]
                latest_location["last_update"] = datetime.now(timezone.utc).isoformat()
                latest_location["error"] = None
                latest_location["trackers"] = [{
                    "id": LOCATAG_CANONIC_ID,
                    "name": LOCATAG_NAME,
                    "latitude": latest["latitude"],
                    "longitude": latest["longitude"],
                    "accuracy_m": latest.get("accuracy_m"),
                    "captured_at": latest["captured_at"],
                }]
            print(f"  [+] {latest['latitude']:.6f}, {latest['longitude']:.6f}")
        else:
            with location_lock:
                latest_location["error"] = "No locations decoded"

    except Exception as e:
        with location_lock:
            latest_location["error"] = str(e)
        print(f"  [-] Error: {e}")


def poll_loop(interval):
    """Continuously poll for location."""
    print(f"[*] Starting poll loop (interval: {interval}s)")
    while True:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Locating LocaTag...")
        locate_tracker()
        print(f"[*] Next poll in {interval}s")
        time.sleep(interval)


class LocationHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/location" or parsed.path == "/":
            with location_lock:
                data = latest_location.copy()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode())

        elif parsed.path == "/trackers":
            with location_lock:
                trackers = latest_location.get("trackers", [])
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"trackers": trackers}, indent=2).encode())

        elif parsed.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())

        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default logging


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fleet Tracker Server")
    parser.add_argument("--port", type=int, default=8082, help="HTTP port (default: 8082)")
    parser.add_argument("--interval", type=int, default=60, help="Poll interval in seconds (default: 60)")
    args = parser.parse_args()

    print("=" * 50)
    print("Fleet Tracker - LocaTag Server")
    print("=" * 50)
    print(f"HTTP server: http://0.0.0.0:{args.port}")
    print(f"Poll interval: {args.interval}s")
    print(f"Endpoints:")
    print(f"  GET /location  - Latest location")
    print(f"  GET /trackers  - All trackers")
    print(f"  GET /health    - Health check")
    print()

    # Do initial locate
    print("[*] Initial location fetch...")
    locate_tracker()

    # Start poll thread
    poll_thread = threading.Thread(target=poll_loop, args=(args.interval,), daemon=True)
    poll_thread.start()

    # Start HTTP server
    server = HTTPServer(("0.0.0.0", args.port), LocationHandler)
    print(f"\n[*] Server running on port {args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped")
