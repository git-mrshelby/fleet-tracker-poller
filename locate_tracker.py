import sys
import os
import time
sys.path.insert(0, os.path.dirname(__file__))

from NovaApi.ExecuteAction.LocateTracker.location_request import get_location_data_for_device
from NovaApi.ExecuteAction.LocateTracker.decrypt_locations import decrypt_location_response_locations, create_google_maps_link
from NovaApi.ListDevices.nbe_list_devices import request_device_list
from ProtoDecoders.decoder import parse_device_list_protobuf, get_canonic_ids
import json

print("[*] Requesting device list...")
result_hex = request_device_list()
device_list = parse_device_list_protobuf(result_hex)
canonic_ids = get_canonic_ids(device_list)

print(f"[+] Found {len(canonic_ids)} trackers:")
for name, cid in canonic_ids:
    print(f"    {name}: {cid}")

# Find the LocaTag
target_name = None
target_cid = None
for name, cid in canonic_ids:
    if 'LocaTag' in name or 'loca' in name.lower():
        target_name = name
        target_cid = cid
        break

if not target_name:
    print("[-] LocaTag not found!")
    sys.exit(1)

print(f"\n[*] Locating tracker: {target_name} ({target_cid})...")
print("[*] This may take 30-60 seconds (waiting for FCM response)...")

get_location_data_for_device(target_cid, target_name)
