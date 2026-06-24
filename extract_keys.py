import sys
import os
import base64
import hashlib
sys.path.insert(0, os.path.dirname(__file__))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from SpotApi.GetEidInfoForE2eeDevices.get_owner_key import get_owner_key
from NovaApi.ListDevices.nbe_list_devices import request_device_list
from ProtoDecoders.decoder import parse_device_list_protobuf, get_canonic_ids
from SpotApi.CreateBleDevice.util import flip_bits
from KeyBackup.cloud_key_decryptor import decrypt_eik
from FMDNCrypto.key_derivation import FMDNOwnerOperations
import json

def raw_bytes_to_pem(raw_key: bytes) -> str:
    """Convert 32-byte raw ECDH P-256 private key to PKCS8 PEM."""
    int_val = int.from_bytes(raw_key, 'big')
    private_key = ec.derive_private_key(int_val, ec.SECP256R1(), default_backend())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')

def generate_eid(identity_key: bytes, nonce: int = 0) -> str:
    """Generate an EID from identity key (8-byte truncated SHA256)."""
    data = identity_key + bytes([nonce])
    h = hashlib.sha256(data).digest()[:8]
    return h.hex()

print("[*] Retrieving owner key...")
owner_key = get_owner_key()
print(f"[+] Owner key: {owner_key.hex() if isinstance(owner_key, bytes) else owner_key}")

print("[*] Requesting device list...")
result_hex = request_device_list()
device_list = parse_device_list_protobuf(result_hex)

canonic_ids = get_canonic_ids(device_list)
print(f"[+] Found {len(device_list.deviceMetadata)} devices")
print(f"[+] Canonic IDs: {canonic_ids}")

for device in device_list.deviceMetadata:
    name = device.userDefinedDeviceName
    dev_reg = device.information.deviceRegistration
    
    eik_data = dev_reg.encryptedUserSecrets.encryptedIdentityKey
    if not eik_data or len(eik_data) not in (48, 60):
        print(f"\n[*] Skipping {name} (not a tracker or no encrypted EIK)")
        continue
    
    is_mcu = (dev_reg.fastPairModelId == "003200") if dev_reg.fastPairModelId else False
    encrypted_eik = flip_bits(eik_data, is_mcu)
    
    print(f"\n[*] Decrypting key for: {name}")
    identity_key = decrypt_eik(owner_key, encrypted_eik)
    print(f"[+] Identity key (hex): {identity_key.hex()}")
    
    pem = raw_bytes_to_pem(identity_key)
    eid = generate_eid(identity_key)
    
    keys = FMDNOwnerOperations()
    keys.generate_keys(identity_key)
    print(f"[+] EID: {eid}")
    print(f"[+] Recovery key:  {keys.recovery_key.hex()}")
    print(f"[+] Ringing key:   {keys.ringing_key.hex()}")
    print(f"[+] Tracking key:  {keys.tracking_key.hex()}")

result = {
    "owner_key": owner_key.hex() if isinstance(owner_key, bytes) else owner_key,
    "devices": []
}

for device in device_list.deviceMetadata:
    name = device.userDefinedDeviceName
    dev_reg = device.information.deviceRegistration
    
    eik_data = dev_reg.encryptedUserSecrets.encryptedIdentityKey
    if not eik_data or len(eik_data) not in (48, 60):
        continue
    
    is_mcu = (dev_reg.fastPairModelId == "003200") if dev_reg.fastPairModelId else False
    encrypted_eik = flip_bits(eik_data, is_mcu)
    identity_key = decrypt_eik(owner_key, encrypted_eik)
    pem = raw_bytes_to_pem(identity_key)
    eid = generate_eid(identity_key)
    keys = FMDNOwnerOperations()
    keys.generate_keys(identity_key)
    
    result["devices"].append({
        "name": name,
        "device_id": eid,
        "eid": eid,
        "identity_key": identity_key.hex(),
        "private_key_pem": pem,
        "recovery_key": keys.recovery_key.hex(),
        "ringing_key": keys.ringing_key.hex(),
        "tracking_key": keys.tracking_key.hex()
    })

with open("extracted_keys.json", "w") as f:
    json.dump(result, f, indent=2)

print("\n[+] Keys saved to extracted_keys.json")
