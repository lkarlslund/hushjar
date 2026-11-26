"""Synthetic user-key envelopes: independent Python HMAC and OpenSSL AES."""
import base64
import hashlib
import hmac
import json
import subprocess
from pathlib import Path

root = Path(__file__).parent
master = bytes.fromhex('1f4f68e29647b15ac250acd1118184518aa745a7fe95021b27c5402a16c3564b')
# One-block HKDF-Expand with SHA256: HMAC(PRK, info || 0x01).
enc = hmac.digest(master, b'enc\x01', 'sha256')
mac_key = hmac.digest(master, b'mac\x01', 'sha256')
iv = bytes(range(16))
vectors = []
for size in (64, 0, 32, 63, 65):
    user_key = bytes(range(size))
    padding = 16 - len(user_key) % 16
    cipher = subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-nopad', '-K', enc.hex(), '-iv', iv.hex()], input=user_key + bytes([padding]) * padding, check=True, capture_output=True).stdout
    mac = hmac.digest(mac_key, iv + cipher, 'sha256')
    encoded = '2.' + '|'.join(base64.b64encode(x).decode() for x in (iv, cipher, mac))
    vectors.append(dict(master_hex=master.hex(), user_key_hex=user_key.hex(), encoded=encoded, valid=size == 64))
raw = json.dumps(vectors, indent=2) + '\n'
(root / 'user-key.json').write_text(raw)
manifest = json.loads((root / 'type2.manifest.json').read_text())
manifest.update(file='user-key.json', sha256=hashlib.sha256(raw.encode()).hexdigest(), origin='https://github.com/bitwarden/sdk-internal/blob/6ad7094edb4f2d391c6468f1fdfe8ac474a3c7e1/crates/bitwarden-crypto/src/keys/master_key.rs', generation='Run generate-user-key.py: Python HMAC HKDF-Expand enc/mac labels and OpenSSL AES-CBC produce synthetic user-key envelopes following pinned SDK wrapping. Includes authenticated wrong key lengths. Expectations are independent of Go implementation.')
(root / 'user-key.manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
