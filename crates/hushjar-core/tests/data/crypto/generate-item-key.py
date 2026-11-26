"""Independent synthetic personal-item key selection oracle."""
import base64
import hashlib
import hmac
import json
import subprocess
from pathlib import Path

root = Path(__file__).parent
parent = bytes(range(64))
child = bytes(reversed(range(64)))

def encrypt(key, plain):
    iv = bytes(range(16))
    padding = 16 - len(plain) % 16
    ciphertext = subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-nopad', '-K', key[:32].hex(), '-iv', iv.hex()], input=plain + bytes([padding]) * padding, capture_output=True, check=True).stdout
    mac = hmac.digest(key[32:], iv + ciphertext, 'sha256')
    return '2.' + '|'.join(base64.b64encode(x).decode() for x in (iv, ciphertext, mac))

raw = json.dumps(dict(parent_hex=parent.hex(), wrapped=encrypt(parent, child), field=encrypt(child, b'item field'), legacy_field=encrypt(parent, b'legacy field')), indent=2) + '\n'
(root / 'item-key.json').write_text(raw)
manifest = json.loads((root / 'type2.manifest.json').read_text())
manifest.update(file='item-key.json', sha256=hashlib.sha256(raw.encode()).hexdigest(), origin='https://github.com/bitwarden/clients/blob/e40ce6f08ebf963db3561464e77b4defe05247e8/libs/common/src/vault/services/cipher.service.ts', upstream_commit='e40ce6f08ebf963db3561464e77b4defe05247e8', generation='Run generate-item-key.py with OpenSSL AES-CBC and Python HMAC. Synthetic parent/item keys exercise pinned client cipher.key != null unwrap selection; absent key uses vault key. No Go implementation generates expectations.')
(root / 'item-key.manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
