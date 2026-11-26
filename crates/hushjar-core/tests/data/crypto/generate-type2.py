"""Original synthetic vectors using OpenSSL AES and Python HMAC, not Go code."""
import base64
import hashlib
import hmac
import json
import subprocess
from pathlib import Path

root = Path(__file__).parent
key = bytes(range(64))
iv = bytes(range(16))
vectors = []
for plaintext in [b'', b'hello', bytes(range(16)), 'synthetic 🔐\0 secret'.encode()]:
    padding = 16 - len(plaintext) % 16
    vectors.append((plaintext, plaintext + bytes([padding]) * padding, True))
# Authenticated invalid padding exercises unpadding independently of MAC rejection.
for padded in [b'A' * 15 + b'\0', b'A' * 15 + b'\x11', b'A' * 14 + b'\x01\x02']:
    vectors.append((b'', padded, False))
result = []
for plaintext, padded, valid in vectors:
    ciphertext = subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-nopad', '-K', key[:32].hex(), '-iv', iv.hex()], input=padded, check=True, capture_output=True).stdout
    mac = hmac.digest(key[32:], iv + ciphertext, 'sha256')
    encoded = '2.' + '|'.join(base64.b64encode(x).decode() for x in (iv, ciphertext, mac))
    result.append(dict(key_hex=key.hex(), encoded=encoded, plaintext_hex=plaintext.hex(), valid=valid))
raw = json.dumps(result, indent=2) + '\n'
(root / 'type2.json').write_text(raw)
manifest = json.loads((root / 'encstring.manifest.json').read_text())
manifest.update(file='type2.json', sha256=hashlib.sha256(raw.encode()).hexdigest(), license='Original synthetic fixtures and factual cryptographic outputs; CC0-1.0. No upstream implementation copied.', generation='Run generate-type2.py using OpenSSL enc AES-256-CBC -nopad and Python hmac SHA256 over IV || ciphertext. Original deterministic key/IV and synthetic inputs; includes authenticated invalid PKCS7 padding. Format follows pinned SDK symmetric.rs, outputs are independent OpenSSL/Python oracle results, not upstream literal vectors.')
(root / 'type2.manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
