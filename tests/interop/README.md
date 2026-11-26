# Vaultwarden test server

A pinned Vaultwarden 1.37.3 for the interop tests, copied from VaultGoblin's
fixture. It listens on http://127.0.0.1:18281, allows sign-ups for invented
test accounts, and keeps its data in memory: stopping it loses everything.

```sh
docker compose -f tests/interop/compose.yaml up -d --wait --wait-timeout 120
HUSHJAR_INTEROP=http://127.0.0.1:18281 cargo test -p hushjar-core --test interop -- --test-threads=1
docker compose -f tests/interop/compose.yaml down
```

Use only invented credentials. Rate limits are raised so repeated test runs
are not throttled.
