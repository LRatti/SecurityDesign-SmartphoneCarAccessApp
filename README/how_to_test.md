# How To Test – Smartphone Car Access PoC (Windows)

This guide shows how to set up, run, and test the full proof‑of‑concept on Windows using PowerShell. It covers mutual TLS (mTLS) setup, signup/login, car registration, access delegation, revocation, and validation flows across the App Client, Car Server, and Backend Server.

## Prerequisites
- Python: Install Python 3.10+ and ensure `python` is on PATH.
- Packages: The code uses the standard library and `cryptography`. Install with:

```powershell
pip install cryptography
```

- OpenSSL: Install an OpenSSL binary for Windows and ensure `openssl` is on PATH.
	- Verify: `openssl version`
	- If not installed, use e.g. Shining Light Productions (Win64 OpenSSL) or Chocolatey: `choco install openssl`.
- Terminals: Use three PowerShell windows (Backend, Car, App). A fourth is handy for a second user.
- Workspace: All commands assume the repo root `SecurityDesign-SmartphoneCarAccessApp`.

## Clean Slate (recommended)
- If you ran older versions, remove or reset server data to avoid format conflicts:

```powershell
Remove-Item -Force -ErrorAction SilentlyContinue "data/server_data/registrations.json"
Remove-Item -Force -ErrorAction SilentlyContinue "data/server_data/cars.json"
Remove-Item -Force -ErrorAction SilentlyContinue "data/server_data/delegations.json"
```

## Generate TLS Certificates (skip if `certs/` already has them)
We need a Root CA, an Intermediate CA (for user certs), and server/client certs for Backend, Car, and App. Run in repo root.

**Windows OpenSSL Fix:** If you encounter `Can't open openssl.cnf` errors, add `-config NUL` to bypass the config file requirement (safe for these simple cert operations).

```powershell
# Ensure folder exists
New-Item -ItemType Directory -Force -Path certs | Out-Null

# 1) Root CA
openssl genpkey -algorithm RSA -out certs/ca-key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key certs/ca-key.pem -out certs/ca-cert.pem -days 3650 -subj "/CN=Test Root CA" -config NUL

# 2) Backend Server key + CSR
openssl genpkey -algorithm RSA -out certs/backend-key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -key certs/backend-key.pem -out certs/backend-csr.pem -subj "/CN=localhost" -config NUL

# 2b) Intermediate CA for users (key + CSR)
openssl genpkey -algorithm RSA -out certs/intermediate-ca-key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -key certs/intermediate-ca-key.pem -out certs/intermediate-ca-csr.pem -subj "/CN=Intermediate CA for User Certificates" -config NUL

# 2c) Create extension file for intermediate CA (if not exists)
# The v3_intermediate_ca.ext file should contain:
# basicConstraints = critical, CA:true, pathlen:0
# keyUsage = critical, digitalSignature, cRLSign, keyCertSign

# 3) Sign Backend + Intermediate
openssl x509 -req -in certs/backend-csr.pem -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/backend-cert.pem -days 365
openssl x509 -req -in certs/intermediate-ca-csr.pem -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/intermediate-ca-cert.pem -days 365 -extfile certs/v3_intermediate_ca.ext

# 3b) Chain CA (Intermediate + Root)
Get-Content certs/intermediate-ca-cert.pem, certs/ca-cert.pem | Set-Content certs/ca-chain.pem

# 4) Car Server key + CSR
openssl genpkey -algorithm RSA -out certs/car-key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -key certs/car-key.pem -out certs/car-csr.pem -subj "/CN=localhost" -config NUL

# 5) Sign Car Server
openssl x509 -req -in certs/car-csr.pem -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/car-cert.pem -days 365

# 6) App Client key + CSR (provisioning or per-user)
openssl genpkey -algorithm RSA -out certs/app-key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -key certs/app-key.pem -out certs/app-csr.pem -subj "/CN=MyTestAppClient" -config NUL

# 7) Sign App Client
openssl x509 -req -in certs/app-csr.pem -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/app-cert.pem -days 365

# Optional cleanup
# Remove-Item certs/*.csr, certs/*.srl
```

Verify that `certs/ca-cert.pem`, `certs/ca-key.pem`, `certs/backend-cert.pem`, `certs/backend-key.pem`, `certs/intermediate-ca-cert.pem`, `certs/intermediate-ca-key.pem`, `certs/ca-chain.pem`, `certs/car-cert.pem`, `certs/car-key.pem`, `certs/app-cert.pem`, and `certs/app-key.pem` exist.

## Start Backend Server (mTLS)
Open PowerShell window 1 in repo root and run:

```powershell
python backend_server.py
```

Expected: logs show SSL context creation and “Backend server listening securely (TLS)”. It will read/create `data/server_data/*.json`.

## Start Car Server (mTLS)
Open PowerShell window 2 in repo root and run:

```powershell
# Optional: set car ID for this session
# $env:CAR_ID = "CAR_VIN_DEMO_789"

python car_server.py
```

Expected: logs show incoming TLS context (App→Car) and outgoing TLS context (Car→Backend). Note the Car ID (default `CAR_VIN_DEMO_789`). Leave running.

## Run App Client – User 1 (Owner)
Open PowerShell window 3 in repo root and run:

```powershell
python app_client.py
```

Follow the menu:
- Sign Up: choose 1, enter `user_id` (e.g., `owner_bob`), enter 4‑digit PIN twice. Backend signs and stores a user certificate fingerprint and PIN hash.
- Login: choose 2, enter same `user_id` and PIN. Backend verifies mTLS CN, certificate fingerprint, and PIN.

Post-login actions:
- Register Car: choose option to register. Provide Car ID from the Car Server (e.g., `CAR_VIN_DEMO_789`) and car certificate PEM if prompted. Backend stores car certificate fingerprint and owner.
- Unlock/Start: choose the actions to test end‑to‑end. Flow: App↔Car (TLS), Car↔Backend (TLS validation), Backend grants/denies, Car replies with `*_ACK`/`*_NAK`.

## Run App Client – User 2 (Recipient)
Use another window (or reuse App window after logout):

```powershell
python app_client.py
```

- Sign Up as `friend_alice`, set PIN.
- Login as `friend_alice`.
- Try Unlock: should fail initially (no ownership/delegation). Backend denies during Car validation.

## Delegate Access (Owner)
Back in the Owner session (`owner_bob`):
- Choose Delegate Access.
- Enter Car ID (`CAR_VIN_DEMO_789`), Recipient (`friend_alice`), Permissions (e.g., `UNLOCK,START`), and duration.
- Backend creates delegation (with ID, permissions, expiry). Check logs.

## Test Delegated Access (Recipient)
In `friend_alice` session:
- Unlock: should succeed. Car asks Backend via TLS; Backend grants based on active delegation.
- Start: should succeed if delegated.

## Revoke Access (Owner)
In `owner_bob` session:
- Choose revoke (last or specific). Backend updates delegation status to `revoked`.

## Test Revocation (Recipient)
In `friend_alice` session:
- Try Unlock/Start again: should fail. Backend denies; Car returns `*_NAK`.

## Certificate Validation Helpers
- App→Backend: `VALIDATE_CAR_CERT` checks the car certificate fingerprint against server records.
- Car→Backend: `VALIDATE_APP_PUBKEY` checks the app’s certificate fingerprint against the user record.

## Troubleshooting
- **OpenSSL config errors** (`Can't open openssl.cnf`): Add `-config NUL` to `openssl req` commands as shown above, or set `$env:OPENSSL_CONF = "NUL"` before running commands.
- **TLS handshake fails**:
	- Ensure all components load the same `ca-chain.pem` and certs exist per `utils/config.py` paths.
	- Backend must run before Car/App attempts to connect.
	- Verify OpenSSL cert subjects: Backend/Car CN `localhost` for demo; App CN matches the user.
- **File not found**: Re-run the certificate generation and confirm files in `certs/`.
- **Login/Signup errors**:
	- PIN must be exactly 4 digits.
	- Certificate CN must match `user_id` on login.
	- Check `data/server_data/registrations.json` and logs for reasons.

## Stop Everything
Press `Ctrl+C` in each window. Backend saves data to `data/server_data/`.

## Optional: Networking notes
See `how_to_test_networking.md` for deeper mTLS and flow notes. This guide is aligned with those steps but adapted for Windows PowerShell.

