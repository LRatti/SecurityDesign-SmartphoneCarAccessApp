# Running the Networking Test (with Full mTLS)

This guide explains how to run the proof-of-concept, which now uses **mutual TLS (mTLS)** for secure communication between:
1.  **App Client <-> Car Server**
2.  **Car Server <-> Backend Server**

## Prerequisites

*   Python 3.x installed.
*   **OpenSSL installed:** You need the `openssl` command-line tool to generate the necessary TLS certificates and keys. Verify installation by running `openssl version` in your terminal. Installation methods vary by operating system (e.g., included in Linux/macOS, downloadable for Windows).
*   You will need at least **three separate terminal windows**.
*   The project code cloned to your local machine.
*   Ensure the `certs/` directory (if it exists) is listed in your `.gitignore` file, as keys should not be committed.

## 1. Generate TLS Certificates

Before running the servers, you must generate the required certificates and private keys for mutual TLS authentication across all components.

1.  **Open a terminal** in the **root directory** of the project.
2.  **Create the `certs` directory if it doesn't exist:**
    ```bash
    mkdir -p certs
    ```
3.  **Run the following `openssl` commands** to generate a Certificate Authority (CA), and certificates/keys for the Backend Server, Car Server, and App Client:

    ```bash
    # --- 1. Create CA Key and Certificate ---
    # Creates a private key for your new Certificate Authority
    openssl genpkey -algorithm RSA -out certs/ca-key.pem -pkeyopt rsa_keygen_bits:2048
    # Creates a self-signed root certificate for your CA (valid for 10 years)
    openssl req -new -x509 -key certs/ca-key.pem -out certs/ca-cert.pem -days 3650 -subj "/CN=My Test CA"

    # --- 2. Create Backend Server Key and CSR ---
    # Creates a private key for the Backend Server
    openssl genpkey -algorithm RSA -out certs/backend-key.pem -pkeyopt rsa_keygen_bits:2048
    # Creates a CSR for the Backend Server.
    # CN should match how the Car Server connects (likely 'localhost' for this demo).
    openssl req -new -key certs/backend-key.pem -out certs/backend-csr.pem -subj "/CN=localhost"

    # --- 3. Sign Backend Server Certificate with CA ---
    # Uses the CA to sign the backend's CSR, creating the backend's certificate
    openssl x509 -req -in certs/backend-csr.pem -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/backend-cert.pem -days 365

    # --- 4. Create Car Server Key and CSR ---
    # Creates a private key for the Car Server
    openssl genpkey -algorithm RSA -out certs/car-key.pem -pkeyopt rsa_keygen_bits:2048
    # Creates a CSR for the Car Server. CN should match how the App Client connects.
    openssl req -new -key certs/car-key.pem -out certs/car-csr.pem -subj "/CN=localhost"

    # --- 5. Sign Car Server Certificate with CA ---
    # Uses the CA to sign the car's CSR, creating the car's certificate
    openssl x509 -req -in certs/car-csr.pem -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/car-cert.pem -days 365 # Reuse CA serial

    # --- 6. Create App Client Key and CSR ---
    # Creates a private key for the App Client
    openssl genpkey -algorithm RSA -out certs/app-key.pem -pkeyopt rsa_keygen_bits:2048
    # Creates a CSR for the App Client. CN can be descriptive.
    openssl req -new -key certs/app-key.pem -out certs/app-csr.pem -subj "/CN=MyTestAppClient"

    # --- 7. Sign App Client Certificate with CA ---
    # Uses the CA to sign the app's CSR, creating the app's certificate
    openssl x509 -req -in certs/app-csr.pem -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/app-cert.pem -days 365 # Reuse CA serial

    # --- 8. Cleanup (Optional) ---
    # You can remove the CSR files and the serial file if desired
    # rm certs/*.csr certs/*.srl
    ```
4.  Verify that the following files now exist inside the `certs/` directory:
    *   `ca-cert.pem`
    *   `ca-key.pem` (**KEEP SAFE**, do not commit)
    *   `backend-cert.pem`
    *   `backend-key.pem` (**KEEP SAFE**, do not commit)
    *   `car-cert.pem`
    *   `car-key.pem` (**KEEP SAFE**, do not commit)
    *   `app-cert.pem`
    *   `app-key.pem` (**KEEP SAFE**, do not commit)
    *   `ca-cert.srl` (Serial number file created by openssl)

## 2. Start the Backend Server (with TLS)

This server now listens securely using TLS and requires connecting clients (specifically, the Car Server) to present a valid TLS certificate signed by the generated CA.

1.  Open your **first terminal**.
2.  Navigate to the root directory of the project.
3.  Run the backend server script:
    ```bash
    python backend_server.py
    ```
4.  **Check the logs:** The server should log messages indicating successful SSL context creation and that it's "Backend server listening securely (TLS)". It will load/create data files in `data/server_data/`. Leave this terminal running. If you see errors about missing certificate files or SSL context creation, revisit Step 1.

## 3. Start the Car Server (with TLS)

This simulates the car itself, listening securely (TLS) for the App Client and *also connecting securely (TLS)* to the Backend Server for validation.

1.  Open your **second terminal**.
2.  Navigate to the root directory of the project.
3.  Run the car server script:
    ```bash
    # Optional: Set a specific Car ID environment variable first
    # export CAR_ID="MY_COOL_CAR"

    python car_server.py
    ```
4.  **Check the logs:** The car server should log:
    *   Successful creation of its *listening* SSL context (for App Clients).
    *   Successful creation of its *backend client* SSL context (for connecting to Backend Server).
    *   That it's "Car server listening securely (TLS)".
    *   Note the Car ID it is using (default: `CAR_VIN_DEMO_789`).
    *   Leave this terminal running. If errors occur, check Step 1 and certificate paths in `utils/config.py`.

## 4. Run the App Client (User 1 - Owner) (with TLS)

This simulates the car owner's smartphone app, connecting securely (TLS) to the Car Server.

1.  Open your **third terminal**.
2.  Navigate to the root directory of the project.
3.  Run the app client script:
    ```bash
    python app_client.py
    ```
4.  When prompted, enter a unique user ID for the **owner** (e.g., `owner_bob`). Check the logs for successful SSL context creation. If errors occur, check Step 1.
5.  Perform initial setup as the owner:
    *   Select option **1** (Register User). This contacts the **Backend Server**.
        *   **Check Backend Server Logs:** Look for the incoming connection and processing of the `REGISTER` request. Note that this App<->Backend connection is *currently not secured by TLS* in the provided code structure.
    *   Select option **3** (Register Car). This also contacts the **Backend Server**.
        *   Enter the **Car ID** noted from the running car server (e.g., `CAR_VIN_DEMO_789`).
        *   **Check Backend Server Logs:** Look for processing of the `REGISTER_CAR` request.
6.  Test owner access (App<->Car over TLS, Car<->Backend over TLS):
    *   Select option **7** (Unlock).
        *   **Check App Client Logs:** Look for "TLS connection established successfully to [Car Address]" and eventually the `UNLOCK_ACK`.
        *   **Check Car Server Logs:** Look for "TLS connection established with [App Address]", then logs indicating connection attempt to Backend Server ("Attempting to connect securely to backend"), "TLS connection established successfully to [Backend Address]", receiving `ACCESS_GRANTED` from backend, and finally processing the unlock.
        *   **Check Backend Server Logs:** Look for "TLS connection established with [Car Address]" (this is the Car connecting for validation), processing of `VALIDATE_ACCESS_ATTEMPT`, and sending `ACCESS_GRANTED`.
    *   Select option **8** (Start) - Should work similarly, check logs in all three terminals.

## 5. Run the App Client (User 2 - Recipient) (with TLS)

*(Requires a fourth terminal, or reuse the third after stopping User 1)*
This simulates the recipient's app, connecting via TLS to the Car Server.

1.  Open a **fourth terminal** (or reuse the third).
2.  Navigate to the root directory.
3.  Run the app client script: `python app_client.py`
4.  Enter a **different** user ID (e.g., `friend_alice`). Check logs for SSL context creation.
5.  Register the user: Select option **1**. Check **Backend Server** logs.
6.  Test initial access (should fail validation):
    *   Select option **7** (Unlock).
    *   Observe logs: App<->Car TLS connects. Car<->Backend TLS connects for validation. Backend denies access. Car sends `UNLOCK_NAK` to App. This *should fail*.

## 6. Delegate Access (as User 1)

Go back to the terminal for **User 1 (owner_bob)**.

1.  Select option **4** (Delegate Access). This contacts the **Backend Server**.
2.  Enter Car ID, Recipient User ID (`friend_alice`), Permissions (e.g., `UNLOCK,START`), and duration.
3.  **Check Backend Server Logs:** Look for processing of `DELEGATE_ACCESS`. Note the Delegation ID.

## 7. Test Delegated Access (as User 2)

Go back to the terminal for **User 2 (friend_alice)**.

1.  Test granted permissions:
    *   Select option **7** (Unlock). Check logs on all three terminals. App<->Car TLS connects. Car<->Backend TLS validation occurs. Backend should grant access based on delegation. Car sends `UNLOCK_ACK` to App. This *should work*.
    *   Select option **8** (Start). Similar flow. *Should work* if `START` permission was delegated.

## 8. Revoke Access (as User 1)

Go back to the terminal for **User 1 (owner_bob)**.

1.  Select option **5** or **6** to revoke the delegation. This contacts the **Backend Server**. Check its logs.

## 9. Test Revoked Access (as User 2)

Go back to the terminal for **User 2 (friend_alice)**.

1.  Attempt unlock: Select option **7**. Check logs. App<->Car TLS connects. Car<->Backend TLS validation occurs. Backend denies access (delegation revoked). Car sends `UNLOCK_NAK` to App. This *should fail*.

## Troubleshooting TLS/Certificate Issues

*   **`FileNotFoundError`:** Ensure you ran *all* `openssl` commands in Step 1 correctly and that the `.pem` files are inside the `certs/` directory. Check file permissions.
*   **`SSLCertVerificationError` / Handshake Failures:**
    *   **General:** Verify the correct `ca-cert.pem` is loaded by all components needing to verify others (Backend Server, Car Server, App Client). Ensure all certificates (`backend-cert.pem`, `car-cert.pem`, `app-cert.pem`) were signed by the *same* `ca-key.pem`.
    *   **App<->Car:** Check `app_client.py` loads `app-cert/key` and `car_server.py` loads `car-cert/key`. Check CA loading and `verify_mode` on both. Check hostname matching if enabled.
    *   **Car<->Backend:** Check `car_server.py` loads `car-cert/key` for its client context and `backend_server.py` loads `backend-cert/key`. Check CA loading and `verify_mode` on both. Check hostname matching if enabled.
*   **Connection Refused/Timeout:** Ensure the relevant server (Backend or Car) started successfully *after* certificate generation, is listening on the correct IP/port (`config.*_IP`, `config.*_PORT`), and didn't exit due to an early error (like failing to create SSL context). Ensure the backend server is running before the car server attempts validation.

## Stopping the POC

*   Press `Ctrl+C` in each terminal running a script.
*   The backend server attempts to save data on shutdown.