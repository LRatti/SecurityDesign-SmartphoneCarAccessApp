# Running the Networking Test (with mTLS)

This guide explains how to run the proof-of-concept, which now uses **mutual TLS (mTLS)** for secure communication between the App Client and the Car Server.

## Prerequisites

*   Python 3.x installed.
*   **OpenSSL installed:** You need the `openssl` command-line tool to generate the necessary TLS certificates and keys. Verify installation by running `openssl version` in your terminal. Installation methods vary by operating system (e.g., included in Linux/macOS, downloadable for Windows).
*   You will need at least three separate terminal windows (four recommended for the full delegation scenario).
*   The project code cloned to your local machine.

## 1. Generate TLS Certificates

Before running the servers, you must generate the required certificates and private keys for mutual TLS authentication. These files should **NOT** be committed to Git (ensure `certs/` is in your `.gitignore`).

1.  **Open a terminal** in the **root directory** of the project.
2.  **Create the `certs` directory:**
    ```bash
    mkdir certs
    ```
3.  **Run the following `openssl` commands** to generate a Certificate Authority (CA), a server certificate/key for the car, and a client certificate/key for the app:

    ```bash
    # --- 1. Create CA Key and Certificate ---
    # Creates a private key for your new Certificate Authority
    openssl genpkey -algorithm RSA -out certs/ca-key.pem -pkeyopt rsa_keygen_bits:2048
    # Creates a self-signed root certificate for your CA
    openssl req -new -x509 -key certs/ca-key.pem -out certs/ca-cert.pem -days 3650 -subj "/CN=My Test CA"

    # --- 2. Create Car Server Key and Certificate Signing Request (CSR) ---
    # Creates a private key for the Car Server
    openssl genpkey -algorithm RSA -out certs/car-key.pem -pkeyopt rsa_keygen_bits:2048
    # Creates a CSR for the Car Server.
    # IMPORTANT: Common Name (CN) should match the hostname/IP the client connects to if hostname checking is enabled.
    # For this demo (connecting to 127.0.0.1/localhost with check_hostname=False), 'localhost' is fine.
    openssl req -new -key certs/car-key.pem -out certs/car-csr.pem -subj "/CN=localhost"

    # --- 3. Sign Car Server Certificate with CA ---
    # Uses the CA to sign the car's CSR, creating the car's certificate
    openssl x509 -req -in certs/car-csr.pem -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/car-cert.pem -days 365

    # --- 4. Create App Client Key and CSR ---
    # Creates a private key for the App Client
    openssl genpkey -algorithm RSA -out certs/app-key.pem -pkeyopt rsa_keygen_bits:2048
    # Creates a CSR for the App Client. CN can be descriptive.
    openssl req -new -key certs/app-key.pem -out certs/app-csr.pem -subj "/CN=MyTestAppClient"

    # --- 5. Sign App Client Certificate with CA ---
    # Uses the CA to sign the app's CSR, creating the app's certificate
    openssl x509 -req -in certs/app-csr.pem -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/app-cert.pem -days 365

    # --- 6. Cleanup (Optional) ---
    # You can remove the CSR files and the serial file if desired
    # rm certs/*.csr certs/*.srl
    ```
4.  Verify that the following files now exist inside the `certs/` directory:
    *   `ca-cert.pem`
    *   `ca-key.pem` (Keep safe, **do not commit**)
    *   `car-cert.pem`
    *   `car-key.pem` (Keep safe, **do not commit**)
    *   `app-cert.pem`
    *   `app-key.pem` (Keep safe, **do not commit**)
    *   `ca-cert.srl` (Serial number file created by openssl)

## 2. Start the Backend Server

This server manages user/car registrations, license status, and access delegations. *(Note: This server does not currently use TLS in the provided code, communication with it is unencrypted in this POC).*

1.  Open your **first terminal**.
2.  Navigate to the root directory of the project.
3.  Run the backend server script:
    ```bash
    python backend_server.py
    ```
4.  The server will start listening and load/create data files in `data/server_data/`. Leave this terminal running.

## 3. Start the Car Server (with TLS)

This simulates the car itself, now listening securely using TLS for commands from the app and validating actions with the backend server.

1.  Open your **second terminal**.
2.  Navigate to the root directory of the project.
3.  Run the car server script:
    ```bash
    # Optional: Set a specific Car ID environment variable first
    # export CAR_ID="MY_COOL_CAR"

    python car_server.py
    ```
4.  **Check the logs:** The car server should log messages indicating successful SSL context creation and that it's "listening securely (TLS)". Note the Car ID it is using (default: `CAR_VIN_DEMO_789`). Leave this terminal running. If you see errors about missing certificate files or SSL context creation, revisit Step 1.

## 4. Run the App Client (User 1 - Owner) (with TLS)

This simulates the car owner's smartphone app, which now connects securely using TLS.

1.  Open your **third terminal**.
2.  Navigate to the root directory of the project.
3.  Run the app client script:
    ```bash
    python app_client.py
    ```
4.  When prompted, enter a unique user ID for the **owner** (e.g., `owner_bob`). Check the logs for successful SSL context creation. If errors occur, check Step 1.
5.  Perform initial setup as the owner:
    *   Select option **1** to register this user (`owner_bob`) with the backend server.
    *   Select option **3** to register the car:
        *   Enter the **Car ID** noted from the running car server (e.g., `CAR_VIN_DEMO_789`).
        *   Enter an optional model name when prompted.
6.  Test owner access (over TLS):
    *   Select option **7** (Unlock).
        *   **Check Car Server Logs:** Look for "TLS connection established" and successful processing of the `UNLOCK_REQUEST`.
        *   **Check App Client Logs:** Look for "TLS connection established" and the `UNLOCK_ACK` response. This *should work*.
    *   Select option **8** (Start) - *should work* similarly.

## 5. Run the App Client (User 2 - Recipient) (with TLS)

This simulates the smartphone app of a user receiving delegated access, also connecting via TLS.

1.  Open a **fourth terminal** (recommended).
2.  Navigate to the root directory of the project.
3.  Run the app client script:
    ```bash
    python app_client.py
    ```
4.  When prompted, enter a **different** unique user ID for the **recipient** (e.g., `friend_alice`). Check logs for SSL context creation.
5.  Perform initial setup as the recipient:
    *   Select option **1** to register this user (`friend_alice`) with the backend server.
6.  Test initial access (should fail over TLS):
    *   Select option **7** (Unlock). Observe the logs. The TLS connection should establish, but the car server (after validating with the backend) should deny access, sending an `UNLOCK_NAK`. This *should fail*.

## 6. Delegate Access (as User 1)

Go back to the terminal running the app for **User 1 (owner_bob)**.

1.  Select option **4** (Delegate Access).
2.  Enter the **Car ID** (e.g., `CAR_VIN_DEMO_789`).
3.  Enter the **Recipient User ID** (e.g., `friend_alice`).
4.  Enter the desired **Permissions**, comma-separated (e.g., `UNLOCK` or `UNLOCK,START`).
5.  Enter the desired **duration** in hours (e.g., `0.1` for 6 minutes, `1` for 1 hour).
6.  **Note the Delegation ID** that is printed if the delegation is successful.

## 7. Test Delegated Access (as User 2)

Go back to the terminal running the app for **User 2 (friend_alice)**.

1.  Test the granted permissions (over TLS):
    *   Select option **7** (Unlock) again. Check logs on both car and app. This *should now work* if `UNLOCK` permission was granted.
    *   Select option **8** (Start). Check logs. This *should only work* if `START` permission was granted *and* the backend server considers the license valid.

## 8. Revoke Access (as User 1)

Go back to the terminal running the app for **User 1 (owner_bob)**.

1.  Choose an option to revoke the delegation:
    *   Option **5** (Revoke Last Delegation).
    *   Option **6** (Revoke Specific Delegation) and enter the **Delegation ID**.

## 9. Test Revoked Access (as User 2)

Go back to the terminal running the app for **User 2 (friend_alice)**.

1.  Attempt to use the previously granted access (over TLS):
    *   Select option **7** (Unlock) again. Check logs. The TLS connection will establish, but access should be denied by the car/backend. This *should fail*.

## Troubleshooting TLS/Certificate Issues

*   **`FileNotFoundError`:** Ensure you ran the `openssl` commands in Step 1 correctly and that the `.pem` files are inside the `certs/` directory relative to the project root. Check file permissions.
*   **`SSLCertVerificationError`:**
    *   Verify the `ca-cert.pem` loaded by both client and server is the correct one used to sign the other certificates.
    *   Ensure the client is loading `app-cert.pem`/`app-key.pem` and the server is loading `car-cert.pem`/`car-key.pem`.
    *   If you enabled `check_hostname=True` on the client, ensure the Car Server certificate's Common Name (CN) exactly matches `config.CAR_IP`.
*   **`SSL routines:ssl3_read_bytes:sslv3 alert handshake failure` (or similar handshake errors):** Could indicate a mismatch in certificates (e.g., server expects a client cert signed by its CA, but client provides an unrelated one), or deeper TLS configuration issues (less likely with defaults). Double-check Step 1.
*   **Connection Refused/Timeout:** Ensure the Car Server started successfully *after* certificate generation and is listening on the correct IP/port (`config.CAR_IP`, `config.CAR_PORT`).

## Stopping the POC

*   You can stop any of the running scripts (servers or apps) by pressing `Ctrl+C` in their respective terminals.
*   The backend server will attempt to save its current state to the data files upon shutdown.