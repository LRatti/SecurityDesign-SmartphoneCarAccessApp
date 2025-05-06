# Running the Networking Test (with Full mTLS and Login/Signup)

This guide explains how to run the proof-of-concept, which now uses **mutual TLS (mTLS)** for secure communication between:
1.  **App Client <-> Car Server**
2.  **Car Server <-> Backend Server**
3.  **App Client <-> Backend Server** (For all operations, including Login/Signup)

It also includes a **Sign Up / Login** system using User ID and a 4-digit PIN, protected by TLS and server-side hashing.

## Prerequisites

*   Python 3.x installed.
*   Required Python libraries: `cryptography`. Install using `pip install cryptography`.
*   **OpenSSL installed:** You need the `openssl` command-line tool to generate the necessary TLS certificates and keys. Verify installation by running `openssl version` in your terminal. Installation methods vary by operating system (e.g., included in Linux/macOS, downloadable for Windows).
*   You will need at least **three separate terminal windows**.
*   The project code cloned to your local machine.
*   Ensure the `certs/` directory (if it exists) is listed in your `.gitignore` file, as keys should not be committed.
*   **(IMPORTANT for Update):** If you ran a previous version, **delete the `data/server_data/registrations.json` file** before starting the backend server. The data format has changed.

## 1. Generate TLS Certificates - Skip if already present in the /certs folder

*(This section remains the same as before)*

Before running the servers, you must generate the required certificates and private keys for mutual TLS authentication across all components.

1.  **Open a terminal** in the **root directory** of the project.
2.  **Create the `certs` directory if it doesn't exist:**
    ```bash
    mkdir -p certs
    ```
3.  **Run the following `openssl` commands** to generate a Certificate Authority (CA), and certificates/keys for the Backend Server, Car Server, and App Client:

    ```bash
    # --- 1. Create CA Key and Certificate ---
    openssl genpkey -algorithm RSA -out certs/ca-key.pem -pkeyopt rsa_keygen_bits:2048
    openssl req -new -x509 -key certs/ca-key.pem -out certs/ca-cert.pem -days 3650 -subj "/CN=My Test CA"

    # --- 2.1 Create Backend Server Key and CSR ---
    openssl genpkey -algorithm RSA -out certs/backend-key.pem -pkeyopt rsa_keygen_bits:2048
    # CN should match how clients connect (use localhost for this demo).
    openssl req -new -key certs/backend-key.pem -out certs/backend-csr.pem -subj "/CN=localhost"

    # --- 2.2 Create Backend Server Intermediate Key and CSR ---
    openssl genpkey -algorithm RSA -out certs/intermediate-ca-key.pem -pkeyopt rsa_keygen_bits:2048
    openssl req -new -key certs/intermediate-ca-key.pem -out certs/intermediate-ca-csr.pem -subj "/CN=Intermediate CA for User Certificates"
    
    # --- 3.1 Sign Backend Server Certificate with CA ---
    openssl x509 -req -in certs/backend-csr.pem -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/backend-cert.pem -days 365

    # --- 3.2 Sign Backend Server Intermediate Certificate with Root CA ---
    openssl x509 -req -in certs/intermediate-ca-csr.pem \
    -CA certs/ca-cert.pem \
    -CAkey certs/ca-key.pem \
    -CAcreateserial \
    -out certs/intermediate-ca-cert.pem \
    -days 365 \
    -extfile certs/v3_intermediate_ca.ext

    # --- 3.3 Create the Chain CA
    cat certs/intermediate-ca-cert.pem certs/ca-cert.pem > certs/ca-chain.pem

    # --- 4. Create Car Server Key and CSR ---
    openssl genpkey -algorithm RSA -out certs/car-key.pem -pkeyopt rsa_keygen_bits:2048
    # CN should match how the App Client connects.
    openssl req -new -key certs/car-key.pem -out certs/car-csr.pem -subj "/CN=localhost"

    # --- 5. Sign Car Server Certificate with CA ---
    openssl x509 -req -in certs/car-csr.pem -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/car-cert.pem -days 365 # Reuse CA serial

    # --- 6. Create App Client Key and CSR ---
    openssl genpkey -algorithm RSA -out certs/app-key.pem -pkeyopt rsa_keygen_bits:2048
    # CN can be descriptive. IMPORTANT: Each distinct user *should* have their own cert/key in a real system. For this PoC, all clients use the same one.
    openssl req -new -key certs/app-key.pem -out certs/app-csr.pem -subj "/CN=MyTestAppClient"

    # --- 7. Sign App Client Certificate with CA ---
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

This server listens securely using TLS and requires connecting clients (App Client and Car Server) to present a valid TLS certificate signed by the generated CA. It now handles `SIGNUP` and `LOGIN` requests.

1.  Open your **first terminal**.
2.  Navigate to the root directory of the project.
3.  **(Optional but Recommended):** Ensure `data/server_data/registrations.json` does not exist or is empty if starting fresh.
4.  Run the backend server script:
    ```bash
    python backend_server.py
    ```
5.  **Check the logs:** The server should log successful SSL context creation and "Backend server listening securely (TLS)". It will create data files in `data/server_data/` if they don't exist. Leave this terminal running.

## 3. Start the Car Server (with TLS)

*(This section remains the same as before)*

This simulates the car, listening securely (TLS) for the App Client and connecting securely (TLS) to the Backend Server for validation.

1.  Open your **second terminal**.
2.  Navigate to the root directory of the project.
3.  Run the car server script:
    ```bash
    # Optional: Set a specific Car ID environment variable first
    # export CAR_ID="MY_COOL_CAR"

    python car_server.py
    ```
4.  **Check the logs:** The car server should log successful creation of its *incoming* and *outgoing* SSL contexts and that it's "Car server listening securely (TLS)". Note the Car ID it uses (default: `CAR_VIN_DEMO_789`). Leave this terminal running.

## 4. Run the App Client (User 1 - Owner)

This simulates the car owner's app. It first requires Sign Up or Login via a secure TLS connection to the Backend Server.

1.  Open your **third terminal**.
2.  Navigate to the root directory of the project.
3.  Run the app client script:
    ```bash
    python app_client.py
    ```
4.  You will see the initial **Authentication Menu**:
    ```
    --- Welcome ---
    1. Sign Up
    2. Login
    0. Exit
    Choose an option:
    ```
5.  **Perform Sign Up:**
    *   Choose option **1**.
    *   Enter a unique User ID (e.g., `owner_bob`).
    *   Enter a 4-digit PIN when prompted (input will be hidden).
    *   Confirm the 4-digit PIN.
    *   **Check App Client Logs:** Look for "Attempting signup..." and "Signup successful!" or "Signup failed: ...".
    *   **Check Backend Server Logs:** Look for "TLS connection established", processing of `SIGNUP`, and "User 'owner_bob' signed up successfully." or an error message (e.g., "User ID already exists"). Check the created/updated `registrations.json`.
6.  **Perform Login:**
    *   After successful signup (or if the user already exists), choose option **2**.
    *   Enter the User ID (`owner_bob`).
    *   Enter the correct 4-digit PIN.
    *   **Check App Client Logs:** Look for "Attempting login..." and "Login successful!".
    *   **Check Backend Server Logs:** Look for processing of `LOGIN`, and "User 'owner_bob' logged in successfully." or "Login failed...".
7.  **Perform Actions as Owner (Post-Login):**
    *   Once login is successful, the **Main Application Menu** will appear (Check License, Register Car, Delegate, etc.).
    *   **Register Car:** Select option **2** (Register a New Car). Enter the Car ID noted from the running car server (e.g., `CAR_VIN_DEMO_789`).
        *   **Check Backend Server Logs:** Look for processing of `REGISTER_CAR` request from `owner_bob`.
    *   **Test Owner Access:** Select options **6** (Unlock) and **7** (Start).
        *   **Check App Client Logs:** Look for TLS connection to Car, validation steps, and eventual `_ACK`.
        *   **Check Car Server Logs:** Look for TLS connection from App, validation request via TLS to Backend, receiving `ACCESS_GRANTED`, and processing the action.
        *   **Check Backend Server Logs:** Look for TLS connection from Car for validation (`VALIDATE_ACCESS_ATTEMPT` for `owner_bob`), and sending `ACCESS_GRANTED`.

## 5. Run the App Client (User 2 - Recipient)

*(Requires a fourth terminal, or reuse the third after stopping User 1)*
This simulates a different user who will receive delegated access.

1.  Open a **fourth terminal** (or reuse the third).
2.  Navigate to the root directory.
3.  Run the app client script: `python app_client.py`
4.  **Perform Sign Up (as User 2):**
    *   Choose option **1**.
    *   Enter a **different** unique User ID (e.g., `friend_alice`).
    *   Enter and confirm a 4-digit PIN.
    *   Check App and Backend logs for successful `SIGNUP`.
5.  **Perform Login (as User 2):**
    *   Choose option **2**.
    *   Enter the User ID (`friend_alice`) and the correct PIN.
    *   Check App and Backend logs for successful `LOGIN`.
6.  **Test Initial Access (Post-Login - Should Fail):**
    *   In the Main Application Menu, select option **6** (Unlock Car).
    *   **Observe Logs:** App<->Car TLS connects. Car<->Backend TLS connects for validation. Backend denies access for `friend_alice` (no ownership/delegation). Car sends `UNLOCK_NAK` to App. This *should fail*.

## 6. Delegate Access (as User 1)

Go back to the terminal for **User 1 (owner_bob)** (ensure they are logged in).

1.  In the Main Application Menu, select option **3** (Delegate Access).
2.  Enter the Car ID (`CAR_VIN_DEMO_789`), Recipient User ID (`friend_alice`), Permissions (e.g., `UNLOCK,START`), and duration.
3.  **Check Backend Server Logs:** Look for processing of `DELEGATE_ACCESS` initiated by `owner_bob`. Note the Delegation ID.

## 7. Test Delegated Access (as User 2)

Go back to the terminal for **User 2 (friend_alice)** (ensure they are logged in).

1.  **Test Granted Permissions:**
    *   Select option **6** (Unlock Car). Check logs on all three terminals. App<->Car TLS connects. Car<->Backend TLS validation occurs. Backend should grant access based on delegation. Car sends `UNLOCK_ACK` to App. This *should work*.
    *   Select option **7** (Start Car). Similar flow. *Should work* if `START` permission was delegated.

## 8. Revoke Access (as User 1)

Go back to the terminal for **User 1 (owner_bob)** (logged in).

1.  Select option **4** (Revoke Last) or **5** (Revoke Specific) to revoke the delegation. This contacts the **Backend Server**. Check its logs for `REVOKE_DELEGATION`.

## 9. Test Revoked Access (as User 2)

Go back to the terminal for **User 2 (friend_alice)** (logged in).

1.  Attempt unlock: Select option **6** (Unlock Car). Check logs. App<->Car TLS connects. Car<->Backend TLS validation occurs. Backend denies access (delegation revoked). Car sends `UNLOCK_NAK` to App. This *should fail*.

## Troubleshooting TLS/Certificate Issues

*   **`FileNotFoundError`:** Ensure you ran *all* `openssl` commands in Step 1 correctly and that the `.pem` files are inside the `certs/` directory. Check file permissions. Check paths in `utils/config.py`.
*   **`SSLCertVerificationError` / Handshake Failures:**
    *   **General:** Verify the correct `ca-cert.pem` is loaded by all components. Ensure all certs were signed by the *same* `ca-key.pem`.
    *   **App<->Backend (Auth):** Check `create_backend_ssl_context` in `app_client.py` loads `app-cert/key` and `ca-cert`. Check `backend_server.py` loads `backend-cert/key` and `ca-cert` with `verify_mode = ssl.CERT_REQUIRED`.
    *   **App<->Car:** Check `app_client.py` loads `app-cert/key` and `ca-cert`. Check `car_server.py` loads `car-cert/key` and `ca-cert` with `verify_mode = ssl.CERT_REQUIRED`.
    *   **Car<->Backend (Validation):** Check `car_server.py`'s *outgoing* context loads `car-cert/key` and `ca-cert`. Check `backend_server.py` loads `backend-cert/key` and `ca-cert` with `verify_mode = ssl.CERT_REQUIRED`.
*   **Connection Refused/Timeout:** Ensure the relevant server (Backend or Car) started successfully, is listening on the correct IP/port (`config.*_IP`, `config.*_PORT`), and didn't exit due to an early error. Backend server must be running before App or Car attempts to connect to it.

## Troubleshooting Login/Signup Issues

*   **`SIGNUP_NAK`:** Check Backend logs. Common reasons: "User ID already exists", "Missing...", "PIN must be 4 digits". Ensure client sent correct data.
*   **`LOGIN_NAK`:** Check Backend logs. Reason is "Invalid user ID or PIN". Double-check the User ID (case-sensitive) and PIN entered. Verify the user exists in `registrations.json`.
*   **Communication Error:** Could be a TLS issue (see above) or a network problem preventing the App Client from reaching the Backend Server.

## Stopping the POC

*   Press `Ctrl+C` in each terminal running a script.
*   The backend server attempts to save data on shutdown. Check `registrations.json`, `cars.json`, `delegations.json` in `data/server_data/` to see the final state.