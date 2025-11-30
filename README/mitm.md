# How to Demonstrate MitM Attack Prevention

This guide demonstrates how the system's mutual TLS (mTLS) combined with backend certificate validation prevents a Man-in-the-Middle (MitM) attack when the app client attempts to communicate with the car server.

## Prerequisites

1.  All servers and the app client code are set up as per the main project instructions (including certificate generation).
2.  You have at least **four separate terminal windows**.
3.  The `mitm_proxy.py` script is available.

## Demonstration Steps

1.  **Terminal 1: Start Backend Server**
    ```bash
    python backend_server.py
    ```
    *Observe logs for successful startup.*

2.  **Terminal 2: Start Car Server**
    ```bash
    # Optional: export CAR_ID="YOUR_CAR_ID" (e.g., CAR_VIN_DEMO_789)
    python car_server.py
    ```
    *Observe logs for successful startup and note the Car ID.*

3.  **Terminal 3: Start MitM Proxy**
    ```bash
    python mitm_proxy.py
    ```
    *Observe logs: It should state it's listening on `127.0.0.1:65005` (or the port defined in `app_client.py`'s `MITM_PROXY_PORT`) and will forward to the car server's actual address.*

4.  **Terminal 4: Run App Client in MitM Test Mode**
    To simulate the app connecting through the MitM proxy, run the `app_client.py` script with the `--mitm-test` flag:
    ```bash
    python app_client.py --mitm-test
    ```
    *   **Login:**
        *   Choose option `2` (Login).
        *   Enter a pre-registered User ID (e.g., `besar1`) and its PIN.
        *   Verify successful login in the App Client and Backend Server logs. The App Client logs should indicate it's in "MitM TEST MODE".
    *   **Attempt Car Action (e.g., Unlock):**
        *   From the App Client's main menu, choose option `5` (Unlock Car).

## Expected Outcome & What to Observe in Logs

*   **App Client Logs:**
    *   Will show it's running in **MitM TEST MODE** and attempting to connect to the MitM proxy's address (e.g., `127.0.0.1:65005`).
    *   A TLS handshake with the MitM proxy will *appear* to succeed initially.
    *   The app will then log that it's retrieving the "car's" certificate (which is actually the certificate presented by the MitM proxy).
    *   It will log contacting the **actual backend server** to validate this certificate's fingerprint.
    *   Crucially, it will log an **error** like:
        *   `ERROR - Backend server rejected certificate validation (via TLS): Certificate fingerprint mismatch`
        *   `ERROR - Backend validation failed for car 'CAR_VIN_DEMO_789' certificate. Aborting connection.`
        *   `ERROR - UNLOCK_REQUEST failed: No response from car at ('127.0.0.1', 65005).`
    *   The unlock operation will **fail**.

*   **MitM Proxy Logs:**
    *   Will show accepting a connection from the App Client.
    *   Will show its "Fake Server" completing a TLS handshake with the App Client.
    *   Will show its "Fake Client" completing a TLS handshake with the actual Car Server.
    *   May show some initial data being forwarded.
    *   Will then show the connection being closed by the App Client (or timing out) after the app aborts due to failed backend validation.

*   **Backend Server Logs:**
    *   Will show a secure TLS connection from the App Client when it requests `VALIDATE_CAR_CERT`.
    *   Will log the fingerprint validation:
        *   `WARNING - Certificate validation FAILED for car 'CAR_VIN_DEMO_789' ... Expected: [actual_car_cert_fingerprint], Received: [mitm_presented_cert_fingerprint]`
    *   Will show it sending a `VALIDATE_CAR_CERT_NAK` (implicitly, as the app client logs the rejection).

*   **Car Server Logs:**
    *   Will show a TLS connection from the MitM proxy (which is pretending to be the app client).
    *   It likely **won't receive the actual `UNLOCK_REQUEST`** because the app client aborts the connection to the MitM before sending it, due to the failed backend certificate validation.

## Conclusion of Demonstration

This flow demonstrates that even if an attacker can position themselves in the middle and perform basic TLS termination/re-establishment, the **application-level security measure of validating the car's certificate fingerprint with a trusted backend server effectively prevents the app from trusting the MitM proxy and sending sensitive commands.** The attack is thwarted.

---

**Note:** To run the app in **normal mode** (connecting directly to the car), simply omit the `--mitm-test` flag:
```bash
python app_client.py