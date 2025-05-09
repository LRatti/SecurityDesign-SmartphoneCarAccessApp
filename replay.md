## How to Demonstrate Replay Attack & Prevention

This scenario demonstrates how an attacker might try to replay captured commands, and how timestamp, sequence number, and signature validation on the car server prevent these attacks. We will test two types of replay:

1.  **Exact Replay:** Replaying the exact captured message. This should be caught by either an old timestamp or a repeated sequence number.
2.  **Replay with Updated Timestamp:** Replaying a message with a fresh timestamp but the original (old) sequence number and original (now invalid for the new timestamp) signature. This should be caught by a signature verification failure or, if somehow the signature was still considered valid, by the sequence number check.

**Prerequisites:**

*   All servers and the app client code are set up.
*   Certificates are generated.
*   App client is **NOT** run with `--mitm-test` for this scenario (direct connection to car is needed).

**Demonstration Steps:**

1.  **Terminal 1: Start Backend Server**
    ```bash
    python backend_server.py
    ```

2.  **Terminal 2: Start Car Server**
    ```bash
    python car_server.py
    ```
    *Observe the Car Server logs closely during the test for messages about replay detection or signature failures.*

3.  **Terminal 3: Run App Client (Legitimate User)**
    ```bash
    python app_client.py
    ```
    *   **Login:** Login as a registered user (e.g., `besar1`).
    *   **Perform a Legitimate Action & Capture:**
        *   Select option `5` (Unlock Car). The unlock should succeed.
        *   **Observe App Client Logs:** You should see a line like:
            `INFO - Message captured for potential replay test: UNLOCK_REQUEST`
            This simulates the attacker capturing this valid, signed command (including its original timestamp, sequence number, and signature).
    *   **(Highly Recommended for Clear Demo) Lock the car again:** Select option `7` (Lock Car). This sends a new, legitimate command and resets the car's state, making the effect of the replay attempt more obvious. The "last captured message" will now be this "Lock" command.

4.  **Terminal 3: Attempt Replay Attack - Type 1 (Exact Replay)**
    *   In the App Client menu, select option:
        `9. REPLAY Last Car Command (Exact)`
    *   **Observe Logs:**
        *   **App Client:** Will log "ATTEMPTING EXACT REPLAY ATTACK". The action will likely fail, with an error from the car indicating "Replay detected (invalid timestamp)" or "Replay detected (invalid sequence number)".
        *   **Car Server:** Will receive the replayed command.
            *   If the timestamp from the captured command is now outside `config.TIMESTAMP_WINDOW_SECONDS`, it will log "REPLAY DETECTED (Timestamp)".
            *   If the timestamp is still within the window (e.g., you replayed very quickly), it will then check the sequence number. Since this sequence number was already processed for the original "Lock" command, it will log "REPLAY DETECTED (Sequence)".
            *   The car will send back a `LOCK_NAK` (or `UNLOCK_NAK` if that was the last command).
        *   The car's state (locked/unlocked) should **not** have changed due to this replayed command.

5.  **Terminal 3: Perform Another Legitimate Action (to capture a new message)**
    *   Again, select option `5` (Unlock Car). This legitimate command should succeed. The `AppClient.last_sent_car_message_for_replay` will now store this new "Unlock" command's details.
    *   (Optional) Lock the car again (option `7`) to reset state.

6.  **Terminal 3: Attempt Replay Attack - Type 2 (Replay with Updated Timestamp, Old Signature & SeqNo)**
    *   In the App Client menu, select option:
        `10. REPLAY Last Car Command (Updated Timestamp, Old Signature & SeqNo)`
    *   **Observe Logs:**
        *   **App Client:** Will log "ATTEMPTING REPLAY ATTACK WITH UPDATED TIMESTAMP (OLD SIG/SEQ)". The action will fail. The error from the car should ideally be "Invalid signature on command".
        *   **Car Server:**
            *   Will receive a command where the `timestamp` in the payload is current.
            *   It will attempt to reconstruct the data that *should have been signed* using this **new timestamp** and the **old sequence number** from the captured message.
            *   It will then try to verify the **old signature** (from the `auth_data` of the captured message) against this reconstructed data.
            *   **Crucially, the signature verification should FAIL** because the signature was generated for the *original* data (which included the *original* timestamp).
            *   The car server should log: `WARNING - SIGNATURE VERIFICATION FAILED for [ACTION_TYPE] from [user_id].`
            *   It will send back a NAK (e.g., `UNLOCK_NAK`) with an error message indicating "Invalid signature on command".
        *   The car's state should **not** change.

7.  **Test Again (Legitimate Command after Replay Attempts):**
    *   In the App Client menu, select option `5` (Unlock Car) again.
    *   This command will have a new timestamp, a new (incremented) sequence number, and a freshly generated valid signature.
    *   **Observe Car Server Logs:** All checks (signature, timestamp, sequence number) should pass. The unlock should succeed.
    *   This demonstrates that the replay protection mechanisms don't interfere with subsequent legitimate commands.

## How It Works & Conclusion

This demonstration illustrates two key aspects of the replay attack prevention:

1.  **Timestamp Validation:** Prevents very old messages from being accepted, even if their sequence number hasn't been seen recently (e.g., after a server restart where sequence number memory is lost, though in this POC sequence numbers are per user and persist as long as the car server runs).
2.  **Sequence Number Validation:** Ensures that each command from a specific user has a unique, strictly increasing identifier. This prevents the immediate replay of an identical message.
3.  **Signature Verification (Most Critical for Tampered Replays):** By signing a data structure that includes the timestamp and sequence number, the system ensures that an attacker cannot simply modify these fields in a captured message and have it pass. Any modification to the signed data (including the timestamp) would invalidate the original signature. The car verifies the signature *first* against the payload's timestamp and sequence number. If the signature is invalid, the command is rejected before even checking if the timestamp/sequence number *values themselves* are plausible for replay.

This multi-faceted approach provides robust protection against basic replay attacks.