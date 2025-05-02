# Running the networking test

## Prerequisites

*   Python 3.x installed.
*   You will need at least three separate terminal windows (four recommended for the full delegation scenario).

## 1. Start the Backend Server

This server manages user/car registrations, license status, and access delegations.

1.  Open your first terminal.
2.  Navigate to the root directory of the project.
3.  Run the backend server script:
    ```bash
    python backend_server.py
    ```
4.  The server will start listening and load/create data files (`registrations.json`, `cars.json`, `delegations.json`) in the `data/server_data/` directory. Leave this terminal running.

## 2. Start the Car Server

This simulates the car itself, listening for commands from the app and validating actions with the backend server.

1.  Open your second terminal.
2.  Navigate to the root directory of the project.
3.  Run the car server script:
    ```bash
    # Optional: Set a specific Car ID environment variable first
    # export CAR_ID="MY_COOL_CAR"

    python car_server.py
    ```
4.  The car server will start listening. By default, it uses the ID `CAR_VIN_DEMO_789` if the `CAR_ID` environment variable is not set. Note the Car ID it is using. Leave this terminal running.

## 3. Run the App Client (User 1 - Owner)

This simulates the car owner's smartphone app.

1.  Open your third terminal.
2.  Navigate to the root directory of the project.
3.  Run the app client script:
    ```bash
    python app_client.py
    ```
4.  When prompted, enter a unique user ID for the **owner** (e.g., `owner_bob`).
5.  Perform initial setup as the owner:
    *   Select option **1** to register this user (`owner_bob`) with the server.
    *   Select option **3** to register the car:
        *   Enter the **Car ID** noted from the running car server (e.g., `CAR_VIN_DEMO_789`).
        *   Enter an optional model name when prompted.
6.  Test owner access:
    *   Select option **7** (Unlock) - *should work*.
    *   Select option **8** (Start) - *should work* (assuming the default valid license status).

## 4. Run the App Client (User 2 - Recipient)

This simulates the smartphone app of a user receiving delegated access.

1.  Open a **fourth terminal** (recommended).
2.  Navigate to the root directory of the project.
3.  Run the app client script:
    ```bash
    python app/app_client.py
    ```
4.  When prompted, enter a **different** unique user ID for the **recipient** (e.g., `friend_alice`).
5.  Perform initial setup as the recipient:
    *   Select option **1** to register this user (`friend_alice`) with the server.
6.  Test initial access (should fail):
    *   Select option **7** (Unlock) - *should fail* because `friend_alice` has not been granted access yet.

## 5. Delegate Access (as User 1)

Go back to the terminal running the app for **User 1 (owner_bob)**.

1.  Select option **4** (Delegate Access).
2.  Enter the **Car ID** (e.g., `CAR_VIN_DEMO_789`).
3.  Enter the **Recipient User ID** (e.g., `friend_alice`).
4.  Enter the desired **Permissions**, comma-separated (e.g., `UNLOCK` or `UNLOCK,START`).
5.  Enter the desired **duration** in hours (e.g., `0.1` for 6 minutes, `1` for 1 hour).
6.  **Note the Delegation ID** that is printed if the delegation is successful.

## 6. Test Delegated Access (as User 2)

Go back to the terminal running the app for **User 2 (friend_alice)**.

1.  Test the granted permissions:
    *   Select option **7** (Unlock) again - *should now work* if `UNLOCK` permission was granted.
    *   Select option **8** (Start) - *should only work* if `START` permission was granted *and* `friend_alice`'s license is considered valid by the server (which it is by default upon registration in this POC).

## 7. Revoke Access (as User 1)

Go back to the terminal running the app for **User 1 (owner_bob)**.

1.  Choose an option to revoke the delegation:
    *   Option **5** (Revoke Last Delegation) if you just created the delegation you want to revoke.
    *   Option **6** (Revoke Specific Delegation) and enter the **Delegation ID** you noted in step 5.

## 8. Test Revoked Access (as User 2)

Go back to the terminal running the app for **User 2 (friend_alice)**.

1.  Attempt to use the previously granted access:
    *   Select option **7** (Unlock) again - *should fail* now that the delegation has been revoked.

## Stopping the POC

*   You can stop any of the running scripts (servers or apps) by pressing `Ctrl+C` in their respective terminals.
*   The backend server will attempt to save its current state to the data files upon shutdown.