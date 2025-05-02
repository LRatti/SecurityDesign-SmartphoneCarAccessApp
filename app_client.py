# app/app_client.py
import socket
import logging
import ssl # <-- Import ssl
import time
import json # For pretty printing responses
from utils import config, network_utils

logging.basicConfig(level=logging.INFO, format='%(asctime)s - AppClient - %(levelname)s - %(message)s')

class AppClient:
    def __init__(self, user_id):
        self.user_id = user_id
        self.server_addr = (config.SERVER_IP, config.SERVER_PORT)
        self.car_addr = (config.CAR_IP, config.CAR_PORT) # Assuming only one car for now
        # TODO (AUTH): Load/generate user's private key securely (e.g., from file/keystore).
        #   The public_key below should be derived from the actual private key.
        self.public_key = f"pubkey_for_{self.user_id}" # Placeholder! Replace
        self.last_delegation_id = None # Store last created delegation ID for easy revocation
        self.ssl_context = self._create_ssl_context()

    def _create_ssl_context(self):
        # Use PROTOCOL_TLS_CLIENT for client-side context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            logging.info(f"Loading APP cert chain: {config.APP_CERT_FILE}, {config.APP_KEY_FILE}")
            context.load_cert_chain(certfile=config.APP_CERT_FILE, keyfile=config.APP_KEY_FILE)

            logging.info(f"Loading CA cert for server verification: {config.CA_CERT_FILE}")
            # Load CA cert to verify the server's certificate
            context.load_verify_locations(cafile=config.CA_CERT_FILE)
            context.verify_mode = ssl.CERT_REQUIRED # Verify server cert

            # Hostname checking - IMPORTANT for production
            # If server cert CN is 'localhost' or IP, set check_hostname=True
            # If using a self-signed cert without matching CN, set to False for testing ONLY
            context.check_hostname = False # Set to True if car cert CN matches config.CAR_IP/hostname
            logging.warning("SSL Hostname Check is DISABLED. Enable in production.")

            # Optional: Set specific TLS versions or cipher suites
            # context.minimum_version = ssl.TLSVersion.TLSv1_3

            logging.info("SSL context created successfully for mTLS.")
            return context
        except ssl.SSLError as e:
            logging.critical(f"SSL Error creating client context: {e}")
            raise SystemExit("Failed to initialize SSL context - check certificate paths and permissions.")
        except FileNotFoundError as e:
             logging.critical(f"Certificate file not found: {e}")
             raise SystemExit("Failed to initialize SSL context - certificate file missing.")
        except Exception as e:
             logging.critical(f"Unexpected error creating SSL context: {e}")
             raise SystemExit("Failed to initialize SSL context.")
        

    def _connect(self, address):
        """Establishes a TLS connection to the given address."""
        if not self.ssl_context:
             logging.error("Cannot connect: SSL context not initialized.")
             return None

        raw_sock = None
        ssl_sock = None
        try:
            logging.debug(f"Attempting to create raw socket connection to {address}")
            # 1. Create standard socket first
            raw_sock = socket.create_connection(address, timeout=5.0)
            logging.debug(f"Raw socket connected to {address}")

            # 2. Wrap the socket with the SSL context
            logging.debug(f"Attempting to wrap socket for TLS and perform handshake")
            # server_hostname should match the CN in the car's certificate if check_hostname=True
            server_hostname = address[0] if self.ssl_context.check_hostname else None
            ssl_sock = self.ssl_context.wrap_socket(raw_sock, server_hostname=server_hostname)

            logging.info(f"TLS connection established successfully to {address}")
            # --- Log Server Cert Info (Optional Debugging) ---
            try:
                server_cert = ssl_sock.getpeercert()
                if server_cert:
                    subject = dict(x[0] for x in server_cert.get('subject', []))
                    logging.debug(f"Server Cert Subject: {subject}")
                else:
                     logging.warning("Could not get peer certificate details from server.")
            except Exception as e:
                 logging.warning(f"Error getting peer certificate from server: {e}")
            # -------------------------------------------------
            return ssl_sock # Return the secure socket

        except socket.timeout:
            logging.error(f"Connection to {address} timed out.")
            if raw_sock: raw_sock.close()
            return None
        except socket.error as e:
            logging.error(f"Socket error connecting to {address}: {e}")
            if raw_sock: raw_sock.close()
            return None
        except ssl.SSLCertVerificationError as e:
             logging.error(f"SSL Certificate Verification Error connecting to {address}: {e}")
             if ssl_sock: ssl_sock.close()
             elif raw_sock: raw_sock.close()
             return None
        except ssl.SSLError as e:
             logging.error(f"SSL Error establishing connection to {address}: {e}")
             if ssl_sock: ssl_sock.close()
             elif raw_sock: raw_sock.close()
             return None
        except Exception as e: # Catch other potential errors during wrap/handshake
             logging.error(f"Unexpected error during TLS connection to {address}: {e}")
             if ssl_sock: ssl_sock.close()
             elif raw_sock: raw_sock.close()
             return None

    def _send_and_receive(self, address, message: dict):
        # App-level crypto (signing) would happen *before* calling this function,
        # modifying the 'message' dict if needed. TLS handles the transport.
        # Placeholder comment from original code:
        # TODO (AUTH): Before sending, sign relevant parts of the 'message' payload.

        # Use the _connect method which now returns an SSLSocket
        ssl_sock = self._connect(address)
        if not ssl_sock:
            return None # Connection failed

        response = None
        try:
            # Use the SSL socket for sending/receiving
            if network_utils.send_message(ssl_sock, message):
                # Add a timeout for receiving data on the SSL socket
                ssl_sock.settimeout(5.0)
                response = network_utils.receive_message(ssl_sock)
                # App-level verification of response signature would happen here if needed
                # TODO (AUTH): Optionally, verify signature on response from server/car
            else:
                logging.error("Failed to send message over TLS.")
        except socket.timeout:
             logging.error(f"Receive operation timed out from {address}.")
        except ssl.SSLError as e:
            logging.error(f"SSL error during communication with {address}: {e}")
        except Exception as e:
            logging.error(f"Error during TLS communication with {address}: {e}")
        finally:
            logging.info(f"Closing TLS connection to {address}")
            try:
                ssl_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass # Ignore if already closed
            ssl_sock.close() # Ensure SSL socket is closed

        if response:
            logging.info(f"Received response: {json.dumps(response, indent=2)}")
        else:
            logging.warning("No response received or error occurred.")

        return response


    def register_with_server(self):
        """Registers the user's public key with the backend server."""
        logging.info("Attempting to register with the backend server...")
        message = {
            "type": "REGISTER",
            "sender_id": self.user_id,
            "payload": {
                "public_key": self.public_key # Use the actual public key here
                # TODO (AUTH): Add signature if the server requires signed registration requests.

            }
        }
        # NOTE (AUTH): No signature added here in current placeholder structure,
        #   assuming server trusts initial registration or uses an out-of-band verification.

        response = self._send_and_receive(self.server_addr, message)
        if response and response.get("type") == "REGISTER_ACK":
            logging.info("Registration successful!")
            return True
        else:
            logging.error(f"Registration failed.")
            return False

    def check_license_status(self):
        """Checks the user's driving license status with the server."""
        logging.info("Checking license status with the backend server...")
        message = {
            "type": "CHECK_LICENSE",
            "sender_id": self.user_id,
            "payload": {}
            # TODO (AUTH): Add signature to authenticate the request.

        }
        response = self._send_and_receive(self.server_addr, message)
        if response and response.get("type") == "LICENSE_STATUS":
            payload = response.get("payload", {})
            if "error" in payload:
                 logging.error(f"License check failed: {payload['error']}")
                 return None
            is_valid = payload.get("is_valid")
            if is_valid is not None:
                status = "Valid" if is_valid else "Invalid/Revoked"
                logging.info(f"License status: {status}")
                return is_valid
            else:
                 logging.error(f"Received malformed license status response.")
                 return None
        else:
            logging.error(f"Failed to check license status.")
            return None

    # --- New Car Management Functions ---
    def register_car(self, car_id: str, model: str = "My Car"):
         """Registers a car with the server (associates it with current user as owner)."""
         logging.info(f"Attempting to register car '{car_id}' with owner '{self.user_id}'...")
         message = {
             "type": "REGISTER_CAR",
             "sender_id": self.user_id, # In real world, maybe admin action ID
             "payload": {
                 "car_id": car_id,
                 "owner_user_id": self.user_id,
                 "car_public_key": f"key_for_{car_id}", # Placeholder car key
                 "model": model
                 # TODO (AUTH): Add signature to authenticate this request.

             }
         }
         response = self._send_and_receive(self.server_addr, message)
         if response and response.get("type") == "REGISTER_CAR_ACK":
             logging.info(f"Car '{car_id}' registered successfully!")
             return True
         else:
             error = response.get("payload", {}).get("error", "Unknown error") if response else "No response"
             logging.error(f"Car registration failed: {error}")
             return False

    def delegate_access(self, car_id: str, recipient_user_id: str, permissions: list, duration_hours: float):
        """Delegates access for a car to another user."""
        if not permissions:
            logging.error("No permissions specified for delegation.")
            return None
        logging.info(f"Attempting to delegate access for car '{car_id}' to '{recipient_user_id}'...")
        message = {
             "type": "DELEGATE_ACCESS",
             "sender_id": self.user_id, # Must be owner
             "payload": {
                 "car_id": car_id,
                 "recipient_user_id": recipient_user_id,
                 "permissions": permissions,
                 "duration_seconds": int(duration_hours * 3600)
                 # TODO (AUTH): Add signature to authenticate this delegation request (proves ownership).

             }
        }
        response = self._send_and_receive(self.server_addr, message)
        if response and response.get("type") == "DELEGATE_ACK":
             payload = response.get("payload", {})
             delegation_id = payload.get("delegation_id")
             expires = payload.get("expires_at")
             logging.info(f"Delegation successful! ID: {delegation_id}, Expires: {time.ctime(expires) if expires else 'N/A'}")
             self.last_delegation_id = delegation_id # Store for easy revoke
             return delegation_id
        else:
             error = response.get("payload", {}).get("error", "Unknown error") if response else "No response"
             logging.error(f"Delegation failed: {error}")
             return None

    def revoke_delegation(self, delegation_id: str):
         """Revokes a previously created delegation."""
         if not delegation_id:
             logging.error("No delegation ID provided to revoke.")
             return False
         logging.info(f"Attempting to revoke delegation ID: {delegation_id}...")
         message = {
            "type": "REVOKE_DELEGATION",
            "sender_id": self.user_id, # Must be owner
            "payload": {
                "delegation_id": delegation_id
                # TODO (AUTH): Add signature to authenticate this revocation request.

            }
         }
         response = self._send_and_receive(self.server_addr, message)
         if response and response.get("type") == "REVOKE_DELEGATION_ACK":
             logging.info(f"Delegation '{delegation_id}' revoked successfully!")
             if self.last_delegation_id == delegation_id:
                 self.last_delegation_id = None
             return True
         else:
             error = response.get("payload", {}).get("error", "Unknown error") if response else "No response"
             logging.error(f"Failed to revoke delegation '{delegation_id}': {error}")
             return False

    # --- Car Interaction ---
    def request_car_action(self, action_type: str, target_car_addr=None):
        """Sends an action request (e.g., UNLOCK_REQUEST, START_REQUEST) to the car."""
        # Uses the default car address unless overridden
        # TODO (AUTH / UI): In a real app, biometric/PIN verification might be required here
        #   before allowing the private key to be used for signing the request.

        car_addr_to_use = target_car_addr if target_car_addr else self.car_addr

        logging.info(f"Attempting to send '{action_type}' request to car at {car_addr_to_use}...")


        # TODO (AUTH): Implement challenge-response for car actions if required.
        # Authentication payload (signatures etc.) is still missing here.
        # The car now relies on server validation based on sender_id.
        #   1. App sends initial request (e.g., "INITIATE_UNLOCK").
        #   2. Car responds with a nonce (challenge).
        #   3. App signs the nonce and sends it back in the actual action request (e.g., "UNLOCK_REQUEST").
        #   If not using challenge-response, sign the payload directly here.

        message = {
            "type": action_type,
            "sender_id": self.user_id,
            "payload": {
                # Placeholder - actual signature or signed challenge goes here
                "auth_data": "placeholder_for_crypto_team"
                # TODO (AUTH): Replace placeholder with actual signature / signed nonce.

            }
        }
        response = self._send_and_receive(car_addr_to_use, message)

        if response:
            response_type = response.get("type", "").upper()
            payload = response.get("payload", {})
            if "ACK" in response_type:
                 status = payload.get("status", "OK")
                 logging.info(f"{action_type} successful! Car status: {status}")
                 return True
            elif "NAK" in response_type or "ERROR" in response_type:
                 error_msg = payload.get("error", "Unknown reason")
                 logging.error(f"{action_type} failed: {error_msg}")
                 return False
            else:
                 logging.warning(f"Received unexpected response type for {action_type}: {response_type}")
                 return False
        else:
            logging.error(f"{action_type} failed: No response from car at {car_addr_to_use}.")
            return False


# --- Command Line Interface ---
def run_cli(client: AppClient):
    while True:
        print("\n--- Smartphone Car Access App ---")
        print(f"User: {client.user_id}")
        print("--- User/Server ---")
        print("1. Register User with Server")
        print("2. Check License Status")
        print("--- Car Management (Owner) ---")
        print("3. Register a New Car")
        print("4. Delegate Access to Car")
        print("5. Revoke Last Delegation")
        print("6. Revoke Specific Delegation")
        print("--- Car Interaction ---")
        print("7. Unlock Car")
        print("8. Start Car")
        print("9. Lock Car")
        print("0. Exit")

        choice = input("Enter your choice: ")

        try:
            if choice == '1':
                client.register_with_server()
            elif choice == '2':
                client.check_license_status()
            elif choice == '3':
                car_id = input("Enter Car ID (VIN) to register: ")
                model = input("Enter Car Model (optional): ")
                if car_id:
                    client.register_car(car_id, model or "Unknown Model")
            elif choice == '4':
                car_id = input("Enter Car ID to delegate access for: ")
                recipient = input("Enter Recipient User ID: ")
                perms_str = input(f"Enter Permissions (comma-separated, e.g., {config.PERMISSION_UNLOCK},{config.PERMISSION_START}): ")
                duration_h = float(input("Enter duration in hours (e.g., 1.5): ") or "1")
                permissions = [p.strip().upper() for p in perms_str.split(',') if p.strip()]
                if car_id and recipient and permissions:
                    client.delegate_access(car_id, recipient, permissions, duration_h)
                else:
                    print("Missing required info for delegation.")
            elif choice == '5':
                 if client.last_delegation_id:
                    client.revoke_delegation(client.last_delegation_id)
                 else:
                    print("No delegation ID stored from the last 'delegate' action.")
            elif choice == '6':
                 del_id = input("Enter Delegation ID to revoke: ")
                 if del_id:
                     client.revoke_delegation(del_id)
            elif choice == '7':
                client.request_car_action("UNLOCK_REQUEST")
            elif choice == '8':
                client.request_car_action("START_REQUEST")
            elif choice == '9':
                client.request_car_action("LOCK_REQUEST")
            elif choice == '0':
                print("Exiting.")
                break
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
             print(f"\nAn error occurred: {e}") # Catch potential errors like float conversion
             logging.exception("CLI Error") # Log traceback

        # input("Press Enter to continue...") # Pause for readability
        time.sleep(0.1)


if __name__ == "__main__":
    default_user = f"user_{int(time.time()) % 100}"
    user_id = input(f"Enter your user ID (e.g., 'user_besar') [default: {default_user}]: ") or default_user
    if not user_id: user_id = default_user

    print(f"Starting app client for user: {user_id}")
    app_client = AppClient(user_id)
    run_cli(app_client)