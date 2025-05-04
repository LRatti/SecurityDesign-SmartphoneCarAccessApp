# server/backend_server.py
import socket
import threading
import json
import logging
import os
import time
import uuid # For unique delegation IDs
import hashlib
import ssl # <-- Import ssl
from cryptography import x509 # <-- Add cryptography
from cryptography.hazmat.primitives import hashes as crypto_hashes # <-- Add cryptography hashes
from cryptography.hazmat.backends import default_backend # <-- Add cryptography backend
from utils import config, network_utils 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - Server - %(threadName)s - %(levelname)s - %(message)s')

class BackendServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Data Stores (in-memory caches, loaded from files)
        self.users = {} # user_id -> { 'public_key': '...', 'license_valid': True }
        self.cars = {} # car_id -> { 'owner_user_id': '...', 'car_public_key': '...', 'model': '...' }
        self.delegations = {} # delegation_id -> { 'car_id': ..., 'owner_user_id': ..., 'recipient_user_id': ..., 'permissions': [...], 'expiry_timestamp': ..., 'status': 'active'/'revoked'/'expired' }

        # Locks for thread safety when accessing shared data
        self.user_lock = threading.Lock()
        self.car_lock = threading.Lock()
        self.delegation_lock = threading.Lock()

        # --- TLS Setup for Backend Server ---
        self.server_ssl_context = self._create_server_ssl_context()

        # Load initial data
        self.load_data()

     # --- Create Backend Server SSL Context ---
    def _create_server_ssl_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            logging.info(f"Loading SERVER cert chain: {config.SERVER_CERT_FILE}, {config.SERVER_KEY_FILE}")
            context.load_cert_chain(certfile=config.SERVER_CERT_FILE, keyfile=config.SERVER_KEY_FILE)
            
            logging.info(f"Loading CA cert for client (app) verification: {config.CA_CERT_FILE}")
            # Require client certificate and verify it against our CA
            context.load_verify_locations(cafile=config.CA_CERT_FILE)
            context.verify_mode = ssl.CERT_REQUIRED # Require app client cert

            # Optional: Set specific TLS versions or cipher suites
            # context.minimum_version = ssl.TLSVersion.TLSv1_3

            logging.info("Backend Server SSL context created successfully for mTLS.")
            return context
        except ssl.SSLError as e:
            logging.critical(f"SSL Error creating backend server context: {e}")
            raise SystemExit("Failed to initialize backend SSL context - check certificate paths/permissions.")
        except FileNotFoundError as e:
             logging.critical(f"Certificate file not found for backend server: {e}")
             raise SystemExit("Failed to initialize backend SSL context - certificate file missing.")
        except Exception as e:
             logging.critical(f"Unexpected error creating backend SSL context: {e}")
             raise SystemExit("Failed to initialize backend SSL context.")

    def load_data(self):
        """Loads all data from JSON files."""
        self._load_json(config.REGISTRATION_FILE, self.users, self.user_lock, "user registrations")
        self._load_json(config.CARS_FILE, self.cars, self.car_lock, "cars")
        self._load_json(config.DELEGATIONS_FILE, self.delegations, self.delegation_lock, "delegations")

    def _load_json(self, filepath, data_dict, lock, description):
        """Helper to load data from a JSON file."""
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    loaded_data = json.load(f)
                with lock:
                    data_dict.clear() # Clear existing cache
                    data_dict.update(loaded_data) # Update with loaded data
                logging.info(f"Loaded {len(data_dict)} {description} from {filepath}")
            except json.JSONDecodeError:
                logging.error(f"Could not decode JSON from {filepath}. Starting fresh for {description}.")
                with lock: data_dict.clear()
            except Exception as e:
                 logging.error(f"Error loading {description} from {filepath}: {e}")
                 with lock: data_dict.clear()
        else:
             logging.info(f"{description.capitalize()} file ({filepath}) not found. Starting fresh.")
             with lock: data_dict.clear()

    def save_data(self):
        """Saves all data to JSON files."""
        # Make copies first, then save without holding locks during I/O
        with self.user_lock:
            users_copy = self.users.copy()
        with self.car_lock:
            cars_copy = self.cars.copy()
        with self.delegation_lock:
            delegations_copy = self.delegations.copy()

        self._save_json(config.REGISTRATION_FILE, users_copy, "user registrations")
        self._save_json(config.CARS_FILE, cars_copy, "cars")
        self._save_json(config.DELEGATIONS_FILE, delegations_copy, "delegations")

    def _save_json(self, filepath, data_to_save: dict, description: str):  # Removed lock argument
        """Helper to save data (passed as a copy) to a JSON file. Assumes caller handles locking."""
        try:
            with open(filepath, 'w') as f:
                json.dump(data_to_save, f, indent=4)
            # Log length of the saved data, not the potentially changed live dictionary
            logging.info(f"Saved {len(data_to_save)} {description} to {filepath}")
        except IOError as e:
            logging.error(f"Could not save {description} to {filepath}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error saving {description}: {e}")

    def _calculate_fingerprint_from_pem(self, cert_pem: str) -> str | None:
        """Calculates SHA-256 fingerprint of a certificate from PEM string."""
        try:
            # Load the certificate from PEM
            cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
            # Calculate SHA-256 hash of the DER encoded certificate
            fingerprint_bytes = cert.fingerprint(crypto_hashes.SHA256())
            return fingerprint_bytes.hex()
        except ValueError as e:
            logging.error(f"Failed to parse certificate PEM: {e}")
            return None
        except Exception as e:
            logging.error(f"Error calculating certificate fingerprint: {e}")
            return None

    def handle_client(self, ssl_client_socket: ssl.SSLSocket, address): # <-- Takes SSLSocket
        # Assign a name to the thread for better logging
        # NOTE: Communication with the app client for this validation should ideally ALSO use TLS.
        # For simplicity here, we are assuming the channel is secure or accepting the risk for the POC.
        # To add TLS here, you'd wrap client_socket similar to how the car server does.
        threading.current_thread().name = f"Client-{address[0]}:{address[1]}"
        logging.info(f"Accepted TLS connection from {address} (App Client)")

        # --- Log Client Cert Info ---
        try:
            client_cert = ssl_client_socket.getpeercert()
            if client_cert:
                 subject = dict(x[0] for x in client_cert.get('subject', []))
                 logging.debug(f"App Client Cert Subject: {subject}")
            else:
                 logging.warning("Could not get peer certificate details from App Client.")
        except Exception as e:
             logging.warning(f"Error getting peer certificate from App Client: {e}")

        try:
            while True:
                # Use the SSL socket for communication
                message = network_utils.receive_message(ssl_client_socket)
                if message is None:
                    break # Error or connection closed gracefully

                response = self.process_message(message) # Logic remains the same

                if response:
                    # Send response over the SSL socket
                    if not network_utils.send_message(ssl_client_socket, response):
                         logging.warning(f"Failed to send response to {address}. Closing TLS connection.")
                         break
        except ConnectionResetError:
             logging.info(f"Connection reset by peer {address}")
        except ssl.SSLError as e:
             logging.error(f"SSL Error during communication with App Client {address}: {e}")
        except Exception as e:
            logging.error(f"Error handling App Client {address}: {e}")
        finally:
            logging.info(f"Closing TLS connection from App Client {address}")
            try:
                ssl_client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass # Ignore if already closed
            ssl_client_socket.close()

    def process_message(self, message: dict) -> dict | None:
        """Processes incoming messages and returns a response dictionary or None."""
        msg_type = message.get('type')
        sender_id = message.get('sender_id') # Could be user_id or car_id
        payload = message.get('payload', {})
        # TODO (AUTH): Extract signature from message if present (e.g., signature = message.get('signature'))

        if not msg_type: # sender_id might be implicit for some server internal actions if needed
            logging.warning(f"Received message with missing type: {message}")
            return {"type": "ERROR", "sender_id": "server", "payload": {"error": "Missing message type"}}

        logging.info(f"Processing message type '{msg_type}' from '{sender_id or 'Unknown Sender'}'")

        response = {"sender_id": "server"} # Base for most responses
        # --- Helper function for verification ---
        def verify_user_signature(user_id, data_to_verify, signature_hex):
            # TODO (AUTH): Implement this function
            # 1. Get user's registered public key from self.users.
            # 2. Deserialize the public key.
            # 3. Decode the signature_hex.
            # 4. Verify the signature against the data_to_verify (e.g., json.dumps(payload)).
            # 5. Return True if valid, False otherwise. Handle errors (key not found, invalid signature).
            logging.warning(f"AUTH PLACEHOLDER: Signature verification for user '{user_id}' not implemented. Assuming valid.")
            return True # Placeholder - DANGER!


        # --- User Management ---
        if msg_type == "REGISTER":
             # TODO (AUTH): If registration requires signing (e.g., during a pairing ceremony),
             #   verify the signature here. For simple POC, maybe trust initial registration.
             # NOTE (AUTH): Storing the ACTUAL public key (PEM/bytes) from payload is crucial.

             if not sender_id: return {"type": "ERROR", "payload": {"error": "Missing sender_id for REGISTER"}}
             
              # --- Expect the app's PUBLIC KEY PEM ---
             app_public_key_pem = payload.get('app_public_key_pem')
             if not app_public_key_pem:
                  response.update({"type": "REGISTER_NAK", "payload": {"error": "Missing app_public_key_pem"}})
             # --- Basic PEM format check (optional but good) ---
             elif not isinstance(app_public_key_pem, str) or not app_public_key_pem.startswith("-----BEGIN PUBLIC KEY-----"):
                 response.update({"type": "REGISTER_NAK", "payload": {"error": "Invalid app public key format provided (expecting PEM)"}})
             else:
                 with self.user_lock:
                     logging.info(f"Registering user '{sender_id}' with public key:\n{app_public_key_pem[:80]}...") # Log start
                     self.users[sender_id] = {
                         # Store public key PEM directly
                         'public_key_pem': app_public_key_pem,
                         'license_valid': True
                     }
                     users_copy = self.users.copy()
                 self._save_json(config.REGISTRATION_FILE, users_copy, "user registrations")
                 response.update({"type": "REGISTER_ACK", "payload": {"status": "OK", "user_id": sender_id}})
                 logging.info(f"User '{sender_id}' registered/updated successfully.")

        elif msg_type == "CHECK_LICENSE":
            # TODO (AUTH): Verify signature from 'sender_id' on the payload/message content.
            # signature = message.get('signature')
            # data_signed = json.dumps(payload) # Or however the app signs it
            # if not verify_user_signature(sender_id, data_signed, signature):
            #     return {"type": "ERROR", "payload": {"error": "Invalid signature"}}

             if not sender_id: return {"type": "ERROR", "payload": {"error": "Missing sender_id for CHECK_LICENSE"}}
             with self.user_lock:
                 user_data = self.users.get(sender_id)
             if user_data:
                 is_valid = user_data.get('license_valid', False)
                 response.update({"type": "LICENSE_STATUS", "payload": {"user_id": sender_id, "is_valid": is_valid}})
             else:
                 response.update({"type": "LICENSE_STATUS", "payload": {"error": "User not registered", "user_id": sender_id, "is_valid": False}})

        # --- Car Management ---
        elif msg_type == "REGISTER_CAR":
            # TODO (AUTH): Verify signature from 'sender_id' (the owner) on the payload.
            #   This proves the user authorized adding this car under their name.
            # signature = message.get('signature')
            # data_signed = json.dumps(payload)
            # if not verify_user_signature(sender_id, data_signed, signature):

            # In POC, any registered user can register a car. In reality, needs admin/verification.
            car_id = payload.get('car_id')
            owner_user_id = payload.get('owner_user_id')
            # --- Expect the full certificate PEM now ---
            car_certificate_pem = payload.get('car_certificate_pem')
            model = payload.get('model', "Unknown Model")

            if not car_id or not owner_user_id or not car_certificate_pem:
                 response.update({"type": "REGISTER_CAR_NAK", "payload": {"error": "Missing car_id, owner_user_id, or car_certificate_pem"}})
            else:
                 # Calculate fingerprint from provided PEM
                 fingerprint = self._calculate_fingerprint_from_pem(car_certificate_pem)
                 if not fingerprint:
                      response.update({"type": "REGISTER_CAR_NAK", "payload": {"error": "Invalid car certificate format provided"}})
                 else:
                     # Check if owner exists
                     with self.user_lock:
                        if owner_user_id not in self.users:
                            response.update({"type": "REGISTER_CAR_NAK", "payload": {"error": f"Owner user '{owner_user_id}' not registered"}})
                        else:
                            # Proceed with registration
                            with self.car_lock:
                                logging.info(f"Registering car '{car_id}' with fingerprint: {fingerprint}")
                                self.cars[car_id] = {
                                    'owner_user_id': owner_user_id,
                                    'model': model,
                                    # Store the fingerprint, not the placeholder key or full cert
                                    'certificate_fingerprint_sha256': fingerprint,
                                    # Optionally store PEM if needed elsewhere, but fingerprint is key for validation
                                    # 'certificate_pem': car_certificate_pem
                                }
                                # --- Need to save cars data ---
                                cars_copy = self.cars.copy() # Create copy within lock
                            # --- Save outside the lock ---
                            self._save_json(config.CARS_FILE, cars_copy, "cars")
                        response.update({"type": "REGISTER_CAR_ACK", "payload": {"status": "OK", "car_id": car_id, "owner": owner_user_id}})
                        logging.info(f"Car '{car_id}' registered/updated for owner '{owner_user_id}'.")

        # --- Delegation Management ---
        elif msg_type == "DELEGATE_ACCESS":
            # TODO (AUTH): Verify signature from 'sender_id' (owner) on the payload. Crucial.
            # signature = message.get('signature')
            # data_signed = json.dumps(payload)
            # if not verify_user_signature(sender_id, data_signed, signature):
            #     return {"type": "DELEGATE_NAK", "payload": {"error": "Invalid signature for delegation"}}

            # sender_id here MUST be the owner initiating the delegation
            if not sender_id: return {"type": "ERROR", "payload": {"error": "Missing sender_id (owner) for DELEGATE_ACCESS"}}
            car_id = payload.get('car_id')
            recipient_user_id = payload.get('recipient_user_id')
            permissions = payload.get('permissions', [])
            duration_seconds = payload.get('duration_seconds', 3600) # Default 1 hour

            if not car_id or not recipient_user_id or not permissions:
                response.update({"type": "DELEGATE_NAK", "payload": {"error": "Missing car_id, recipient_user_id, or permissions"}})
            else:
                 # Validate permissions
                 if not all(p in config.VALID_PERMISSIONS for p in permissions):
                     response.update({"type": "DELEGATE_NAK", "payload": {"error": f"Invalid permissions specified. Valid: {config.VALID_PERMISSIONS}"}})
                 else:
                     # Check ownership
                     with self.car_lock:
                         car_info = self.cars.get(car_id)
                     if not car_info:
                         response.update({"type": "DELEGATE_NAK", "payload": {"error": f"Car '{car_id}' not registered"}})
                     elif car_info.get('owner_user_id') != sender_id:
                         response.update({"type": "DELEGATE_NAK", "payload": {"error": f"User '{sender_id}' does not own car '{car_id}'"}})
                     else:
                         # Check if recipient exists
                         with self.user_lock:
                            if recipient_user_id not in self.users:
                                 response.update({"type": "DELEGATE_NAK", "payload": {"error": f"Recipient user '{recipient_user_id}' not registered"}})
                            else:
                                 # Create delegation
                                 delegation_id = str(uuid.uuid4())
                                 expiry_timestamp = time.time() + duration_seconds
                                 delegation_record = {
                                     'delegation_id': delegation_id, # Add for easier lookup if needed
                                     'car_id': car_id,
                                     'owner_user_id': sender_id,
                                     'recipient_user_id': recipient_user_id,
                                     'permissions': permissions,
                                     'expiry_timestamp': expiry_timestamp,
                                     'status': 'active'
                                 }
                                 with self.delegation_lock:
                                     self.delegations[delegation_id] = delegation_record
                                     self._save_json(config.DELEGATIONS_FILE, self.delegations, "delegations")

                                 response.update({
                                     "type": "DELEGATE_ACK",
                                     "payload": {
                                         "status": "OK",
                                         "delegation_id": delegation_id,
                                         "car_id": car_id,
                                         "recipient": recipient_user_id,
                                         "permissions": permissions,
                                         "expires_at": expiry_timestamp
                                     }
                                 })
                                 logging.info(f"Delegation '{delegation_id}' created for car '{car_id}' to user '{recipient_user_id}' by owner '{sender_id}'.")

        elif msg_type == "REVOKE_DELEGATION":
             # TODO (AUTH): Verify signature from 'sender_id' (owner) on the payload. Crucial.
             # signature = message.get('signature')
             # data_signed = json.dumps(payload)
             # if not verify_user_signature(sender_id, data_signed, signature):
             #     return {"type": "REVOKE_DELEGATION_NAK", "payload": {"error": "Invalid signature for revocation"}}

             # sender_id MUST be the owner
             if not sender_id: return {"type": "ERROR", "payload": {"error": "Missing sender_id (owner) for REVOKE_DELEGATION"}}
             delegation_id = payload.get('delegation_id')
             if not delegation_id:
                  response.update({"type": "REVOKE_DELEGATION_NAK", "payload": {"error": "Missing delegation_id"}})
             else:
                  with self.delegation_lock:
                     delegation = self.delegations.get(delegation_id)
                     if not delegation:
                         response.update({"type": "REVOKE_DELEGATION_NAK", "payload": {"error": "Delegation not found"}})
                     elif delegation['owner_user_id'] != sender_id:
                         response.update({"type": "REVOKE_DELEGATION_NAK", "payload": {"error": "Only the owner can revoke"}})
                     elif delegation['status'] != 'active':
                          response.update({"type": "REVOKE_DELEGATION_NAK", "payload": {"error": f"Delegation already {delegation['status']}"}})
                     else:
                         delegation['status'] = 'revoked'
                         self._save_json(config.DELEGATIONS_FILE, self.delegations, "delegations")
                         response.update({"type": "REVOKE_DELEGATION_ACK", "payload": {"status": "OK", "delegation_id": delegation_id}})
                         logging.info(f"Delegation '{delegation_id}' revoked by owner '{sender_id}'.")
        
        # --- NEW: Certificate Validation (Called by App Client) ---
        elif msg_type == "VALIDATE_CAR_CERT":
            # This request comes from the App Client (sender_id is user_id)
            if not sender_id: return {"type": "ERROR", "payload": {"error": "Missing sender_id (user) for VALIDATE_CAR_CERT"}}

            car_id_to_validate = payload.get('car_id')
            received_fingerprint = payload.get('certificate_fingerprint')

            if not car_id_to_validate or not received_fingerprint:
                response.update({"type": "VALIDATE_CAR_CERT_NAK", "payload": {"error": "Missing car_id or certificate_fingerprint"}})
            else:
                with self.car_lock:
                    car_data = self.cars.get(car_id_to_validate)

                if not car_data:
                    logging.warning(f"Validation failed: Car ID '{car_id_to_validate}' not found for user '{sender_id}'.")
                    response.update({"type": "VALIDATE_CAR_CERT_NAK", "payload": {"car_id": car_id_to_validate, "status": "INVALID", "reason": "Car not registered"}})
                else:
                    expected_fingerprint = car_data.get('certificate_fingerprint_sha256')
                    if not expected_fingerprint:
                        # This shouldn't happen if registration is correct
                        logging.error(f"Internal Error: Missing stored fingerprint for car '{car_id_to_validate}'.")
                        response.update({"type": "VALIDATE_CAR_CERT_NAK", "payload": {"car_id": car_id_to_validate, "status": "INVALID", "reason": "Server internal error: fingerprint missing"}})
                    elif received_fingerprint == expected_fingerprint:
                        logging.info(f"Certificate validation SUCCESS for car '{car_id_to_validate}' requested by user '{sender_id}'. Fingerprint: {received_fingerprint}")
                        response.update({"type": "VALIDATE_CAR_CERT_ACK", "payload": {"car_id": car_id_to_validate, "status": "VALID"}})
                    else:
                        logging.warning(f"Certificate validation FAILED for car '{car_id_to_validate}' requested by user '{sender_id}'. Expected: {expected_fingerprint}, Received: {received_fingerprint}")
                        response.update({"type": "VALIDATE_CAR_CERT_NAK", "payload": {"car_id": car_id_to_validate, "status": "INVALID", "reason": "Certificate fingerprint mismatch"}})
        

        # --- App Public Key Validation (Called by Car Server) ---
        elif msg_type == "VALIDATE_APP_PUBKEY": # New message type
            # Request from Car Server (sender_id is car_id)
            if not sender_id: return {"type": "ERROR", "payload": {"error": "Missing sender_id (car) for VALIDATE_APP_PUBKEY"}}

            user_id_to_validate = payload.get('user_id_to_validate')
            received_app_pubkey_pem = payload.get('app_public_key_pem')

            if not user_id_to_validate or not received_app_pubkey_pem:
                response.update({"type": "VALIDATE_APP_PUBKEY_NAK", "payload": {"error": "Missing user_id_to_validate or app_public_key_pem"}})
            else:
                with self.user_lock:
                    user_data = self.users.get(user_id_to_validate)

                if not user_data:
                    logging.warning(f"App PubKey Validation failed: User ID '{user_id_to_validate}' not found (req by car '{sender_id}').")
                    response.update({"type": "VALIDATE_APP_PUBKEY_NAK", "payload": {"user_id": user_id_to_validate, "status": "INVALID", "reason": "User not registered"}})
                else:
                    expected_pubkey_pem = user_data.get('public_key_pem')
                    if not expected_pubkey_pem:
                        logging.error(f"Internal Error: Missing stored public key PEM for user '{user_id_to_validate}'.")
                        response.update({"type": "VALIDATE_APP_PUBKEY_NAK", "payload": {"user_id": user_id_to_validate, "status": "INVALID", "reason": "Server internal error: user public key missing"}})
                    # --- Direct String Comparison of PEMs ---
                    elif received_app_pubkey_pem == expected_pubkey_pem:
                        logging.info(f"App public key validation SUCCESS for user '{user_id_to_validate}' requested by car '{sender_id}'.")
                        response.update({"type": "VALIDATE_APP_PUBKEY_ACK", "payload": {"user_id": user_id_to_validate, "status": "VALID"}})
                    else:
                        logging.warning(f"App public key validation FAILED for user '{user_id_to_validate}' requested by car '{sender_id}'. Keys do not match.")
                        # Don't log the keys themselves unless debugging heavily
                        response.update({"type": "VALIDATE_APP_PUBKEY_NAK", "payload": {"user_id": user_id_to_validate, "status": "INVALID", "reason": "App public key mismatch"}})

        # --- Access Validation (Called by Car Server) ---
        elif msg_type == "VALIDATE_ACCESS_ATTEMPT":
             # TODO (AUTH): Verify that this request genuinely came from the car identified by 'sender_id'.
             #   This requires the car to have a registered key and sign this request.
             # car_signature = message.get('car_signature')
             # car_data_signed = json.dumps(payload)
             # if not verify_car_signature(sender_id, car_data_signed, car_signature): # Need verify_car_signature helper
             #    return {"type": "ACCESS_DENIED", "payload": {"error": "Invalid car signature on validation request"}}

             # sender_id here is the car_id making the request
             requesting_user_id = payload.get('requesting_user_id')
             car_id = payload.get('car_id') # Car should know its own ID, but client sends it for verification
             requested_action = payload.get('requested_action') # e.g., "UNLOCK", "START"

             if not requesting_user_id or not car_id or not requested_action:
                   response.update({"type": "ACCESS_DENIED", "payload": {"error": "Incomplete validation request"}})
             else:
                   # 1. Check Ownership
                   with self.car_lock:
                      car_info = self.cars.get(car_id)
                   is_owner = car_info and car_info['owner_user_id'] == requesting_user_id

                   # 2. Check License (Crucial for START action, maybe optional for UNLOCK)
                   with self.user_lock:
                       user_info = self.users.get(requesting_user_id)
                   license_valid = user_info and user_info.get('license_valid', False)

                   access_granted = False
                   permissions_granted = []
                   grant_reason = "Unknown"

                   if is_owner:
                        # Owner access
                        grant_reason = "Owner"
                        if requested_action == config.PERMISSION_START and not license_valid:
                             access_granted = False
                             response.update({"type": "ACCESS_DENIED", "payload": {"error": "Owner license invalid/revoked", "reason": grant_reason}})
                        else:
                            access_granted = True
                            permissions_granted = [config.PERMISSION_UNLOCK, config.PERMISSION_START] # Owner gets all perms
                            # Check if the requested action is implicitly allowed for owner
                            if requested_action in permissions_granted:
                                 response.update({"type": "ACCESS_GRANTED", "payload": {"status": "OK", "reason": grant_reason, "granted_permissions": permissions_granted}})
                            else:
                                 # Should not happen if request action is valid
                                  access_granted = False
                                  response.update({"type": "ACCESS_DENIED", "payload": {"error": f"Action '{requested_action}' not applicable", "reason": grant_reason}})

                   else:
                       # 3. Check Delegations if not owner
                       grant_reason = "Delegation"
                       found_valid_delegation = False
                       with self.delegation_lock:
                           # Iterate through copies to avoid issues if modifying during iteration (though we only read here)
                           active_delegations = [d for d in self.delegations.values() if
                                                  d['car_id'] == car_id and
                                                  d['recipient_user_id'] == requesting_user_id and
                                                  d['status'] == 'active' and
                                                  time.time() < d['expiry_timestamp']]

                       if active_delegations:
                           # In theory, there should only be one active for a user/car, but check all valid ones
                           for delegation in active_delegations:
                               if requested_action in delegation.get('permissions', []):
                                    # Now check license for START permission via delegation
                                    if requested_action == config.PERMISSION_START and not license_valid:
                                        response.update({"type": "ACCESS_DENIED", "payload": {"error": "Delegated user license invalid/revoked", "reason": grant_reason, "delegation_id": delegation['delegation_id']}})
                                        found_valid_delegation = False # Mark as invalid attempt overall
                                        break # Stop checking other delegations for this user/car
                                    else:
                                        # Valid delegation found for the action & license OK if starting
                                        permissions_granted = delegation['permissions']
                                        response.update({"type": "ACCESS_GRANTED", "payload": {"status": "OK", "reason": grant_reason, "delegation_id": delegation['delegation_id'], "granted_permissions": permissions_granted}})
                                        found_valid_delegation = True
                                        break # Found a working delegation

                       if not found_valid_delegation and "error" not in response.get("payload", {}): # Don't overwrite license error
                           response.update({"type": "ACCESS_DENIED", "payload": {"error": f"No active/valid delegation found for user '{requesting_user_id}' on car '{car_id}' with permission for '{requested_action}'", "reason": grant_reason}})
                           access_granted = False # Explicitly set
                       elif found_valid_delegation:
                           access_granted = True

                   if access_granted:
                       logging.info(f"Access GRANTED for user '{requesting_user_id}' on car '{car_id}' for action '{requested_action}'. Reason: {grant_reason}.")
                   else:
                       logging.warning(f"Access DENIED for user '{requesting_user_id}' on car '{car_id}' for action '{requested_action}'. Reason: {response.get('payload',{}).get('error', 'Denied')}.")



        # --- Unknown Message Type ---
        else:
            logging.warning(f"Received unknown message type '{msg_type}' from {sender_id or 'Unknown Sender'}")
            response.update({"type": "ERROR", "payload": {"error": f"Unknown message type: {msg_type}"}})

        return response

    def start(self):
        if not self.server_ssl_context: # Check if context creation failed
            logging.critical("Cannot start backend server without a valid SSL context.")
            return

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            logging.info(f"Backend server listening securely (TLS) on {self.host}:{self.port}")

            while True:
                try:
                    client_socket, address = self.server_socket.accept()
                    logging.info(f"Incoming connection attempt from {address}")
                    # --- Wrap socket with Backend Server SSL Context ---
                    try:
                        # Use the server_ssl_context here
                        ssl_sock = self.server_ssl_context.wrap_socket(client_socket, server_side=True)
                        logging.debug(f"Backend SSL handshake initiated with {address}")

                        # Pass the secure socket to the handler thread
                        client_thread = threading.Thread(target=self.handle_client, args=(ssl_sock, address), daemon=True)
                        client_thread.name = f"Handler-{address[0]}:{address[1]}"
                        client_thread.start()
                    except ssl.SSLError as e:
                         logging.error(f"Backend SSL Handshake failed with {address}: {e}. Closing raw socket.")
                         client_socket.close()
                    except Exception as e:
                        logging.error(f"Error wrapping socket or starting thread for backend connection {address}: {e}")
                        client_socket.close()
                except KeyboardInterrupt:
                     logging.info("Shutdown signal received.")
                     break
                except Exception as e:
                    logging.error(f"Error accepting connection: {e}")

        except socket.error as e:
            logging.critical(f"Could not start server on {self.host}:{self.port}. Error: {e}")
        finally:
             logging.info("Shutting down server...")
             # Save final data state on shutdown
             self.save_data()
             self.server_socket.close()
             logging.info("Server socket closed.")

if __name__ == "__main__":
    server = BackendServer(config.SERVER_IP, config.SERVER_PORT)
    server.start()