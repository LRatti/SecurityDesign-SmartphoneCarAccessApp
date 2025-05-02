# server/backend_server.py
import socket
import threading
import json
import logging
import os
import time
import uuid # For unique delegation IDs
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

        # Load initial data
        self.load_data()

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

    def handle_client(self, client_socket: socket.socket, address):
        # Assign a name to the thread for better logging
        threading.current_thread().name = f"Client-{address[0]}:{address[1]}"
        logging.info(f"Accepted connection from {address}")
        try:
            while True:
                message = network_utils.receive_message(client_socket)
                if message is None:
                    break

                response = self.process_message(message)

                if response:
                    if not network_utils.send_message(client_socket, response):
                         logging.warning(f"Failed to send response to {address}. Closing connection.")
                         break
        except ConnectionResetError:
             logging.info(f"Connection reset by peer {address}")
        except Exception as e:
            logging.error(f"Error handling client {address}: {e}")
        finally:
            logging.info(f"Closing connection from {address}")
            client_socket.close()

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
             public_key = payload.get('public_key')
             if not public_key:
                  response.update({"type": "REGISTER_NAK", "payload": {"error": "Missing public key"}})
             else:
                 with self.user_lock:
                     self.users[sender_id] = {'public_key': public_key, 'license_valid': True}
                     self._save_json(config.REGISTRATION_FILE, self.users, "user registrations") # Save immediately
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
            car_public_key = payload.get('car_public_key', "placeholder_car_key") # Optional
            model = payload.get('model', "Unknown Model")

            if not car_id or not owner_user_id:
                 response.update({"type": "REGISTER_CAR_NAK", "payload": {"error": "Missing car_id or owner_user_id"}})
            else:
                 # Check if owner exists
                 with self.user_lock:
                    if owner_user_id not in self.users:
                        response.update({"type": "REGISTER_CAR_NAK", "payload": {"error": f"Owner user '{owner_user_id}' not registered"}})
                    else:
                        # Proceed with registration
                        with self.car_lock:
                            if car_id in self.cars:
                                logging.warning(f"Car '{car_id}' already registered. Updating owner/details.")
                            self.cars[car_id] = {
                                'owner_user_id': owner_user_id,
                                'car_public_key': car_public_key,
                                'model': model
                            }
                            self._save_json(config.CARS_FILE, self.cars, "cars")
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
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            logging.info(f"Backend server listening on {self.host}:{self.port}")

            while True:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True)
                    # Naming the thread helps debugging logs
                    client_thread.name = f"Handler-{address[0]}:{address[1]}"
                    client_thread.start()
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