# car/car_server.py
import socket
import threading
import logging
from utils import config, network_utils
import os
logging.basicConfig(level=logging.INFO, format='%(asctime)s - CarServer [{car_id}] - %(threadName)s - %(levelname)s - %(message)s')

class CarServer:
    def __init__(self, car_id, host, port):
        self.car_id = car_id
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.is_unlocked = False
        self.is_started = False
        self.backend_server_addr = (config.SERVER_IP, config.SERVER_PORT)
        # Inject car_id into logger extra context for formatting
        self.logger = logging.getLogger(__name__)
        self.logger_adapter = logging.LoggerAdapter(self.logger, {'car_id': self.car_id})
        # TODO (AUTH): Load car's private key securely (e.g., from file/secure element).
        self.car_private_key = None # Replace with actual key object

        # TODO (AUTH): Potentially store/cache public keys of authorized users fetched from server
        #   to allow offline verification or faster online verification.
        self.user_public_keys_cache = {} # Example: { 'user_id': loaded_public_key_object }

    def _log(self, level, msg, *args, **kwargs):
        """Helper for logging with car_id context."""
        self.logger_adapter.log(level, msg, *args, **kwargs)

    def _connect_to_backend(self):
        """Establishes a connection to the backend server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(self.backend_server_addr)
            self._log(logging.DEBUG, f"Connected to backend server at {self.backend_server_addr}")
            return sock
        except socket.error as e:
            self._log(logging.ERROR, f"Failed to connect to backend server {self.backend_server_addr}: {e}")
            return None

    def _validate_action_with_server(self, requesting_user_id: str, action: str) -> bool:
        """Asks the backend server if the user is allowed to perform the action."""
        self._log(logging.INFO, f"Validating action '{action}' for user '{requesting_user_id}' with backend server.")
        backend_sock = self._connect_to_backend()
        if not backend_sock:
            return False # Cannot validate if connection fails

        validation_request = {
            "type": "VALIDATE_ACCESS_ATTEMPT",
            "sender_id": self.car_id, # Car identifies itself
            "payload": {
                "requesting_user_id": requesting_user_id,
                "car_id": self.car_id,
                "requested_action": action
            }
            # TODO (AUTH): Add signature from the car to authenticate this request to the server.
            #   Sign the payload using self.car_private_key.
            #   validation_request['car_signature'] = sign(...)

        }

        access_granted = False
        try:
            if network_utils.send_message(backend_sock, validation_request):
                response = network_utils.receive_message(backend_sock)
                # TODO (AUTH): Optionally verify signature on response from server.

                if response and response.get("type") == "ACCESS_GRANTED":
                    self._log(logging.INFO, f"Server GRANTED access for '{requesting_user_id}' to perform '{action}'. Reason: {response.get('payload',{}).get('reason', 'N/A')}")
                    access_granted = True
                    # TODO (AUTH): Optionally cache the user's public key if sent by server
                    #   or cache the temporary grant itself for offline use.

                elif response:
                     error_msg = response.get("payload", {}).get("error", "Unknown reason")
                     self._log(logging.WARNING, f"Server DENIED access for '{requesting_user_id}' to perform '{action}'. Reason: {error_msg}")
                else:
                     self._log(logging.ERROR, "No valid response received from backend server during validation.")
            else:
                 self._log(logging.ERROR, "Failed to send validation request to backend server.")
        except Exception as e:
             self._log(logging.ERROR, f"Error during validation communication with backend: {e}")
        finally:
            self._log(logging.DEBUG, f"Closing connection to backend server after validation.")
            backend_sock.close()

        return access_granted


    def handle_client(self, client_socket: socket.socket, address):
        # Assign a name to the thread for better logging
        threading.current_thread().name = f"App-{address[0]}:{address[1]}"
        self._log(logging.INFO, f"Accepted connection from {address}")
        try:
            while True:
                message = network_utils.receive_message(client_socket)
                if message is None:
                    break # Error or connection closed

                response = self.process_message(message)

                if response:
                    if not network_utils.send_message(client_socket, response):
                         self._log(logging.WARNING, f"Failed to send response to {address}. Closing.")
                         break
        except ConnectionResetError:
             self._log(logging.INFO, f"Connection reset by peer {address}")
        except Exception as e:
            self._log(logging.ERROR, f"Error handling client {address}: {e}")
        finally:
            self._log(logging.INFO, f"Closing connection from {address}")
            client_socket.close()

    def process_message(self, message: dict) -> dict | None:
        msg_type = message.get('type')
        # This is the user interacting with the car via the app
        requesting_user_id = message.get('sender_id')
        payload = message.get('payload', {}) # Use if needed
        # TODO (AUTH): Extract signature/auth_data from payload.
        #   auth_data = payload.get('auth_data') # Could be signature or signed nonce

        if not msg_type or not requesting_user_id:
            self._log(logging.WARNING, f"Received incomplete message: {message}")
            return {"type": "ERROR", "sender_id": self.car_id, "payload": {"error": "Incomplete message (missing type or sender_id)"}}

        self._log(logging.INFO, f"Processing message type '{msg_type}' from user '{requesting_user_id}'")

        response = {"sender_id": self.car_id}

        # --- Helper for App Signature Verification ---
        def verify_app_signature(user_id, data_signed, signature):
            # TODO (AUTH): Implement this function.
            # 1. Get user's public key (e.g., from cache self.user_public_keys_cache or request from server).
            # 2. Verify the signature against the data_signed.
            # 3. Return True/False. Handle key not found, invalid sig.
            self._log(logging.WARNING, f"AUTH PLACEHOLDER: App signature verification for user '{user_id}' not implemented.")
            # For Challenge-Response:
            # - Need to store the nonce sent to the app.
            # - Verify signature against the *stored nonce*.
            # - Invalidate nonce after use.
            return True # Placeholder

        # --- Car Actions (require validation AND direct app auth) ---
        action_requires_direct_auth = msg_type in ["UNLOCK_REQUEST", "START_REQUEST", "LOCK_REQUEST"]

        # TODO (AUTH): Add Challenge-Response Handling Here if applicable
        #   - If msg_type is INITIATE_UNLOCK/START: generate nonce, store it mapped to user/session, send back nonce.
        #   - If msg_type is UNLOCK/START_REQUEST: Retrieve expected nonce, verify signed nonce in auth_data.

        if action_requires_direct_auth:
             # TODO (AUTH): Perform direct verification of the app's request *before* contacting the server.
             #   Extract signature/signed nonce from auth_data.
             #   data_to_verify = ... # Depends on what the app signs (nonce or payload)
             #   if not verify_app_signature(requesting_user_id, data_to_verify, auth_data):
             #       self._log(logging.warning, f"Direct authentication failed for {requesting_user_id} for action {msg_type}")
             #       return {"type": f"{msg_type.split('_')[0]}_NAK", "payload": {"error": "Direct authentication failed"}}
             pass # Placeholder for actual verification call

        # --- Car Actions (require validation) ---
        if msg_type == "UNLOCK_REQUEST":
            action_to_validate = config.PERMISSION_UNLOCK
            if self._validate_action_with_server(requesting_user_id, action_to_validate):
                self.is_unlocked = True
                self.is_started = False # Ensure started state is reset
                response.update({"type": "UNLOCK_ACK", "payload": {"status": "Unlocked"}})
                self._log(logging.INFO, f"Car unlocked by {requesting_user_id} (Validation OK)")
            else:
                 response.update({"type": "UNLOCK_NAK", "payload": {"error": "Access denied by server or validation failed"}})
                 self._log(logging.WARNING, f"Unlock failed for {requesting_user_id} (Validation Failed)")

        elif msg_type == "START_REQUEST":
            action_to_validate = config.PERMISSION_START
            if not self.is_unlocked:
                 response.update({"type": "START_NAK", "payload": {"error": "Car is locked"}})
                 self._log(logging.WARNING, f"Start failed for {requesting_user_id} (Car locked)")
            elif self._validate_action_with_server(requesting_user_id, action_to_validate):
                 self.is_started = True
                 response.update({"type": "START_ACK", "payload": {"status": "Started"}})
                 self._log(logging.INFO, f"Car started by {requesting_user_id} (Validation OK)")
            else: # Validation failed
                 response.update({"type": "START_NAK", "payload": {"error": "Access denied by server or validation failed"}})
                 self._log(logging.WARNING, f"Start failed for {requesting_user_id} (Validation Failed)")

        elif msg_type == "LOCK_REQUEST":
            # Optional: Should locking require validation? Maybe only if unlocked by someone else?
            # For simplicity, let's allow anyone connected to lock (could be debated).
            # Or, maybe validate with UNLOCK permission? Let's validate.
             action_to_validate = config.PERMISSION_UNLOCK # Require unlock permission to lock again
             if self._validate_action_with_server(requesting_user_id, action_to_validate):
                 self.is_unlocked = False
                 self.is_started = False
                 response.update({"type": "LOCK_ACK", "payload": {"status": "Locked"}})
                 self._log(logging.INFO, f"Car locked by {requesting_user_id} (Validation OK)")
             else:
                  response.update({"type": "LOCK_NAK", "payload": {"error": "Access denied for locking (validation failed)"}})
                  self._log(logging.WARNING, f"Lock failed for {requesting_user_id} (Validation Failed)")


        # --- Simple Hello/Ping (doesn't need validation) ---
        elif msg_type == "HELLO":
             response.update({"type": "HELLO_ACK", "payload": {"car_id": self.car_id, "status": "Ready"}})


        # --- Unknown ---
        else:
            self._log(logging.WARNING, f"Received unknown message type '{msg_type}' from {requesting_user_id}")
            response.update({"type": "ERROR", "payload": {"error": f"Unknown message type: {msg_type}"}})

        return response

    def start(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self._log(logging.INFO, f"Car server listening on {self.host}:{self.port}")

            while True:
                 try:
                    client_socket, address = self.server_socket.accept()
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True)
                    client_thread.name = f"Handler-{address[0]}:{address[1]}" # Name the thread
                    client_thread.start()
                 except KeyboardInterrupt:
                     self._log(logging.INFO, f"Shutdown signal received.")
                     break
                 except Exception as e:
                    self._log(logging.ERROR, f"Error accepting connection: {e}")

        except socket.error as e:
            self._log(logging.CRITICAL, f"Could not start server on {self.host}:{self.port}. Error: {e}")
        finally:
            self._log(logging.INFO, f"Shutting down server...")
            self.server_socket.close()
            self._log(logging.INFO, f"Server socket closed.")


if __name__ == "__main__":
    # Should get this from config/secure storage in a real car
    car_id = os.environ.get("CAR_ID", "CAR_VIN_DEMO_789")
    car = CarServer(car_id, config.CAR_IP, config.CAR_PORT)
    car.start()