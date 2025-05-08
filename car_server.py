# car/car_server.py
import socket
import threading
import logging
import ssl # <-- Import ssl
from utils import config, network_utils
import os
# --- Need cryptography for parsing cert and serializing key ---
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - CarServer [{car_id}] - %(threadName)s - %(levelname)s - %(message)s')

class CarServer:
    def __init__(self, car_id, host, port):
        self.car_id = car_id
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.is_unlocked = False
        self.is_started = False
        self.started_by_user_id = None  # Track who started the car
        self.backend_server_addr = (config.SERVER_IP, config.SERVER_PORT)
        # Inject car_id into logger extra context for formatting
        self.logger = logging.getLogger(__name__)
        self.logger_adapter = logging.LoggerAdapter(self.logger, {'car_id': self.car_id})

        # --- TLS Setup ---
        # Context for incoming connections from AppClient
        self.incoming_ssl_context = self._create_incoming_ssl_context() # Renamed
        # NEW: Context for outgoing connections to BackendServer
        self.outgoing_ssl_context = self._create_outgoing_ssl_context()

        # TODO (AUTH): Load car's private key securely (e.g., from file/secure element).
        self.car_private_key = None # Replace with actual key object

        # TODO (AUTH): Potentially store/cache public keys of authorized users fetched from server
        #   to allow offline verification or faster online verification.
        self.user_public_keys_cache = {} # Example: { 'user_id': loaded_public_key_object }

    # ---  Create SSL Context for INCOMING connections ---
    def _create_incoming_ssl_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            self._log(logging.INFO, f"Loading CAR cert chain: {config.CAR_CERT_FILE}, {config.CAR_KEY_FILE}")
            context.load_cert_chain(certfile=config.CAR_CERT_FILE, keyfile=config.CAR_KEY_FILE)

            self._log(logging.INFO, f"Loading CA chain for client verification: {config.CA_CHAIN_FILE}") # Use CA_CHAIN_FILE
            context.load_verify_locations(cafile=config.CA_CHAIN_FILE) # Use CA_CHAIN_FILE
            context.verify_mode = ssl.CERT_REQUIRED

            # Optional: Set specific TLS versions or cipher suites
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.set_ciphers('ECDHE+AESGCM:!aNULL') # Example

            self._log(logging.INFO, "INCOMING SSL context created successfully for mTLS (Car <- App).")
            return context
        except ssl.SSLError as e:
            self._log(logging.CRITICAL, f"SSL Error creating server context: {e}")
            raise SystemExit("Failed to initialize SSL context - check certificate paths and permissions.")
        except FileNotFoundError as e:
             self._log(logging.CRITICAL, f"Certificate file not found: {e}")
             raise SystemExit("Failed to initialize SSL context - certificate file missing.")
        except Exception as e:
             self._log(logging.CRITICAL, f"Unexpected error creating INCOMING SSL context: {e}")
             raise SystemExit("Failed to initialize INCOMING SSL context.")


     # --- Create SSL Context for OUTGOING connections ---
    def _create_outgoing_ssl_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            self._log(logging.INFO, f"Loading CAR cert chain for backend auth: {config.CAR_CERT_FILE}, {config.CAR_KEY_FILE}")
            # Uses CAR's cert/key TO authenticate itself TO BackendServer
            context.load_cert_chain(certfile=config.CAR_CERT_FILE, keyfile=config.CAR_KEY_FILE)

            self._log(logging.INFO, f"Loading CA chain for backend server verification: {config.CA_CHAIN_FILE}") # Use CA_CHAIN_FILE
            # Uses CA cert TO verify the BackendServer's certificate
            context.load_verify_locations(cafile=config.CA_CHAIN_FILE) # Use CA_CHAIN_FILE
            context.verify_mode = ssl.CERT_REQUIRED

            # Hostname checking for the backend server - IMPORTANT
            context.check_hostname = False # Set True if backend server cert CN matches config.SERVER_IP/hostname
            if not context.check_hostname:
                 self._log(logging.WARNING, "SSL Hostname Check is DISABLED for Car->Backend connection.")

            self._log(logging.INFO, "OUTGOING SSL context created successfully for mTLS (Car -> Backend).")
            return context
        except ssl.SSLError as e:
            self._log(logging.CRITICAL, f"SSL Error creating outgoing client context for Car: {e}")
            raise SystemExit("Failed to initialize outgoing Car SSL context.")
        except FileNotFoundError as e:
             self._log(logging.CRITICAL, f"Certificate file not found for outgoing Car context: {e}")
             raise SystemExit("Failed to initialize outgoing Car SSL context.")
        except Exception as e:
             self._log(logging.CRITICAL, f"Unexpected error creating outgoing Car SSL context: {e}")
             raise SystemExit("Failed to initialize outgoing Car SSL context.")

    def _log(self, level, msg, *args, **kwargs):
        """Helper for logging with car_id context."""
        self.logger_adapter.log(level, msg, *args, **kwargs)

    def _connect_to_backend(self):
        """Establishes a connection to the backend server."""

        if not self.outgoing_ssl_context:
            self._log(logging.ERROR, "Cannot connect to backend: Outgoing SSL context not initialized.")
            return None
        
        raw_sock = None
        ssl_sock = None
        address = self.backend_server_addr
        try:
            raw_sock = socket.create_connection(address, timeout=5.0)
            server_hostname = address[0] if self.outgoing_ssl_context.check_hostname else None
            # Use the outgoing context
            ssl_sock = self.outgoing_ssl_context.wrap_socket(raw_sock, server_hostname=server_hostname)
            self._log(logging.INFO, f"Secure TLS connection established to backend server {address}")
            return ssl_sock # Return the secure socket
        except socket.timeout:
            self._log(logging.ERROR, f"Connection to backend server {address} timed out.")
            if raw_sock: raw_sock.close()
            return None
        except socket.error as e:
            self._log(logging.ERROR, f"Socket error connecting to backend {address}: {e}")
            if raw_sock: raw_sock.close()
            return None
        except ssl.SSLError as e:
             self._log(logging.ERROR, f"SSL Error establishing connection to backend {address}: {e}")
             if ssl_sock: ssl_sock.close()
             elif raw_sock: raw_sock.close()
             return None
        except Exception as e:
             self._log(logging.ERROR, f"Unexpected error connecting to backend {address}: {e}")
             if ssl_sock: ssl_sock.close()
             elif raw_sock: raw_sock.close()
             return None

    def _validate_action_with_server(self, requesting_user_id: str, action: str) -> bool:
        """Asks the backend server if the user is allowed to perform the action."""
        self._log(logging.INFO, f"Validating action '{action}' for user '{requesting_user_id}' with backend server (using TLS).")
        backend_tls_sock = self._connect_to_backend()
        if not backend_tls_sock:
            self._log(logging.ERROR,"Failed to establish secure connection to backend for validation.")
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
            # --- Use the TLS socket ---
            if network_utils.send_message(backend_tls_sock, validation_request):
                backend_tls_sock.settimeout(5.0) # Set timeout on the TLS socket
                response = network_utils.receive_message(backend_tls_sock)
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
                     # Log error already happened in receive_message
                     self._log(logging.ERROR, "No valid response received from backend server during validation (TLS).")
            else:
                 # Log error already happened in send_message
                 self._log(logging.ERROR, "Failed to send validation request to backend server (TLS).")
        # --- Catch SSL errors during communication ---
        except ssl.SSLError as e:
             self._log(logging.ERROR, f"SSL error during validation communication with backend: {e}")
        except Exception as e:
             self._log(logging.ERROR, f"Error during validation communication with backend: {e}")
        finally:
            if backend_tls_sock:
                self._log(logging.DEBUG, f"Closing TLS connection to backend server after validation.")
                try:
                    backend_tls_sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                backend_tls_sock.close()

        return access_granted

    # --- Helper Method: Validate App Public Key with Backend ---
    def _validate_app_pubkey_with_server(self, app_certificate_pem_str: str, user_id: str) -> bool:
        """Contacts the backend server securely (TLS) to validate the app's public key PEM for the given user."""
        if not app_certificate_pem_str or not user_id: # MODIFIED check
            self._log(logging.ERROR, "App certificate PEM or User ID missing for validation call.")
            return False

        self._log(logging.INFO, f"Validating app certificate for user '{user_id}' with backend.")
        validation_message = {
            "type": "VALIDATE_APP_PUBKEY", # Type name kept, payload key changed
            "sender_id": self.car_id,
            "payload": {
                "user_id_to_validate": user_id,
                "app_certificate_pem": app_certificate_pem_str # MODIFIED payload key
            }
        }

        backend_tls_sock = None
        try:
            backend_tls_sock = self._connect_to_backend() # Connect securely
            if not backend_tls_sock:
                self._log(logging.ERROR,"Failed to connect to backend for app pubkey validation.")
                return False

            if network_utils.send_message(backend_tls_sock, validation_message):
                backend_tls_sock.settimeout(5.0)
                response = network_utils.receive_message(backend_tls_sock)
                if response and response.get("type") == "VALIDATE_APP_PUBKEY_ACK" and response.get("payload", {}).get("status") == "VALID":
                    self._log(logging.INFO, f"Backend validation SUCCESS for app certificate (User: {user_id}).")
                    return True
                else:
                    reason = response.get("payload", {}).get("reason", "Unknown") if response else "No response"
                    self._log(logging.WARNING, f"Backend validation FAILED for app public key (User: {user_id}): {reason}")
                    return False
            else:
                self._log(logging.ERROR,"Failed to send app pubkey validation request to backend.")
                return False
        # ... (keep exception handling: timeout, ssl error, generic error) ...
        # --- Catch SSL errors during communication ---
        except socket.timeout:
            self._log(logging.ERROR, f"Connection to backend server timed out.")
        except ssl.SSLError as e:
             self._log(logging.ERROR, f"SSL error during validation communication with backend: {e}")
        except Exception as e:
             self._log(logging.ERROR, f"Error during validation communication with backend: {e}")
        finally:
             if backend_tls_sock:
                 self._log(logging.DEBUG,"Closing backend connection after app pubkey validation.")
                 try: backend_tls_sock.shutdown(socket.SHUT_RDWR)
                 except OSError: pass
                 backend_tls_sock.close()
        return False # Default to false if any error path not returning explicitly


    def handle_client(self, ssl_client_socket: ssl.SSLSocket, address): # <-- Takes SSLSocket now
        threading.current_thread().name = f"App-{address[0]}:{address[1]}"
        self._log(logging.INFO, f"TLS connection established with {address}")

        # Extract full app certificate PEM
        app_certificate_pem_str = None

        try:
            app_cert_der = ssl_client_socket.getpeercert(binary_form=True)
            if not app_cert_der:
                 raise ValueError("Could not get peer certificate (app) in binary form.")
            
            app_cert_obj = x509.load_der_x509_certificate(app_cert_der, default_backend())
            # Serialize the *entire certificate* to PEM
            app_certificate_pem_str = app_cert_obj.public_bytes(
                 encoding=serialization.Encoding.PEM
            ).decode('utf-8')
            self._log(logging.INFO, f"App's full certificate PEM extracted for validation.")

        except (ValueError, TypeError, ssl.SSLError) as e:
             self._log(logging.ERROR, f"Failed to get or process app certificate from {address}: {e}. Closing connection.")
             try: ssl_client_socket.close()
             except Exception: pass
             return
        except Exception as e:
            self._log(logging.ERROR, f"Unexpected error getting app certificate from {address}: {e}. Closing connection.")
            try: ssl_client_socket.close()
            except Exception: pass
            return

        # --- Log Client Cert Info (Optional Debugging) ---
        try:
            client_cert = ssl_client_socket.getpeercert()
            if client_cert:
                 subject = dict(x[0] for x in client_cert.get('subject', []))
                 issuer = dict(x[0] for x in client_cert.get('issuer', []))
                 self._log(logging.DEBUG, f"Client Cert Subject: {subject}")
                 self._log(logging.DEBUG, f"Client Cert Issuer: {issuer}")
                 # You could potentially use subject CN or other fields for app-level checks
            else:
                 self._log(logging.WARNING, "Could not get peer certificate details.")
        except Exception as e:
             self._log(logging.WARNING, f"Error getting peer certificate: {e}")
        # -------------------------------------------------

        try:
            while True:
                # Use the SSL socket for communication
                message = network_utils.receive_message(ssl_client_socket)
                if message is None:
                    break

                # Pass full app_certificate_pem_str
                response = self.process_message(message, app_certificate_pem_str, ssl_client_socket)
                
                if response:
                    # Send response over the SSL socket
                    if not network_utils.send_message(ssl_client_socket, response):
                         self._log(logging.WARNING, f"Failed to send response to {address}. Closing TLS connection.")
                         break
        except ConnectionResetError:
             self._log(logging.INFO, f"Connection reset by peer {address}")
        except ssl.SSLError as e:
            self._log(logging.ERROR, f"SSL Error during communication with {address}: {e}")
        except Exception as e:
            self._log(logging.ERROR, f"Error handling client {address}: {e}")
        finally:
            self._log(logging.INFO, f"Closing TLS connection from {address}")
            try:
                ssl_client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass # Ignore if already closed
            ssl_client_socket.close()

    def process_message(self, message: dict, app_certificate_pem_str: str, ssl_sock: ssl.SSLSocket) -> dict | None:        
        msg_type = message.get('type')
        # This is the user interacting with the car via the app
        requesting_user_id = message.get('sender_id')        
        payload = message.get('payload', {}) # Use if needed
        response = {"sender_id": self.car_id} # Initialize response
        # TODO (AUTH): Extract signature/auth_data from payload.
        #   auth_data = payload.get('auth_data') # Could be signature or signed nonce
        if not msg_type or not requesting_user_id:
            self._log(logging.WARNING, f"Received incomplete message: {message}")
            return {"type": "ERROR", "sender_id": self.car_id, "payload": {"error": "Incomplete message (missing type or sender_id)"}}

        self._log(logging.INFO, f"Processing message type '{msg_type}' from user '{requesting_user_id}'")

        # ---=== Step 1: Validate App Public Key against User ID ===---
        # Validate app's full certificate PEM
        if not self._validate_app_pubkey_with_server(app_certificate_pem_str, requesting_user_id):
             self._log(logging.WARNING, f"Authentication failed for user '{requesting_user_id}' due to app certificate mismatch.")
             nak_type = "ERROR"
             if msg_type.endswith("_REQUEST"): nak_type = msg_type.replace("_REQUEST", "_NAK")
             return {"type": nak_type, "sender_id": self.car_id, "payload": {"error": "Authentication failed (certificate validation)"}} # More specific error
        # ---=== Validation Successful ===---


        # --- Step 2: Proceed with message processing (permission checks, etc.) ---
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
        action_requires_direct_auth = msg_type in ["UNLOCK_REQUEST", "START_REQUEST", "LOCK_REQUEST", "STOP_CAR_REQUEST"]

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
                response.update({"type": "UNLOCK_ACK", "payload": {"status": "Unlocked"}})
                self._log(logging.INFO, f"Car unlocked by {requesting_user_id} (Validation OK)")
            else:
                 response.update({"type": "UNLOCK_NAK", "payload": {"error": "Access denied by server or validation failed"}})
                 self._log(logging.WARNING, f"Unlock failed for {requesting_user_id} (Validation Failed)")

        elif msg_type == "START_REQUEST":
            action_to_validate = config.PERMISSION_START
            original_starter = self.started_by_user_id
            if requesting_user_id != original_starter and self.is_started:
                    response.update({"type": "START_NAK", "payload": {"error": "Car has already been started by " + original_starter}})
                    self._log(logging.WARNING, f"Start failed for {requesting_user_id} (Car already started by other user)")
            # elif not self.is_unlocked:
            #      response.update({"type": "START_NAK", "payload": {"error": "Car is locked"}})
            #      self._log(logging.WARNING, f"Start failed for {requesting_user_id} (Car locked)")
            elif self._validate_action_with_server(requesting_user_id, action_to_validate):
                 self.is_started = True
                 # --- Store the user who started the car ---
                 self.started_by_user_id = requesting_user_id
                 # ------------------------------------------
                 
                 response.update({"type": "START_ACK", "payload": {"status": "Started"}})
                 self._log(logging.INFO, f"Car started by {self.started_by_user_id} (Validation OK)")
            else:
                 response.update({"type": "START_NAK", "payload": {"error": "Access denied by server or validation failed"}})
                 self._log(logging.WARNING, f"Start failed for {requesting_user_id} (Validation Failed)")

        elif msg_type == "LOCK_REQUEST":
             action_to_validate = config.PERMISSION_UNLOCK # Require unlock permission to lock
             if self._validate_action_with_server(requesting_user_id, action_to_validate):
                 self.is_unlocked = False
                 response.update({"type": "LOCK_ACK", "payload": {"status": "Locked"}})
                 log_msg = f"Car locked by {requesting_user_id} (Validation OK)."
                 original_starter = self.started_by_user_id
                 if original_starter:
                     log_msg += f" Car was previously started by {original_starter}."
                 self._log(logging.INFO, log_msg)
             else:
                  response.update({"type": "LOCK_NAK", "payload": {"error": "Access denied for locking (validation failed)"}})
                  self._log(logging.WARNING, f"Lock failed for {requesting_user_id} (Validation Failed)")

        elif msg_type == "STOP_CAR_REQUEST":
            if not self.is_started:
                # Condition 1: Car must be started
                response.update({"type": "STOP_CAR_NAK", "payload": {"error": "Car is not started"}})
                self._log(logging.WARNING, f"Stop car request failed for {requesting_user_id}: Car not started.")
            elif self.started_by_user_id != requesting_user_id:
                # Condition 2: Requester must be the one who started it
                response.update({"type": "STOP_CAR_NAK", "payload": {"error": f"Action denied. Car was started by '{self.started_by_user_id}'."}})
                self._log(logging.WARNING, f"Stop car request denied for {requesting_user_id}. Car started by {self.started_by_user_id}.")
            else:
                # Conditions met: Stop the car
                self.is_started = False
                stopped_by = self.started_by_user_id # Store temporarily for logging
                self.started_by_user_id = None # Reset the starter ID
                response.update({"type": "STOP_CAR_ACK", "payload": {"status": "Stopped"}})
                self._log(logging.INFO, f"Car stopped by {stopped_by}.")


        # --- Simple Hello/Ping (doesn't need validation) ---
        elif msg_type == "HELLO":
             response.update({"type": "HELLO_ACK", "payload": {"car_id": self.car_id, "status": "Ready"}})


        # --- Unknown ---
        else:
            self._log(logging.WARNING, f"Received unknown message type '{msg_type}' from {requesting_user_id}")
            response.update({"type": "ERROR", "payload": {"error": f"Unknown message type: {msg_type}"}})

        return response

    def start(self):
        # Check both contexts now
        if not self.incoming_ssl_context or not self.outgoing_ssl_context:
            self._log(logging.CRITICAL, "Cannot start car server without valid SSL contexts.")
            return

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self._log(logging.INFO, f"Car server listening securely (TLS) on {self.host}:{self.port}")

            while True:
                 try:
                    client_socket, address = self.server_socket.accept()
                    self._log(logging.INFO, f"Incoming connection attempt from {address}")
                    # --- Wrap socket with SSL Context ---
                    try:
                        ssl_sock = self.incoming_ssl_context.wrap_socket(client_socket, server_side=True)
                        self._log(logging.DEBUG, f"SSL handshake initiated with {address}")
                        # Handshake happens implicitly here or on first read/write
                        # You could explicitly call ssl_sock.do_handshake() if needed, but it's often automatic.

                        # Pass the secure socket to the handler thread
                        client_thread = threading.Thread(target=self.handle_client, args=(ssl_sock, address), daemon=True)
                        client_thread.name = f"Handler-{address[0]}:{address[1]}"
                        client_thread.start()
                    except ssl.SSLError as e:
                         self._log(logging.ERROR, f"Car SSL Handshake failed with {address}: {e}. Closing raw socket.")
                         client_socket.close()
                    except Exception as e:
                        self._log(logging.ERROR, f"Error wrapping socket or starting thread for {address}: {e}")
                        client_socket.close()

                 except KeyboardInterrupt:
                     self._log(logging.INFO, "Shutdown signal received.")
                     break
                 except Exception as e:
                    self._log(logging.ERROR, f"Error accepting connection: {e}")

        except socket.error as e:
            self._log(logging.CRITICAL, f"Could not start server on {self.host}:{self.port}. Error: {e}")
        finally:
            self._log(logging.INFO, "Shutting down server...")
            self.server_socket.close()
            self._log(logging.INFO, "Server socket closed.")


if __name__ == "__main__":
    # Should get this from config/secure storage in a real car
    car_id = os.environ.get("CAR_ID", "CAR_VIN_DEMO_789")
    # Corrected CA file in car_server.py based on general structure
    # Ensuring car_server uses CA_CHAIN_FILE for verifying app client certs and backend server certs
    # This was done in _create_incoming_ssl_context and _create_outgoing_ssl_context
    car = CarServer(car_id, config.CAR_IP, config.CAR_PORT)
    car.start()