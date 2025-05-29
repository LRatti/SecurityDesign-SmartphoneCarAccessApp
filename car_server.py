# car/car_server.py
import socket
import threading
import logging
import ssl
import time
import json # Import json for reconstructing signed data
from utils import config, network_utils, crypto
import os
# --- Need cryptography for parsing cert and serializing key ---
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec # For type hinting public key

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - CarServer [{car_id}] - %(threadName)s - %(levelname)s - %(message)s')

class CarServer:
    def __init__(self, car_id, host, port):
        self.car_id = car_id
        self.host = host
        self.port = port
        self.car_private_key = None # Assuming car also has a key for signing its own messages if needed
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.is_unlocked = False
        self.is_started = False
        self.started_by_user_id = None  # Track who started the car
        self.backend_server_addr = (config.SERVER_IP, config.SERVER_PORT)
        # Inject car_id into logger extra context for formatting
        self.logger = logging.getLogger(__name__)
        self.logger_adapter = logging.LoggerAdapter(self.logger, {'car_id': self.car_id})

        self.app_public_key_cache = {}
        self.app_key_cache_lock = threading.Lock()

        # --- TLS Setup ---
        # Context for incoming connections from AppClient
        self.incoming_ssl_context = self._create_incoming_ssl_context() # Renamed
        # NEW: Context for outgoing connections to BackendServer
        self.outgoing_ssl_context = self._create_outgoing_ssl_context()

        self.user_sequence_numbers = {}
        self.sequence_lock = threading.Lock() # Lock for accessing user_sequence_numbers

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

    def handle_client(self, ssl_client_socket: ssl.SSLSocket, address):
        threading.current_thread().name = f"App-{address[0]}:{address[1]}"
        self._log(logging.INFO, f"TLS connection established with {address}")

        app_public_key: ec.EllipticCurvePublicKey | None = None
        app_cert_cn: str | None = None  # Common Name from app's cert
        app_full_cert_pem_for_backend_validation: str | None = None  # For backend validation

        try:
            # --- Extract App's Public Key and CN from Client Certificate ---
            app_cert_der = ssl_client_socket.getpeercert(binary_form=True)
            if not app_cert_der:
                raise ValueError("Could not get app certificate (DER) from TLS session.")

            app_cert_obj = x509.load_der_x509_certificate(app_cert_der, default_backend())
            app_full_cert_pem_for_backend_validation = app_cert_obj.public_bytes(serialization.Encoding.PEM).decode(
                'utf-8')

            # Extract CN
            try:
                app_cert_cn = app_cert_obj.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
                self._log(logging.INFO, f"App client certificate CN: {app_cert_cn}")
            except IndexError:
                self._log(logging.WARNING, "App client certificate is missing Common Name (CN).")
                # Depending on policy, might reject here or rely on backend validation later

            # Extract Public Key object
            app_public_key = app_cert_obj.public_key()
            if not isinstance(app_public_key, ec.EllipticCurvePublicKey):  # Check type
                raise ValueError("App client certificate public key is not ECC type as expected.")

            # Optional: Cache the public key associated with the CN
            if app_cert_cn and app_public_key:
                with self.app_key_cache_lock:
                    self.app_public_key_cache[app_cert_cn] = app_public_key
                self._log(logging.DEBUG, f"Cached public key for app cert CN: {app_cert_cn}")

        except (ValueError, TypeError, ssl.SSLError) as e:
            self._log(logging.ERROR, f"Failed to get/process app certificate from {address}: {e}. Closing connection.")
            try:
                ssl_client_socket.close(); return
            except Exception:
                pass
        except Exception as e:  # Catch-all for unexpected
            self._log(logging.ERROR,
                      f"Unexpected error getting app certificate from {address}: {e}. Closing connection.")
            try:
                ssl_client_socket.close(); return
            except Exception:
                pass
        first_message_for_validation = network_utils.receive_message(ssl_client_socket)
        if not first_message_for_validation:
            self._log(logging.WARNING, f"No initial message received from {address} after TLS handshake. Closing.")
            ssl_client_socket.close()
            return

        requesting_user_id_from_first_msg = first_message_for_validation.get('sender_id')
        if not requesting_user_id_from_first_msg:
            self._log(logging.ERROR, f"Initial message from {address} missing 'sender_id'. Closing.")
            # Send an error back if possible, then close
            err_resp = {"type": "ERROR", "sender_id": self.car_id,
                        "payload": {"error": "Initial message requires sender_id"}}
            network_utils.send_message(ssl_client_socket, err_resp)
            ssl_client_socket.close()
            return

        # Now validate the presented app certificate against this sender_id with the backend
        if not self._validate_app_pubkey_with_server(app_full_cert_pem_for_backend_validation,
                                                     requesting_user_id_from_first_msg):
            self._log(logging.WARNING,
                      f"Backend validation of app cert failed for user '{requesting_user_id_from_first_msg}' (CN: {app_cert_cn}). Closing connection.")
            err_resp = {"type": "ERROR", "sender_id": self.car_id,
                        "payload": {"error": "App certificate not valid for specified user."}}
            network_utils.send_message(ssl_client_socket, err_resp)
            ssl_client_socket.close()
            return
        self._log(logging.INFO,
                  f"Backend validation of app cert for user '{requesting_user_id_from_first_msg}' (CN: {app_cert_cn}) successful.")

        # Process the first message, then loop for more
        try:
            # Pass the extracted app_public_key to process_message
            response = self.process_message(first_message_for_validation, app_public_key, app_cert_cn,
                                            ssl_client_socket)
            if response:
                if not network_utils.send_message(ssl_client_socket, response):
                    self._log(logging.WARNING, f"Failed to send response (1) to {address}.")
                    # Don't break yet, might be a one-off send issue

            while True:
                message = network_utils.receive_message(ssl_client_socket)
                if message is None:
                    break  # Connection closed or error in receive_message

                response = self.process_message(message, app_public_key, app_cert_cn, ssl_client_socket)
                if response:
                    if not network_utils.send_message(ssl_client_socket, response):
                        self._log(logging.WARNING, f"Failed to send response to {address}. Closing TLS connection.")
                        break
        # ... (rest of handle_client: except blocks, finally block to close socket) ...
        except ConnectionResetError:
            self._log(logging.INFO, f"Connection reset by peer {address}")
        except ssl.SSLError as e:
            self._log(logging.ERROR, f"SSL Error during communication with {address}: {e}")
        except Exception as e:
            self._log(logging.ERROR, f"Error handling client {address}: {e}", exc_info=True)
        finally:
            self._log(logging.INFO, f"Closing TLS connection from {address}")
            # Clean up cached key for this specific CN if it was a short-lived session concept
            if app_cert_cn:
                with self.app_key_cache_lock:
                    self.app_public_key_cache.pop(app_cert_cn, None)
            try:
                ssl_client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            ssl_client_socket.close()

    def process_message(self, message: dict, app_public_key: ec.EllipticCurvePublicKey | None, app_cert_cn: str | None, ssl_sock: ssl.SSLSocket) -> dict | None:
        msg_type = message.get('type')
        requesting_user_id = message.get('sender_id') # This is user_id from payload
        payload = message.get('payload', {})
        response = {"sender_id": self.car_id}
        if not msg_type or not requesting_user_id:
            # ... (incomplete message handling) ...
            return {"type": "ERROR", "sender_id": self.car_id, "payload": {"error": "Incomplete message"}}
        self._log(logging.INFO, f"Processing message type '{msg_type}' from user '{requesting_user_id}' (App Cert CN: {app_cert_cn})")

        if app_cert_cn != requesting_user_id:
            self._log(logging.WARNING, f"SECURITY ALERT: Payload sender_id '{requesting_user_id}' MISMATCHES authenticated TLS CN '{app_cert_cn}'. Rejecting.")
            nak_type = msg_type.replace("_REQUEST", "_NAK") if msg_type.endswith("_REQUEST") else "ERROR"
            return {"type": nak_type, "sender_id": self.car_id, "payload": {"error": "Identity mismatch (payload vs TLS cert)"}}
        # --- Replay Protection & Signature Verification ---
        action_requests_needing_replay_protection = [
            "UNLOCK_REQUEST", "START_REQUEST", "LOCK_REQUEST", "STOP_CAR_REQUEST"
        ]

        if msg_type in action_requests_needing_replay_protection:
            timestamp = payload.get("timestamp")
            sequence_number = payload.get("sequence_number")
            auth_data_dict = payload.get("auth_data")

            if timestamp is None or sequence_number is None or auth_data_dict is None or "signature" not in auth_data_dict:
                # ... (return error: Missing replay/auth fields) ...
                self._log(logging.WARNING, f"Missing replay/auth fields for {msg_type} from {requesting_user_id}")
                return {"type": msg_type.replace("_REQUEST", "_NAK"), "sender_id": self.car_id,
                        "payload": {"error": "Missing replay or auth fields"}}


            # --- 1.1: Verify Signature ---
            auth_data_dict = payload.get("auth_data")
            signature_hex = auth_data_dict.get("signature")
            if not app_public_key:  # Should have been extracted in handle_client
                self._log(logging.ERROR,
                          f"CRITICAL: App public key not available for signature verification for user {requesting_user_id}.")
                return {"type": msg_type.replace("_REQUEST", "_NAK"), "sender_id": self.car_id,
                        "payload": {"error": "Internal error: cannot verify signature (no key)"}}

            data_that_was_signed_dict = {
                "action": msg_type,
                "user_id": requesting_user_id,
                "car_id": self.car_id,
                "timestamp": timestamp,
                "sequence_number": sequence_number
            }
            data_that_was_signed_bytes = json.dumps(data_that_was_signed_dict, sort_keys=True,
                                                    separators=(',', ':')).encode('utf-8')

            try:
                signature_bytes = bytes.fromhex(signature_hex)
                is_signature_valid = crypto.verify_signature(app_public_key, signature_bytes,
                                                             data_that_was_signed_bytes)
            except ValueError:  # fromhex error
                is_signature_valid = False
                self._log(logging.WARNING, f"Invalid signature hex format for {msg_type} from {requesting_user_id}.")
            except Exception as e:  # Catch other crypto errors
                is_signature_valid = False
                self._log(logging.ERROR,
                          f"Error during signature verification for {msg_type} from {requesting_user_id}: {e}")

            if not is_signature_valid:
                self._log(logging.WARNING, f"SIGNATURE VERIFICATION FAILED for {msg_type} from {requesting_user_id}.")
                # DO NOT update sequence number here, as it might be an attacker trying to burn sequence numbers.
                return {"type": msg_type.replace("_REQUEST", "_NAK"), "sender_id": self.car_id,
                        "payload": {"error": "Invalid signature on command"}}

            self._log(logging.INFO, f"SIGNATURE OK for {msg_type} from {requesting_user_id}.")
            # 1.2 Validate timestamp only if signature is valid
            current_server_time = int(time.time())
            if abs(current_server_time - timestamp) > config.TIMESTAMP_WINDOW_SECONDS:
                self._log(logging.WARNING, f"REPLAY DETECTED (Timestamp) for {msg_type} from {requesting_user_id}")
                return {"type": msg_type.replace("_REQUEST", "_NAK"), "sender_id": self.car_id,
                        "payload": {"error": "Replay detected (invalid timestamp)"}}

            # 1.3 Validate Sequence Number - only if signature is valid
            with self.sequence_lock:
                last_seen_sequence = self.user_sequence_numbers.get(requesting_user_id, -1)
                if sequence_number <= last_seen_sequence:
                    self._log(logging.WARNING,
                              f"REPLAY DETECTED (Sequence after Sig OK): {msg_type} from {requesting_user_id}. Recv: {sequence_number}, Last: {last_seen_sequence}")
                    return {"type": msg_type.replace("_REQUEST", "_NAK"), "sender_id": self.car_id,
                            "payload": {"error": "Replay detected (invalid sequence number)"}}
                self.user_sequence_numbers[requesting_user_id] = sequence_number
                self._log(logging.DEBUG,
                          f"REPLAY CHECK: Valid sequence number {sequence_number} for user {requesting_user_id}. Updated last seen.")

            self._log(logging.INFO,
                      f"ALL CHECKS OK (Timestamp/SeqNo/Signature) for {msg_type} from {requesting_user_id}.")
        # --- Step 2: Proceed with message processing (permission checks, etc.) ---
        # --- Car Actions (require validation AND direct app auth) ---
        action_requires_direct_auth = msg_type in ["UNLOCK_REQUEST", "START_REQUEST", "LOCK_REQUEST", "STOP_CAR_REQUEST"]

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