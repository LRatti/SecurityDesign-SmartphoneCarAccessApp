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
import hmac # <-- Add hmac for secure comparison
from datetime import datetime, timedelta # For cert validity
from cryptography import x509 # <-- Add cryptography
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import hashes as crypto_hashes # <-- Add cryptography hashes
from cryptography.hazmat.backends import default_backend # <-- Add cryptography backend
from cryptography.hazmat.primitives import serialization
from utils import config, network_utils 

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - Server - %(threadName)s - %(levelname)s - %(message)s')

# --- Hashing constants ---
SALT_BYTES = 16
HASH_ALGORITHM = 'sha256'

# Global CA cert/key storage (Load once)
CA_CERT = None
CA_KEY = None

def load_ca_credentials():
    global CA_CERT, CA_KEY
    if CA_CERT and CA_KEY:
        return True
    try:
        logging.info(f"Loading Intermediate CA Certificate from: {config.INTERMEDIATE_CA_CERT_FILE}")
        with open(config.INTERMEDIATE_CA_CERT_FILE, "rb") as f:
            int_ca_cert_pem = f.read()
        CA_CERT = x509.load_pem_x509_certificate(int_ca_cert_pem, default_backend())

        logging.info(f"Loading Intermediate CA Private Key from: {config.INTERMEDIATE_CA_KEY_FILE}")
        with open(config.INTERMEDIATE_CA_KEY_FILE, "rb") as f:
            int_ca_key_pem = f.read()
        # IMPORTANT: Provide password=None if key is not encrypted
        CA_KEY = serialization.load_pem_private_key(int_ca_key_pem, password=None, backend=default_backend())
        logging.info("CA Certificate and Key loaded successfully.")
        return True
    except FileNotFoundError as e:
        logging.critical(f"CA certificate or key file not found: {e}")
        return False
    except Exception as e:
        logging.critical(f"Failed to load CA credentials: {e}")
        return False

class BackendServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Data Stores (in-memory caches, loaded from files)
        self.users = {} # user_id -> { 'certificate_fingerprint_sha256': '...', 'license_valid': True }
        self.cars = {} # car_id -> { 'owner_user_id': '...', 'certificate_fingerprint_sha256': '...', 'model': '...' }
        self.delegations = {} # delegation_id -> { 'car_id': ..., 'owner_user_id': ..., 'recipient_user_id': ..., 'permissions': [...], 'expiry_timestamp': ..., 'status': 'active'/'revoked'/'expired' }

        # Locks for thread safety when accessing shared data
        self.user_lock = threading.Lock()
        self.car_lock = threading.Lock()
        self.delegation_lock = threading.Lock()

        # --- TLS Setup for Backend Server ---
        self.server_ssl_context = self._create_server_ssl_context()

        # Load initial data
        self.load_data()

        # Load CA credentials needed for signing
        if not load_ca_credentials():
            raise SystemExit("Cannot start server without CA credentials.")

     # --- Hashing Helper Functions ---
    def _generate_salt(self) -> bytes:
        return os.urandom(SALT_BYTES)

    def _hash_pin(self, pin: str, salt: bytes) -> str:
        """Hashes the PIN with the given salt."""
        if not isinstance(pin, str): pin = str(pin) # Ensure pin is string
        hasher = hashlib.new(HASH_ALGORITHM)
        hasher.update(salt)
        hasher.update(pin.encode('utf-8'))
        return hasher.hexdigest()

    def _verify_pin(self, user_id: str, provided_pin: str) -> bool:
        """Verifies the provided PIN against the stored hash for the user."""
        with self.user_lock:
            user_data = self.users.get(user_id)

        if not user_data or 'pin_salt' not in user_data or 'pin_hash' not in user_data:
            logging.warning(f"PIN verification attempt for non-existent or incomplete user: {user_id}")
            return False

        try:
            salt = bytes.fromhex(user_data['pin_salt'])
            stored_hash = user_data['pin_hash']
            provided_hash = self._hash_pin(provided_pin, salt)

            # Use hmac.compare_digest for timing-attack resistance
            return hmac.compare_digest(stored_hash, provided_hash)
        except (ValueError, TypeError) as e:
            logging.error(f"Error during PIN verification for {user_id}: {e}")
            return False

     # --- Create Backend Server SSL Context ---
    def _create_server_ssl_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            logging.info(f"Loading SERVER cert chain: {config.SERVER_CERT_FILE}, {config.SERVER_KEY_FILE}")
            context.load_cert_chain(certfile=config.SERVER_CERT_FILE, keyfile=config.SERVER_KEY_FILE)
            
            logging.info(f"Loading CA chain for client (app) verification: {config.CA_CHAIN_FILE}")
            # Require client certificate and verify it against our CA chain (Intermediate + Root)
            context.load_verify_locations(cafile=config.CA_CHAIN_FILE)
            # CERT_REQUIRED ensures *some* valid client cert is presented
            context.verify_mode = ssl.CERT_REQUIRED # Require app client cert

            # Optional: Set specific TLS versions or cipher suites
            context.minimum_version = ssl.TLSVersion.TLSv1_3

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

        # --- Get Peer Certificate Info ---
        client_cert_details = None
        client_cn = None
        client_public_key_pem = None # Store extracted key for potential use (less needed now)
        is_provisioning_cert = False # Flag if the generic cert was used
        client_cert_der_for_processing = None # For passing to process_message

        # --- Log Client Cert Info ---
        try:
            client_cert_der = ssl_client_socket.getpeercert(binary_form=True) # Get DER form
            if client_cert_der:
                client_cert_der_for_processing = client_cert_der # Store for process_message
                client_cert_obj = x509.load_der_x509_certificate(client_cert_der, default_backend())
                
                subject_dict = {attr.oid._name: attr.value for attr in client_cert_obj.subject}
                client_cn = subject_dict.get('commonName')
                logging.debug(f"App Client Cert Subject: {subject_dict}")

                # Public key extraction (might be useful for other things, not directly for new login)
                public_key = client_cert_obj.public_key()
                client_public_key_pem = public_key.public_bytes(
                     encoding=serialization.Encoding.PEM,
                     format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                logging.debug(f"Extracted App Client public key PEM from cert.")

                # Check if it's the generic provisioning cert based on its CN
                # Load the provisioning cert CN once for comparison
                # This is a bit hacky; fingerprint comparison would be better
                try:
                    with open(config.PROVISIONING_APP_CERT_FILE, 'rb') as f:
                        prov_cert_pem = f.read()
                    prov_cert = x509.load_pem_x509_certificate(prov_cert_pem, default_backend())
                    prov_cn = prov_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    if client_cn == prov_cn:
                        is_provisioning_cert = True
                        logging.info(f"Connection from {address} is using the generic provisioning certificate.")
                except Exception as cert_load_err:
                    logging.error(f"Failed to load provisioning cert for CN check: {cert_load_err}")

            else: # Fallback to getpeercert() if binary_form fails or not available
                client_cert_details = ssl_client_socket.getpeercert()
                if client_cert_details:
                    subject_dict_fallback = dict(x[0] for x in client_cert_details.get('subject', []))
                    client_cn = subject_dict_fallback.get('commonName')

            # Extract public key PEM (might still be useful for logging/debugging)
            # client_cert_der = ssl_client_socket.getpeercert(binary_form=True)
            # if client_cert_der:
            #      client_cert_obj = x509.load_der_x509_certificate(client_cert_der, default_backend())
            #      public_key = client_cert_obj.public_key()
            #      client_public_key_pem = public_key.public_bytes(
            #          encoding=serialization.Encoding.PEM,
            #          format=serialization.PublicFormat.SubjectPublicKeyInfo
            #      ).decode('utf-8')
            #      logging.debug(f"Extracted App Client public key PEM from cert.")

        except Exception as e:
             logging.warning(f"Error getting/processing peer certificate from App Client {address}: {e}")
        # --- End Cert Info ---

        try:
            while True:
                # Use the SSL socket for communication
                message = network_utils.receive_message(ssl_client_socket)
                if message is None:
                    break # Error or connection closed gracefully

                # Pass client CN and provisioning flag for context
                response = self.process_message(message, client_cn, is_provisioning_cert, client_public_key_pem, client_cert_der_for_processing)                
                
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

    def process_message(self, message: dict, client_cn: str | None, is_provisioning_connection: bool, client_cert_pubkey_pem: str | None, client_cert_der: bytes | None) -> dict | None:        
        """Processes incoming messages and returns a response dictionary or None."""
        msg_type = message.get('type')
        sender_id_payload = message.get('sender_id') # User ID provided in payload (for some messages)
        payload = message.get('payload', {})
        response = {"sender_id": "server"}


        # TODO (AUTH): Extract signature from message if present (e.g., signature = message.get('signature'))

        if not msg_type: # sender_id might be implicit for some server internal actions if needed
            logging.warning(f"Received message with missing type: {message}")
            return {"type": "ERROR", "sender_id": "server", "payload": {"error": "Missing message type"}}

        logging.info(f"Processing message type '{msg_type}' (Payload keys: {list(payload.keys())})")

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

        # --- Message Routing based on Type and Connection Context ---
        
        # --- User Signup ---
        if msg_type == "SIGNUP":
            
            if not is_provisioning_connection:
                logging.warning(f"Rejecting SIGNUP from non-provisioning connection (CN: {client_cn})")
                return {"type": "SIGNUP_NAK", "payload": {"error": "Signup only allowed during initial provisioning"}}
            
            user_id = payload.get('user_id')
            pin = payload.get('pin')
            csr_pem_str = payload.get('csr_pem')
        
            if not user_id or not pin or not csr_pem_str:
                return {"type": "SIGNUP_NAK", "payload": {"error": "Missing user_id, pin, or csr_pem"}}

            if not isinstance(pin, str) or not pin.isdigit() or len(pin) != 4:
                 return {"type": "SIGNUP_NAK", "payload": {"error": "PIN must be a 4-digit number"}}

            # --- Parse CSR ---
            try:
                csr_pem = csr_pem_str.encode('utf-8')
                csr = x509.load_pem_x509_csr(csr_pem, default_backend())

                # --- Verify CSR Signature ---
                if not csr.is_signature_valid:
                    logging.warning(f"CSR signature validation failed for user '{user_id}'.")
                    return {"type": "SIGNUP_NAK", "payload": {"error": "Invalid CSR signature"}}

                # Extract Public Key and Subject CN from CSR
                csr_public_key = csr.public_key()
                csr_subject = csr.subject
                try:
                    # Ensure CN matches the user_id payload
                    csr_cn = csr_subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    if csr_cn != user_id:
                         logging.warning(f"CSR CN '{csr_cn}' does not match payload user_id '{user_id}'.")
                         return {"type": "SIGNUP_NAK", "payload": {"error": "CSR common name mismatch"}}
                except IndexError:
                     logging.warning(f"CSR for user '{user_id}' is missing Common Name.")
                     return {"type": "SIGNUP_NAK", "payload": {"error": "CSR missing common name"}}

            except Exception as e:
                logging.error(f"Failed to parse CSR for user '{user_id}': {e}")
                return {"type": "SIGNUP_NAK", "payload": {"error": "Invalid CSR format"}}

            with self.user_lock:
                if user_id in self.users:
                    return {"type": "SIGNUP_NAK", "payload": {"error": "User ID already exists"}}
                else:
                    # --- Sign the Certificate ---
                    if not CA_CERT or not CA_KEY: # Should have been checked at startup
                         logging.critical("CA credentials not loaded, cannot sign certificate.")
                         return {"type": "SIGNUP_NAK", "payload": {"error": "Server internal error: CA unavailable"}}
                    try:
                        builder = x509.CertificateBuilder()
                        builder = builder.subject_name(csr_subject) # Use subject from CSR
                        builder = builder.issuer_name(CA_CERT.subject) # Issuer is CA
                        builder = builder.public_key(csr_public_key) # Public key from CSR
                        builder = builder.serial_number(x509.random_serial_number()) # Unique serial
                        builder = builder.not_valid_before(datetime.utcnow())
                        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365)) # 1 year validity

                        # Add extensions from CSR if needed (e.g., Key Usage)
                        # for ext in csr.extensions: builder = builder.add_extension(ext.value, critical=ext.critical)
                        # Or add default extensions:
                        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                        builder = builder.add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, data_encipherment=False, key_agreement=False, content_commitment=True, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)


                        new_certificate = builder.sign(CA_KEY, crypto_hashes.SHA256(), default_backend())
                        new_certificate_pem_str = new_certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                        logging.info(f"Successfully signed certificate for user '{user_id}'.")
                        user_cert_fingerprint = self._calculate_fingerprint_from_pem(new_certificate_pem_str)
                        if not user_cert_fingerprint:
                            logging.error(f"Failed to calculate fingerprint for newly signed cert for user '{user_id}'.")
                            return {"type": "SIGNUP_NAK", "payload": {"error": "Server internal error: Cert processing failed"}}
                    except Exception as e:
                        logging.error(f"Failed to sign certificate for user '{user_id}': {e}")
                        return {"type": "SIGNUP_NAK", "payload": {"error": "Server internal error: Certificate signing failed"}}
                    
                    # --- Store User Data ---
                    salt = self._generate_salt()
                    pin_hash = self._hash_pin(pin, salt)
                    self.users[user_id] = {
                        'certificate_fingerprint_sha256': user_cert_fingerprint,  # Store user's certificate fingerprint
                        'pin_salt': salt.hex(), # Store salt as hex string
                        'pin_hash': pin_hash,
                        'license_valid': True # Default license to valid on signup
                    }
                    users_copy = self.users.copy() # Make copy inside lock

            # Save outside lock
            self._save_json(config.REGISTRATION_FILE, users_copy, "user registrations")
            logging.info(f"User '{user_id}' signed up successfully. Stored cert fingerprint.")
            response.update({
                "type": "SIGNUP_ACK",
                "payload": {"status": "OK", "user_id": user_id, "certificate_pem": new_certificate_pem_str}
            })

            # --- Send ACK with Certificate ---
            # response.update({
            #     "type": "SIGNUP_ACK",
            #     "payload": {
            #         "status": "OK",
            #         "user_id": user_id,
            #         "certificate_pem": new_certificate_pem.decode('utf-8') # Send back the signed cert
            #     }
            # })

        # --- User Login ---
        elif msg_type == "LOGIN":
            if is_provisioning_connection:
                logging.warning(f"Rejecting LOGIN from provisioning connection.")
                return {"type": "LOGIN_NAK", "payload": {"error": "Login requires user-specific certificate"}}
            
            user_id = payload.get('user_id')
            pin = payload.get('pin')

            if not user_id or not pin:
                return {"type": "LOGIN_NAK", "payload": {"error": "Missing user_id or pin"}}

            if not isinstance(pin, str) or not pin.isdigit() or len(pin) != 4:
                 return {"type": "LOGIN_NAK", "payload": {"error": "PIN must be a 4-digit number"}}

            # --- Verify TLS Certificate CN matches Payload User ID ---
            if client_cn != user_id:
                 logging.warning(f"Login attempt failed: TLS CN '{client_cn}' does not match payload user ID '{user_id}'.")
                 return {"type": "LOGIN_NAK", "payload": {"error": "Certificate identity mismatch"}}
            
            if client_cert_der:
                presented_cert_fingerprint = hashlib.sha256(client_cert_der).hexdigest()
                with self.user_lock:
                    user_data = self.users.get(user_id)
                stored_fingerprint = user_data.get('certificate_fingerprint_sha256') if user_data else None

                if not user_data: # Check if user exists first
                    logging.warning(f"Login failed: User '{user_id}' not found.")
                    return {"type": "LOGIN_NAK", "payload": {"error": "Invalid user ID or PIN"}}

                if not stored_fingerprint or not hmac.compare_digest(presented_cert_fingerprint, stored_fingerprint):
                    logging.warning(f"Login failed for user '{user_id}': Presented certificate fingerprint mismatch.")
                    # For debugging:
                    presented_fp_short = presented_cert_fingerprint[:10] if presented_cert_fingerprint else "N/A"
                    stored_fp_short = stored_fingerprint[:10] if stored_fingerprint else "N/A"
                    logging.debug(f"Presented FP (DER hash): {presented_fp_short}..., Stored FP: {stored_fp_short}...")
                    return {"type": "LOGIN_NAK", "payload": {"error": "Invalid user ID or PIN"}} # Keep error generic
                logging.info(f"Certificate fingerprint validated successfully for user '{user_id}'")
            else:
                logging.error(f"Login attempt for user '{user_id}' but client certificate DER not available.")
                return {"type": "LOGIN_NAK", "payload": {"error": "Client certificate error"}}
            
            if self._verify_pin(user_id, pin):
                logging.info(f"User '{user_id}' logged in successfully.")
                # Optionally fetch license status to send back
                with self.user_lock:
                    license_valid = self.users.get(user_id, {}).get('license_valid', False)
                response.update({"type": "LOGIN_ACK", "payload": {"status": "OK", "user_id": user_id, "license_valid": license_valid}})
            else:
                logging.warning(f"Login failed for user '{user_id}' (Invalid PIN).")
                response.update({"type": "LOGIN_NAK", "payload": {"error": "Invalid user ID or PIN"}})
        
        elif msg_type == "CHECK_LICENSE":
                # TODO (AUTH): Verify signature from 'sender_id' on the payload/message content.
                # signature = message.get('signature')
                # data_signed = json.dumps(payload) # Or however the app signs it
                # if not verify_user_signature(sender_id, data_signed, signature):
                #     return {"type": "ERROR", "payload": {"error": "Invalid signature"}}
                sender_id = message.get('sender_id') # Get sender_id from message now
                if not sender_id: return {"type": "ERROR", "payload": {"error": "Missing sender_id for CHECK_LICENSE"}}
                with self.user_lock:
                    user_data = self.users.get(sender_id)
                if user_data:
                    is_valid = user_data.get('license_valid', False)
                    response.update({"type": "LICENSE_STATUS", "payload": {"user_id": sender_id, "is_valid": is_valid}})
                else:
                    response.update({"type": "LICENSE_STATUS", "payload": {"error": "User not registered", "user_id": sender_id, "is_valid": False}})



        # --- Delegation Management ---
        elif msg_type == "DELEGATE_ACCESS":
            # TODO (AUTH): Verify signature from 'sender_id' (owner) on the payload. Crucial.
            sender_id = message.get('sender_id') # Owner performing delegation
            if not sender_id: return {"type": "ERROR", "payload": {"error": "Missing sender_id (owner) for DELEGATE_ACCESS"}}

            payload = message.get('payload', {}) # Define payload here
            car_id = payload.get('car_id')
            recipient_user_id = payload.get('recipient_user_id')
            permissions = payload.get('permissions', [])
            duration_seconds = payload.get('duration_seconds', 3600) # Default 1 hour

            response = {"sender_id": "server"} # Initialize response here

            if not car_id or not recipient_user_id or not permissions:
                response.update({"type": "DELEGATE_NAK", "payload": {"error": "Missing car_id, recipient_user_id, or permissions"}})
            # --- Start: Added Validation Block ---
            elif len(permissions) == 1 and permissions[0] == "START":
                response.update({"type": "DELEGATE_NAK", "payload": {"error": "Invalid permissions specified. Needs 'UNLOCK' to 'START'."}})
            elif not all(p in config.VALID_PERMISSIONS for p in permissions):
                response.update({"type": "DELEGATE_NAK", "payload": {"error": f"Invalid permissions specified. Valid: {config.VALID_PERMISSIONS}"}})
            else:
                # Check ownership first (outside delegation lock)
                with self.car_lock:
                    car_info = self.cars.get(car_id)
                if not car_info:
                    response.update({"type": "DELEGATE_NAK", "payload": {"error": f"Car '{car_id}' not registered"}})
                elif car_info.get('owner_user_id') != sender_id:
                    response.update({"type": "DELEGATE_NAK", "payload": {"error": f"User '{sender_id}' does not own car '{car_id}'"}})
                else:
                    # Check if recipient exists (outside delegation lock)
                    with self.user_lock:
                       if recipient_user_id not in self.users:
                            response.update({"type": "DELEGATE_NAK", "payload": {"error": f"Recipient user '{recipient_user_id}' not registered"}})
                       else:
                           # --- Now check for existing delegations FOR THIS CAR (inside delegation lock) ---
                           with self.delegation_lock:
                                car_already_delegated = False
                                active_delegation_recipient = None
                                for existing_delegation in self.delegations.values():
                                    # Check if there's an *active* and *unexpired* delegation for the *same car*
                                    if (existing_delegation['car_id'] == car_id and
                                        existing_delegation['status'] == 'active' and
                                        time.time() < existing_delegation['expiry_timestamp']):
                                         car_already_delegated = True
                                         active_delegation_recipient = existing_delegation['recipient_user_id']
                                         break # Found one, no need to check further

                                if car_already_delegated:
                                     # Car already has an active delegation, reject this new one
                                     logging.warning(f"Delegation failed: Car '{car_id}' already has an active delegation to user '{active_delegation_recipient}'.")
                                     response.update({"type": "DELEGATE_NAK", "payload": {"error": f"Car '{car_id}' already has an active delegation to another user ({active_delegation_recipient}). Revoke existing delegation first."}})
                                     # --- Important: Return here ---
                                     return response # Exit processing for DELEGATE_ACCESS

                                # --- If we reach here, the car is not currently delegated actively ---
                                # Create the new delegation
                                delegation_id = str(uuid.uuid4())
                                expiry_timestamp = time.time() + duration_seconds
                                delegation_record = {
                                    'delegation_id': delegation_id,
                                    'car_id': car_id,
                                    'owner_user_id': sender_id,
                                    'recipient_user_id': recipient_user_id,
                                    'permissions': permissions,
                                    'expiry_timestamp': expiry_timestamp,
                                    'status': 'active'
                                }
                                self.delegations[delegation_id] = delegation_record
                                delegations_copy = self.delegations.copy() # Create copy inside lock

                           # --- Save outside the lock ---
                           self._save_json(config.DELEGATIONS_FILE, delegations_copy, "delegations")

                           # --- Update response for SUCCESS ---
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
                           





        # --- Car Management ---
        elif msg_type == "REGISTER_CAR":
            try:
                # TODO (AUTH): Verify signature from 'sender_id' (the owner) on the payload.
                #   This proves the user authorized adding this car under their name.
                # signature = message.get('signature')
                # data_signed = json.dumps(payload)
                # if not verify_user_signature(sender_id, data_signed, signature):
                
                sender_id = message.get('sender_id') # Get sender_id from message
                if not sender_id: return {"type": "ERROR", "payload": {"error": "Missing sender_id for REGISTER_CAR"}}
                if is_provisioning_connection: # Ensure it's not the provisioning cert
                    logging.warning(f"Rejecting '{msg_type}' from provisioning connection.")
                    return {"type": "ERROR", "payload": {"error": "Action requires authenticated user session"}}
                if client_cn != sender_id:
                    logging.warning(f"{msg_type} failed: TLS CN '{client_cn}' != sender_id '{sender_id}'.")
                    return {"type": "ERROR", "payload": {"error": "Certificate identity mismatch"}}
                # In POC, any registered user can register a car. In reality, needs admin/verification.
                car_id = payload.get('car_id')
                owner_user_id = payload.get('owner_user_id')
                # --- Expect the full certificate PEM now ---
                car_certificate_pem = payload.get('car_certificate_pem')
                model = payload.get('model', "Unknown Model")
                logging.debug(f"REGISTER_CAR: Processing for car '{car_id}', owner '{owner_user_id}'") # Add logging

                if not car_id or not owner_user_id or not car_certificate_pem:
                    response.update({"type": "REGISTER_CAR_NAK", "payload": {"error": "Missing car_id, owner_user_id, or car_certificate_pem"}})
                elif sender_id != owner_user_id: # Ensure the authenticated user is the one claiming ownership
                    response.update({"type": "REGISTER_CAR_NAK", "payload": {"error": f"Authenticated user '{sender_id}' does not match owner '{owner_user_id}'"}})
                else:
                    # Calculate fingerprint from provided PEM
                    logging.debug("Calculating fingerprint...")
                    fingerprint = self._calculate_fingerprint_from_pem(car_certificate_pem)
                    logging.debug(f"Fingerprint result: {fingerprint}")   
                    if not fingerprint:
                        response.update({"type": "REGISTER_CAR_NAK", "payload": {"error": "Invalid car certificate format provided"}})
                    else:
                        # Check if owner exists    
                        logging.debug("Checking owner existence...") # Add logging
                        with self.user_lock:
                            need_to_save = False # Flag to indicate if save is needed
                            cars_copy = None     # Variable to hold data for saving
                            if owner_user_id not in self.users:
                                response.update({"type": "REGISTER_CAR_NAK", "payload": {"error": f"Owner user '{owner_user_id}' not registered"}})
                            else:
                                logging.debug(f"Owner '{owner_user_id}' exists.") # Add logging
                                # --- Add Duplicate Car Check HERE ---
                                # Proceed with registration
                                with self.car_lock:
                                    if car_id in self.cars:
                                        # Car ID already exists! Reject the registration.
                                        logging.warning(f"Attempt to register duplicate car ID: {car_id}")
                                        response.update({
                                            "type": "REGISTER_CAR_NAK",
                                            "payload": {"error": f"Car ID '{car_id}' is already registered."}
                                        })
                                        # No need to save, need_to_save remains False
                                    else:
                                        # Car ID is unique, proceed with registration
                                        logging.info(f"Registering NEW car '{car_id}' with fingerprint: {fingerprint}")
                                        self.cars[car_id] = {
                                            'owner_user_id': owner_user_id,
                                            'model': model,
                                            'certificate_fingerprint_sha256': fingerprint,
                                        }
                                        cars_copy = self.cars.copy() # Prepare data for saving
                                        need_to_save = True          # Set flag to save
                                        # Set success response only if added
                                        response.update({
                                            "type": "REGISTER_CAR_ACK",
                                            "payload": {"status": "OK", "car_id": car_id, "owner": owner_user_id}
                                        })
                                    # --- Save outside the lock, only if needed ---
                                if need_to_save and (cars_copy is not None):
                                    logging.debug("Attempting to save cars data...")
                                    self._save_json(config.CARS_FILE, cars_copy, "cars")
                                    # Logging success message can happen after successful save or earlier
                                    logging.info(f"Car '{car_id}' registered successfully for owner '{owner_user_id}'.")
                                elif response.get("type") == "REGISTER_CAR_NAK":
                                    logging.info(f"Car '{car_id}' registration failed: {response.get('payload',{}).get('error')}")
            except Exception as e: # <--- Add except block
                logging.error(f"!!! Unhandled exception during REGISTER_CAR processing: {e}", exc_info=True) # Log the full traceback
                # Send a generic error response back to the client if possible
                response.update({"type": "REGISTER_CAR_NAK", "payload": {"error": f"Server internal error during registration: {e}"}})
                # Note: The connection might already be broken if the exception was severe

        elif msg_type == "REVOKE_DELEGATION":
            # TODO (AUTH): Verify signature from 'sender_id' (owner) on the payload. Crucial.
            # signature = message.get('signature')
            # data_signed = json.dumps(payload)
            # if not verify_user_signature(sender_id, data_signed, signature):
            #     return {"type": "REVOKE_DELEGATION_NAK", "payload": {"error": "Invalid signature for revocation"}}
            sender_id = message.get('sender_id') # Owner performing delegation
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
                        delegations_copy = self.delegations.copy() # Save copy
                        self._save_json(config.DELEGATIONS_FILE, delegations_copy, "delegations")
                        response.update({"type": "REVOKE_DELEGATION_ACK", "payload": {"status": "OK", "delegation_id": delegation_id}})
                        logging.info(f"Delegation '{delegation_id}' revoked by owner '{sender_id}'.")
        
        # --- NEW: Certificate Validation (Called by App Client) ---
        elif msg_type == "VALIDATE_CAR_CERT":
            sender_id = message.get('sender_id') # Owner performing delegation

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
        
        elif msg_type in ["VALIDATE_APP_PUBKEY", "VALIDATE_ACCESS_ATTEMPT"]:
            # We need to identify if the connection is from a CAR.
            # This could be based on the CN of the car's certificate.
            # Let's assume car cert CN is 'localhost' or the car's actual ID for this PoC.
            # Modify this check based on how you generate car certs.
            expected_car_cn = "localhost" # Or config.CAR_ID if CN matches that
            if client_cn != expected_car_cn: # Simple CN check for car identification
                 logging.warning(f"Rejecting '{msg_type}' from unexpected CN '{client_cn}' (expected car cert).")
                 return {"type": "ERROR", "payload": {"error": "Request not from recognized car certificate"}}

            # Sender ID in payload should be the car's ID
            sender_id = message.get('sender_id') # Car's ID from payload
            if not sender_id:
                 return {"type": "ERROR", "payload": {"error": f"Missing sender_id (car_id) for {msg_type}"}}

            # --- App Public Key Validation (Called by Car Server) ---
            elif msg_type == "VALIDATE_APP_PUBKEY": # New message type
                sender_id = message.get('sender_id') # Owner performing delegation

                # Request from Car Server (sender_id is car_id)
                if not sender_id: return {"type": "ERROR", "payload": {"error": "Missing sender_id (car) for VALIDATE_APP_PUBKEY"}}

                user_id_to_validate = payload.get('user_id_to_validate')
                # Expect 'app_certificate_pem' instead of 'app_public_key_pem'
                received_app_cert_pem = payload.get('app_certificate_pem')

                if not user_id_to_validate or not received_app_cert_pem:
                    response.update({"type": "VALIDATE_APP_PUBKEY_NAK", "payload": {"error": "Missing user_id_to_validate or received_app_cert_pem"}})
                else:
                    # Calculate fingerprint from received app certificate PEM
                    app_cert_fingerprint_to_validate = self._calculate_fingerprint_from_pem(received_app_cert_pem)
                    if not app_cert_fingerprint_to_validate:
                        logging.warning(f"App Cert Validation failed: Could not calculate fingerprint from PEM for user '{user_id_to_validate}'.")
                        response.update({"type": "VALIDATE_APP_PUBKEY_NAK", "payload": {"user_id": user_id_to_validate, "status": "INVALID", "reason": "Invalid app certificate format"}})
                        return response
                    
                    with self.user_lock:
                        user_data = self.users.get(user_id_to_validate)

                    if not user_data:
                        logging.warning(f"App Cert Validation failed: User ID '{user_id_to_validate}' not found (req by car '{sender_id}').")
                        response.update({"type": "VALIDATE_APP_PUBKEY_NAK", "payload": {"user_id": user_id_to_validate, "status": "INVALID", "reason": "User not registered"}})
                    else:
                        stored_user_cert_fingerprint = user_data.get('certificate_fingerprint_sha256')
                        if not stored_user_cert_fingerprint:
                            logging.error(f"Internal Error: Missing stored certificate fingerprint for user '{user_id_to_validate}'.")
                            response.update({"type": "VALIDATE_APP_PUBKEY_NAK", "payload": {"user_id": user_id_to_validate, "status": "INVALID", "reason": "Server internal error: user certificate fingerprint missing"}})
                        # --- Direct String Comparison of PEMs ---
                        elif hmac.compare_digest(app_cert_fingerprint_to_validate, stored_user_cert_fingerprint):
                            logging.info(f"App certificate validation SUCCESS for user '{user_id_to_validate}' requested by car '{sender_id}' Fingerprint: {app_cert_fingerprint_to_validate}.")
                            response.update({"type": "VALIDATE_APP_PUBKEY_ACK", "payload": {"user_id": user_id_to_validate, "status": "VALID"}})
                        else:
                            logging.warning(f"App certificate validation FAILED for user '{user_id_to_validate}' (req by car '{sender_id}'). Cert fingerprints mismatch.")
                            # For debugging:
                            presented_fp_short = app_cert_fingerprint_to_validate[:10] if app_cert_fingerprint_to_validate else "N/A"
                            stored_fp_short = stored_user_cert_fingerprint[:10] if stored_user_cert_fingerprint else "N/A"
                            logging.debug(f"Presented App Cert FP (from PEM): {presented_fp_short}..., Stored User Cert FP: {stored_fp_short}...")
                            response.update({"type": "VALIDATE_APP_PUBKEY_NAK", "payload": {"user_id": user_id_to_validate, "status": "INVALID", "reason": "App certificate mismatch"}})

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
                car_id_sender = message.get('sender_id') # Car sending the request

                if not car_id_sender: return {"type": "ERROR", "payload": {"error": "Missing sender_id (car) for VALIDATE_ACCESS_ATTEMPT"}}

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
            lsender_id = message.get('sender_id', 'Unknown')
            logging.warning(f"Received unknown message type '{msg_type}' from {lsender_id}") # Corrected variable name
            response.update({"type": "ERROR", "payload": {"error": f"Unknown message type: {msg_type}"}})

        return response

    def start(self):
        if not self.server_ssl_context: # Check if context creation failed
            logging.critical("Cannot start backend server without a valid SSL context.")
            return
        
        if not CA_CERT or not CA_KEY:
            logging.critical("Cannot start backend server without CA credentials loaded.")
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
    try:
        server = BackendServer(config.SERVER_IP, config.SERVER_PORT)
        server.start()
    except SystemExit as e:
        logging.critical(f"Server failed to initialize: {e}")
    except Exception as e:
        logging.critical(f"Unexpected error starting server: {e}", exc_info=True)