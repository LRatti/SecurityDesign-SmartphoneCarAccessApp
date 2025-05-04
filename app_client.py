# app/app_client.py
import socket
import logging
import ssl # <-- Import ssl
import hashlib # <-- Add hashlib
import time
import json # For pretty printing responses
import os
import getpass # <-- Add getpass for hidden PIN input
from utils import config, network_utils
# --- Cryptography for parsing cert and serializing key ---
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
# -------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format='%(asctime)s - AppClient - %(levelname)s - %(message)s')

# --- Centralized place to create backend SSL context ---
# (Can be used by AppClient instance and also standalone login/signup)
def create_backend_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        # Uses APP cert/key to authenticate itself to BACKEND
        context.load_cert_chain(certfile=config.APP_CERT_FILE, keyfile=config.APP_KEY_FILE)
        # Uses CA cert to verify BACKEND SERVER's cert
        context.load_verify_locations(cafile=config.CA_CERT_FILE)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False # Set True if backend cert CN=localhost (for this setup)
        if not context.check_hostname:
                logging.warning("SSL Hostname Check is DISABLED for Backend connection. Enable in production.")
        logging.debug("BACKEND SSL context created successfully for mTLS.")
        return context
    except Exception as e:
        logging.critical(f"Failed to create backend SSL context: {e}")
        raise SystemExit("Cannot proceed without backend SSL context.")

# --- Login/Signup Functions (outside AppClient class) ---
def _send_receive_auth(message: dict):
    """Sends an auth message (login/signup) to backend and gets response."""
    context = create_backend_ssl_context()
    raw_sock = None
    ssl_sock = None
    address = (config.SERVER_IP, config.SERVER_PORT)
    response = None
    try:
        logging.debug(f"Attempting raw socket connection to backend {address} for auth")
        raw_sock = socket.create_connection(address, timeout=5.0)
        logging.debug(f"Wrapping socket for backend TLS handshake for auth")
        server_hostname = address[0] if context.check_hostname else None
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=server_hostname)
        logging.info(f"TLS connection established successfully to backend server {address} for auth")

        # Send message
        if network_utils.send_message(ssl_sock, message):
            ssl_sock.settimeout(10.0)
            response = network_utils.receive_message(ssl_sock)
        else:
             logging.error(f"Failed to send {message.get('type')} message to backend.")

    except (socket.timeout, socket.error, ssl.SSLError, Exception) as e:
        logging.error(f"Error during backend communication for {message.get('type')}: {e}")
    finally:
        if ssl_sock:
            try:
                ssl_sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            ssl_sock.close()
        elif raw_sock:
            raw_sock.close()
    return response

def signup_with_server(user_id: str, pin: str) -> bool:
    """Attempts to sign up a new user with the backend."""
    logging.info(f"Attempting signup for user '{user_id}'...")
    # Note: Public key is implicitly sent via the client certificate during TLS handshake
    # The backend's handle_client extracts it.
    message = {
        "type": "SIGNUP",
        "payload": {
            "user_id": user_id,
            "pin": pin
            # No need to send app_public_key_pem here, backend gets from cert
        }
    }
    response = _send_receive_auth(message)
    if response and response.get("type") == "SIGNUP_ACK":
        logging.info("Signup successful!")
        return True
    else:
        error = response.get("payload", {}).get("error", "Unknown error") if response else "Communication error"
        logging.error(f"Signup failed: {error}")
        return False

def login_with_server(user_id: str, pin: str) -> bool:
    """Attempts to log in a user with the backend."""
    logging.info(f"Attempting login for user '{user_id}'...")
    message = {
        "type": "LOGIN",
        "payload": {
            "user_id": user_id,
            "pin": pin
        }
    }
    response = _send_receive_auth(message)
    if response and response.get("type") == "LOGIN_ACK":
        logging.info("Login successful!")
        # You could potentially store session info/token here if needed later
        return True
    else:
        error = response.get("payload", {}).get("error", "Invalid user ID or PIN") if response else "Communication error"
        logging.error(f"Login failed: {error}")
        return False

class AppClient:
    def __init__(self, user_id):
        self.user_id = user_id
        self.server_addr = (config.SERVER_IP, config.SERVER_PORT)
        self.car_addr = (config.CAR_IP, config.CAR_PORT) # Assuming only one car for now
        # TODO (AUTH): Load/generate user's private key securely (e.g., from file/keystore).
        #   The public_key below should be derived from the actual private key.

        # Public key is implicitly handled by TLS certs, no need to store here unless for signing
        # self.public_key = f"pubkey_for_{self.user_id}" # Placeholder! Replace

        self.last_delegation_id = None # Store last created delegation ID for easy revocation
        # --- TLS Setup ---
        self.car_ssl_context = self._create_car_ssl_context() # Renamed for clarity
        # We use the shared function for backend context creation if needed within the class
        self.backend_ssl_context = create_backend_ssl_context()

    def _create_car_ssl_context(self):
        # Use PROTOCOL_TLS_CLIENT for client-side context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            logging.info(f"Loading APP cert chain: {config.APP_CERT_FILE}, {config.APP_KEY_FILE}")
            # Uses APP cert/key to authenticate itself to CAR
            context.load_cert_chain(certfile=config.APP_CERT_FILE, keyfile=config.APP_KEY_FILE)
            logging.info(f"Loading CA cert for server verification: {config.CA_CERT_FILE}")
            # Load CA cert to verify the server's certificate
            # Uses CA cert to verify CAR's cert
            context.load_verify_locations(cafile=config.CA_CERT_FILE)
            context.verify_mode = ssl.CERT_REQUIRED
            # Hostname checking - IMPORTANT for production
            # If server cert CN is 'localhost' or IP, set check_hostname=True
            # If using a self-signed cert without matching CN, set to False for testing ONLY
            context.check_hostname = False # Set to True if car cert CN matches config.CAR_IP/hostname
            if (not context.check_hostname):
                logging.warning("SSL Hostname Check is DISABLED. Enable in production.")

            # Optional: Set specific TLS versions or cipher suites
            context.minimum_version = ssl.TLSVersion.TLSv1_3

            logging.info("SSL context created successfully for mTLS.")
            return context
        except ssl.SSLError as e:
            logging.critical(f"SSL Error creating client context: {e}")
            raise SystemExit("Failed to initialize SSL context - check certificate paths and permissions.")
        except FileNotFoundError as e:
             logging.critical(f"Certificate file not found: {e}")
             raise SystemExit("Failed to initialize SSL context - certificate file missing.")
        except Exception as e:
             logging.critical(f"Unexpected error creating CAR SSL context: {e}")
             # Exit or proper handling if context fails
             raise SystemExit("Failed to initialize CAR SSL context.")
        
     # --- REMOVED: _create_backend_ssl_context (using shared function now) ---
   
     # --- Create SSL Context for BACKEND connection ---
    # def _create_backend_ssl_context(self):
    #     context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    #     try:
    #         logging.info(f"Loading APP cert chain for backend: {config.APP_CERT_FILE}, {config.APP_KEY_FILE}")
    #         # Uses APP cert/key to authenticate itself to BACKEND
    #         context.load_cert_chain(certfile=config.APP_CERT_FILE, keyfile=config.APP_KEY_FILE)

    #         logging.info(f"Loading CA cert for backend server verification: {config.CA_CERT_FILE}")
    #         # Uses CA cert to verify BACKEND SERVER's cert
    #         context.load_verify_locations(cafile=config.CA_CERT_FILE)
    #         context.verify_mode = ssl.CERT_REQUIRED

    #         # Hostname checking for the backend server - IMPORTANT
    #         # Set to True if backend server cert CN matches config.SERVER_IP/hostname
    #         context.check_hostname = False # Set True if backend cert CN=localhost (for this setup)
    #         if not context.check_hostname:
    #              logging.warning("SSL Hostname Check is DISABLED for Backend connection. Enable in production.")

    #         logging.info("BACKEND SSL context created successfully for mTLS.")
    #         return context
    #     except ssl.SSLError as e:
    #         logging.critical(f"SSL Error creating backend client context: {e}")
    #         raise SystemExit("Failed to initialize backend SSL context.")
    #     except FileNotFoundError as e:
    #          logging.critical(f"Certificate file not found for backend context: {e}")
    #          raise SystemExit("Failed to initialize backend SSL context.")
    #     except Exception as e:
    #          logging.critical(f"Unexpected error creating backend SSL context: {e}")
    #          raise SystemExit("Failed to initialize backend SSL context.")


    def _connect(self, address, target_car_id: str): # <-- Add target_car_id
        """Establishes a TLS connection to the given address."""
        if not self.car_ssl_context: # Use the CAR context
             logging.error("Cannot connect to car: SSL context not initialized.")
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
            server_hostname = address[0] if self.car_ssl_context.check_hostname else None
            ssl_sock = self.car_ssl_context.wrap_socket(raw_sock, server_hostname=server_hostname)

            logging.info(f"TLS connection established successfully to {address}")

            # --- 3. Certificate Validation Step ---
            logging.info("Retrieving car's certificate for validation...")
            try:
                # Get certificate in DER format for consistent hashing
                car_cert_der = ssl_sock.getpeercert(binary_form=True)
                if not car_cert_der:
                    raise ValueError("Could not retrieve peer certificate in binary form.")

                # Calculate SHA-256 fingerprint
                fingerprint = hashlib.sha256(car_cert_der).hexdigest()
                logging.info(f"Car certificate fingerprint (SHA-256): {fingerprint}")

                # Ask backend server to validate this fingerprint for the target car ID
                if not self._validate_car_certificate_with_server(target_car_id, fingerprint):
                    # Validation failed! Close the connection.
                    logging.error(f"Backend validation failed for car '{target_car_id}' certificate. Aborting connection.")
                    ssl_sock.close() # Close the TLS socket
                    return None # Indicate connection failure

                logging.info(f"Backend successfully validated car '{target_car_id}' certificate.")
                # --- Validation Successful ---
            except (ValueError, AttributeError) as e:
                logging.error(f"Failed to get or hash car certificate: {e}")
                ssl_sock.close()
                return None
            except Exception as e: # Catch potential errors during validation call
                 logging.error(f"Error during backend certificate validation step: {e}")
                 ssl_sock.close()
                 return None

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

            return ssl_sock # Return the secure socket

        except socket.timeout:
            logging.error(f"Connection or TLS handshake to {address} timed out.")
            if ssl_sock: ssl_sock.close()
            elif raw_sock: raw_sock.close()
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

    # --- Connect to Backend using TLS ---
    def _connect_to_backend_tls(self, address):
        """Establishes a TLS connection to the BACKEND server."""
        if not self.backend_ssl_context: # Use the BACKEND context
             logging.error("Cannot connect to backend: BACKEND SSL context not initialized.")
             return None

        raw_sock = None
        ssl_sock = None
        try:
            logging.debug(f"Attempting raw socket connection to backend {address}")
            raw_sock = socket.create_connection(address, timeout=5.0)
            logging.debug(f"Raw socket connected to backend {address}")

            logging.debug(f"Wrapping socket for backend TLS handshake")
            # Determine server_hostname for backend connection if needed
            server_hostname = address[0] if self.backend_ssl_context.check_hostname else None
            # --- Use self.backend_ssl_context ---
            ssl_sock = self.backend_ssl_context.wrap_socket(raw_sock, server_hostname=server_hostname)

            logging.info(f"TLS connection established successfully to backend server {address}")
            # Optional: Log backend server cert details
            try:
                server_cert = ssl_sock.getpeercert()
                if server_cert:
                    subject = dict(x[0] for x in server_cert.get('subject', []))
                    logging.debug(f"Backend Server Cert Subject: {subject}")
            except Exception as e:
                 logging.warning(f"Error getting peer certificate from backend server: {e}")

            return ssl_sock # Return the secure socket

        except socket.timeout:
            logging.error(f"Connection to backend {address} timed out.")
            if raw_sock: raw_sock.close()
            return None
        except socket.error as e:
            logging.error(f"Socket error connecting to backend {address}: {e}")
            if raw_sock: raw_sock.close()
            return None
        except ssl.SSLCertVerificationError as e:
             logging.error(f"SSL Certificate Verification Error connecting to backend {address}: {e}")
             if ssl_sock: ssl_sock.close()
             elif raw_sock: raw_sock.close()
             return None
        except ssl.SSLError as e:
             logging.error(f"SSL Error establishing connection to backend {address}: {e}")
             if ssl_sock: ssl_sock.close()
             elif raw_sock: raw_sock.close()
             return None
        except Exception as e:
             logging.error(f"Unexpected error during TLS connection to backend {address}: {e}")
             if ssl_sock: ssl_sock.close()
             elif raw_sock: raw_sock.close()
             return None

    # --- Make validation call use TLS ---
    def _validate_car_certificate_with_server(self, car_id: str, fingerprint: str) -> bool:
        """Contacts the backend server securely (TLS) to validate the car's certificate fingerprint."""
        logging.info(f"Contacting backend server {self.server_addr} SECURELY to validate cert for car '{car_id}'")
        validation_message = {
            "type": "VALIDATE_CAR_CERT",
            "sender_id": self.user_id,
            "payload": {
                "car_id": car_id,
                "certificate_fingerprint": fingerprint
            }
            # TODO (AUTH): Sign this request if backend requires authenticated validation requests
        }
        # --- Use the new TLS connection method for the backend ---
        backend_tls_sock = None
        try:
            backend_tls_sock = self._connect_to_backend_tls(self.server_addr)
            if not backend_tls_sock:
                logging.error("Failed to establish secure connection to backend for validation.")
                return False # Can't validate if connection fails

            if network_utils.send_message(backend_tls_sock, validation_message):
                backend_tls_sock.settimeout(5.0)
                response = network_utils.receive_message(backend_tls_sock)
                if response and response.get("type") == "VALIDATE_CAR_CERT_ACK" and response.get("payload", {}).get("status") == "VALID":
                    logging.info("Backend server confirmed certificate validity over TLS.")
                    return True
                else:
                    reason = response.get("payload", {}).get("reason", "Unknown") if response else "No response"
                    logging.error(f"Backend server rejected certificate validation (via TLS): {reason}")
                    return False
            else:
                logging.error("Failed to send validation request to backend server over TLS.")
                return False
        except socket.timeout:
            logging.error(f"Connection to backend server {self.server_addr} timed out during TLS validation.")
            return False
        except ssl.SSLError as e:
            logging.error(f"SSL error communicating with backend server {self.server_addr} during validation: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error validating cert with backend via TLS: {e}")
            return False
        finally:
             if backend_tls_sock:
                 logging.debug("Closing secure connection to backend server after validation.")
                 try:
                     backend_tls_sock.shutdown(socket.SHUT_RDWR)
                 except OSError: pass
                 backend_tls_sock.close()
        # --- End Backend TLS Connection Block ---

    def _send_and_receive(self, address, message: dict, target_car_id: str | None = None):
        """
        Connects securely (validating car cert via _connect if applicable),
        sends a message, receives a response, and disconnects.
        Handles both CAR and SERVER addresses using appropriate TLS contexts.
        """
        sock = None # Use generic name, could be TLS or plain socket

        # Step 1: Establish connection based on address type
        if address == self.car_addr:
            if not target_car_id:
                 logging.error("Target Car ID required for car connection.")
                 return None
            # _connect handles TLS setup AND backend validation internally
            sock = self._connect(address, target_car_id)
            if not sock:
                 # _connect logs the specific reason (TLS or validation failure)
                 logging.error(f"Failed to establish validated TLS connection to car '{target_car_id}' at {address}")
                 return None
            logging.debug(f"Validated TLS connection established to car {address}")

        elif address == self.server_addr:
             # Use the simple, insecure backend connection for now
             # WARNING: This should be upgraded to TLS in a real system.
             sock = self._connect_to_backend_tls(address)
             if not sock:
                 logging.error(f"Failed to establish TLS connection to backend server at {address}")
                 return None
             logging.debug(f"TLS connection established to backend server {address}")
        else:
             logging.error(f"Cannot send/receive: Unknown address type: {address}")
             return None

        # Step 2: Send message and receive response over the established socket
        response = None
        try:
            logging.debug(f"Sending message to {address}: {message.get('type')}")
            if network_utils.send_message(sock, message):
                # Set timeout for receiving response
                sock.settimeout(10.0) # Slightly longer timeout for network variability
                response = network_utils.receive_message(sock)
                if response:
                    logging.debug(f"Received response from {address}: {response.get('type')}")
                else:
                    # receive_message logs specific errors (timeout, JSON decode, etc.)
                     logging.warning(f"No valid message received from {address} after sending {message.get('type')}.")
            else:
                # send_message logs specific errors
                logging.error(f"Failed to send message ({message.get('type')}) to {address}.")
        except socket.timeout:
             logging.error(f"Receive operation timed out waiting for response from {address}.")
        except ssl.SSLError as e: # Only relevant if sock is SSLSocket (i.e., connected to car)
            logging.error(f"SSL error during communication with {address}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during communication with {address}: {e}")

        # Step 3: Close the socket cleanly
        finally:
            if sock:
                logging.debug(f"Closing connection to {address}")
                try:
                    # Shutdown needs care, might already be closed on error
                    sock.shutdown(socket.SHUT_RDWR)
                except (OSError, socket.error) as e:
                    # Ignore errors like "Socket is not connected" if already closed/broken
                    logging.debug(f"Socket shutdown error (ignoring): {e}")
                    pass
                finally:
                      sock.close() # Ensure close is always attempted

        # Step 4: Return the response
        if response:
            logging.info(f"Received final response type '{response.get('type')}' from {address}")
        else:
            logging.warning(f"No response ultimately received from {address} for message type {message.get('type')}.")

        return response

    # --- REMOVED: register_with_server (handled by standalone signup_with_server) ---

    # def register_with_server(self):
    #     """Registers the user's public key with the backend server."""
    #     logging.info("Attempting to register with the backend server...")
        
    #     app_public_key_pem = None # Initialize to None

    #     # --- Load app cert, extract public key, serialize to PEM ---
    #     try:
    #         with open(config.APP_CERT_FILE, 'rb') as f: # Read bytes
    #             app_cert_pem_bytes = f.read()
    #         app_cert = x509.load_pem_x509_certificate(app_cert_pem_bytes, default_backend())
    #         public_key = app_cert.public_key()
    #         app_public_key_pem = public_key.public_bytes(
    #             encoding=serialization.Encoding.PEM,
    #             format=serialization.PublicFormat.SubjectPublicKeyInfo
    #         ).decode('utf-8') # Decode bytes to string for JSON
    #         logging.debug("Extracted and serialized app public key PEM for registration.")
    #     except FileNotFoundError:
    #         logging.error(f"Cannot register user: App certificate file '{config.APP_CERT_FILE}' not found.")
    #         return False
    #     except (IOError, ValueError, TypeError) as e: # Catch parsing/serialization errors
    #         logging.error(f"Cannot register user: Error processing app certificate/key: {e}")
    #         return False
        
    #     message = {
    #         "type": "REGISTER",
    #         "sender_id": self.user_id,
    #         "payload": {
    #             "app_public_key_pem": app_public_key_pem # <-- Send the public key PEM
    #         }
    #     }

    #     # NOTE (AUTH): No signature added here in current placeholder structure,
    #     #   assuming server trusts initial registration or uses an out-of-band verification.

    #     response = self._send_and_receive(self.server_addr, message) # Uses TLS backend connection
    #     if response and response.get("type") == "REGISTER_ACK":
    #         logging.info("Registration successful!")
    #         return True
    #     else:
    #         error = response.get("payload", {}).get("error", "Unknown error") if response else "No response/comm error"
    #         logging.error(f"Registration failed: {error}")
    #         return False

    def check_license_status(self):
        """Checks the user's driving license status with the server."""
        logging.info("Checking license status with the backend server...")
        message = {
            "type": "CHECK_LICENSE",
            "sender_id": self.user_id,
            "payload": {}
            # TODO (AUTH): Add signature to authenticate the request.

        }
        response = self._send_and_receive(self.server_addr, message) # No target_car_id
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
    
        # --- Load the car's certificate PEM to send ---
        # In a real scenario, the OWNER app might not *have* the car's cert.
        # This registration might happen via a different mechanism (e.g., factory, dealer).
        # FOR THIS POC: We assume the owner running this client somehow has the car's public cert PEM.
        # Let's read it from the expected file path used by the car server.
        try:
            with open(config.CAR_CERT_FILE, 'r') as f:
                car_cert_pem_content = f.read()
            logging.debug(f"Read car certificate PEM from {config.CAR_CERT_FILE} for registration.")
        except FileNotFoundError:
            logging.error(f"Cannot register car: Car certificate file '{config.CAR_CERT_FILE}' not found.")
            return False
        except IOError as e:
            logging.error(f"Cannot register car: Error reading car certificate file: {e}")
            return False
        # -------------------------------------------

        message = {
            "type": "REGISTER_CAR",
            "sender_id": self.user_id,
            "payload": {
                "car_id": car_id,
                "owner_user_id": self.user_id,
                "car_certificate_pem": car_cert_pem_content, # <-- Send the PEM
                "model": model
                # TODO (AUTH): Add signature
            }
        }

        # Send to backend (no target_car_id needed)
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
        response = self._send_and_receive(self.server_addr, message) # No target_car_id
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
         response = self._send_and_receive(self.server_addr, message) # No target_car_id
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
    def request_car_action(self, action_type: str, target_car_addr=None, target_car_id: str | None = None): 
        """Sends an action request (e.g., UNLOCK_REQUEST, START_REQUEST) to the car."""
        # Uses the default car address unless overridden
        # TODO (AUTH / UI): In a real app, biometric/PIN verification might be required here
        #   before allowing the private key to be used for signing the request.

        car_addr_to_use = target_car_addr if target_car_addr else self.car_addr

        # --- Get the default car ID if not specified ---
        # This is a simplification; a real app would know which car it's interacting with.
        if not target_car_id:
            # You might need a way to configure the default car ID for the client
            target_car_id = os.environ.get("CAR_ID", "CAR_VIN_DEMO_789") # Match car default
            logging.warning(f"Target car ID not specified, using default: {target_car_id}")

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

        # Pass the target_car_id to _send_and_receive
        response = self._send_and_receive(car_addr_to_use, message, target_car_id=target_car_id)

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


# --- Updated Command Line Interface ---
def run_cli(client: AppClient):
    """Runs the main menu *after* the user has logged in."""
    while True:
        print(f"\n--- Smartphone Car Access App (User: {client.user_id}) ---")
        # print("--- User/Server ---") # Registration/Login now handled outside
        # print("1. Register User with Server") # Removed
        print("1. Check License Status")
        print("--- Car Management (Owner) ---")
        print("2. Register a New Car")
        print("3. Delegate Access to Car")
        print("4. Revoke Last Delegation")
        print("5. Revoke Specific Delegation")
        print("--- Car Interaction ---")
        print("6. Unlock Car")
        print("7. Start Car")
        print("8. Lock Car")
        print("9. Stop Car")
        print("0. Exit")

        choice = input("Enter your choice: ")

        try:
            if choice == '1':
                client.check_license_status()
            elif choice == '2':
                car_id = input("Enter Car ID (VIN) to register: ")
                model = input("Enter Car Model (optional): ")
                if car_id:
                    client.register_car(car_id, model or "Unknown Model")
            elif choice == '3':
                car_id = input("Enter Car ID to delegate access for: ")
                recipient = input("Enter Recipient User ID: ")
                perms_str = input(f"Enter Permissions ({','.join(config.VALID_PERMISSIONS)}): ")
                duration_h_str = input("Enter duration in hours (e.g., 1.5) [default: 1]: ")
                duration_h = float(duration_h_str) if duration_h_str else 1.0
                permissions = [p.strip().upper() for p in perms_str.split(',') if p.strip()]
                if car_id and recipient and permissions:
                    client.delegate_access(car_id, recipient, permissions, duration_h)
                else:
                    print("Missing required info for delegation.")
            elif choice == '4':
                 if client.last_delegation_id:
                    client.revoke_delegation(client.last_delegation_id)
                 else:
                    print("No delegation ID stored from the last 'delegate' action.")
            elif choice == '5':
                 del_id = input("Enter Delegation ID to revoke: ")
                 if del_id:
                     client.revoke_delegation(del_id)
            # --- Car Interaction Cases ---
            elif choice == '6':
                # Ask for car ID if multiple cars are supported later
                # car_id_to_unlock = input("Enter Car ID to unlock [default: configured car]: ") or None
                client.request_car_action("UNLOCK_REQUEST") # Pass car_id_to_unlock if implemented
            elif choice == '7':
                client.request_car_action("START_REQUEST")
            elif choice == '8':
                client.request_car_action("LOCK_REQUEST")
            # --- NEW CASE ---
            elif choice == '9':
                client.request_car_action("STOP_CAR_REQUEST")
            # ----------------
            elif choice == '0':
                print("Exiting.")
                break
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
             print(f"\nAn error occurred: {e}")
             logging.exception("CLI Error")

        time.sleep(0.1) # Prevent tight loop on error


if __name__ == "__main__":
    # --- New Login/Signup Loop ---
    logged_in_user_id = None
    while logged_in_user_id is None:
        print("\n--- Welcome ---")
        print("1. Sign Up")
        print("2. Login")
        print("0. Exit")
        auth_choice = input("Choose an option: ")

        if auth_choice == '1':
            user_id = input("Enter desired User ID: ")
            while True:
                pin = getpass.getpass("Enter 4-digit PIN: ") # Hidden input
                if len(pin) == 4 and pin.isdigit():
                    pin_confirm = getpass.getpass("Confirm 4-digit PIN: ")
                    if pin == pin_confirm:
                        break
                    else:
                        print("PINs do not match. Try again.")
                else:
                    print("PIN must be exactly 4 digits. Try again.")

            if not user_id:
                print("User ID cannot be empty.")
                continue

            if signup_with_server(user_id, pin):
                print(f"Signup successful for {user_id}. Please log in.")
                # Automatically log in after signup? Or force login? Let's force login for now.
            else:
                print("Signup failed. Please check logs or try a different User ID.")

        elif auth_choice == '2':
            user_id = input("Enter User ID: ")
            pin = getpass.getpass("Enter 4-digit PIN: ") # Hidden input

            if not user_id or not pin:
                 print("User ID and PIN are required.")
                 continue
            if not pin.isdigit() or len(pin) != 4:
                 print("PIN must be 4 digits.")
                 continue

            if login_with_server(user_id, pin):
                logged_in_user_id = user_id # Set the user ID upon successful login
                print(f"Login successful for {user_id}.")
            else:
                print("Login failed. Invalid User ID or PIN.") # Keep error generic

        elif auth_choice == '0':
            print("Exiting.")
            exit()
        else:
            print("Invalid choice.")

        time.sleep(0.1)

    # --- Proceed only if login was successful ---
    if logged_in_user_id:
        print(f"\nStarting app client for authenticated user: {logged_in_user_id}")
        try:
            app_client = AppClient(logged_in_user_id)
            run_cli(app_client) # Start the main application menu
        except SystemExit as e:
             print(f"Exiting due to critical setup error: {e}")
        except Exception as e:
             print(f"An unexpected error occurred during client initialization: {e}")
             logging.exception("Client Init Error")