# utils/config.py
import os

SERVER_IP = '127.0.0.1'
SERVER_PORT = 65000

CAR_IP = '127.0.0.1'
CAR_PORT = 65001 # Example port for one car

# Data storage paths
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
SERVER_DATA_DIR = os.path.join(DATA_DIR, 'server_data')
REGISTRATION_FILE = os.path.join(SERVER_DATA_DIR, 'registrations.json')
CARS_FILE = os.path.join(SERVER_DATA_DIR, 'cars.json') # New
DELEGATIONS_FILE = os.path.join(SERVER_DATA_DIR, 'delegations.json') # New


# Ensure data directories exist
os.makedirs(SERVER_DATA_DIR, exist_ok=True)

# Permissions constants (can be shared)
PERMISSION_UNLOCK = "UNLOCK"
PERMISSION_START = "START"
VALID_PERMISSIONS = {PERMISSION_UNLOCK, PERMISSION_START}

# --- TLS Configuration ---
# Directory where certificates are stored
CERT_DIR = os.path.join(os.path.dirname(__file__), '..', 'certs')

# Ensure certs directory exists (optional, good for setup)
# os.makedirs(CERT_DIR, exist_ok=True)

# Certificate Authority
CA_CERT_FILE = os.path.join(CERT_DIR, 'ca-cert.pem')

# Car Server Certificates
CAR_CERT_FILE = os.path.join(CERT_DIR, 'car-cert.pem')
CAR_KEY_FILE = os.path.join(CERT_DIR, 'car-key.pem')

# App Client Certificates (Example - could be user-specific in a real app)
APP_CERT_FILE = os.path.join(CERT_DIR, 'app-cert.pem')
APP_KEY_FILE = os.path.join(CERT_DIR, 'app-key.pem')

# Backend Server Certificates (NEW)
SERVER_CERT_FILE = os.path.join(CERT_DIR, 'server-cert.pem')
SERVER_KEY_FILE = os.path.join(CERT_DIR, 'server-key.pem')

# Check if files exist (optional, but good for debugging setup)
if not os.path.exists(CA_CERT_FILE):
    print(f"Warning: CA Certificate not found at {CA_CERT_FILE}")
