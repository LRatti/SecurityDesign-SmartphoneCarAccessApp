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
os.makedirs(CERT_DIR, exist_ok=True)

# Certificate Authority
CA_CERT_FILE = os.path.join(CERT_DIR, 'ca-cert.pem')

# Car Server Certificates
CAR_CERT_FILE = os.path.join(CERT_DIR, 'car-cert.pem')
CAR_KEY_FILE = os.path.join(CERT_DIR, 'car-key.pem')

# Directory for user-specific certs (can be the same as CERT_DIR)
# USER_CERT_DIR = CERT_DIR # Or a subdirectory if preferred
USER_CERT_DIR = os.path.join(CERT_DIR, 'users')
os.makedirs(USER_CERT_DIR, exist_ok=True) # Ensure it exists if using subdirectory

def get_user_cert_path(user_id):
    """Gets the path for a user's certificate."""
    return os.path.join(USER_CERT_DIR, f"user_{user_id}_cert.pem")

def get_user_key_path(user_id):
    """Gets the path for a user's private key."""
    return os.path.join(USER_CERT_DIR, f"user_{user_id}_key.pem")

# Certificate Authority Key (Needed by backend for signing)
CA_KEY_FILE = os.path.join(CERT_DIR, 'ca-key.pem')

# App Client Certificates (Example - could be user-specific in a real app)
PROVISIONING_APP_CERT_FILE = os.path.join(CERT_DIR, 'app-cert.pem')
PROVISIONING_APP_KEY_FILE = os.path.join(CERT_DIR, 'app-key.pem')

# Backend Server Certificates (NEW)
SERVER_CERT_FILE = os.path.join(CERT_DIR, 'server-cert.pem')
SERVER_KEY_FILE = os.path.join(CERT_DIR, 'server-key.pem')

# Intermediate CA (NEW)
INTERMEDIATE_CA_KEY_FILE = os.path.join(CERT_DIR, 'intermediate-ca-key.pem')
INTERMEDIATE_CA_CERT_FILE = os.path.join(CERT_DIR, 'intermediate-ca-cert.pem')

# Intermediate CA Chain (if applicable) (NEW)
CA_CHAIN_FILE = os.path.join(CERT_DIR, 'ca-chain.pem')

# Check if files exist (optional, but good for debugging setup)
if not os.path.exists(CA_CERT_FILE):
    print(f"Warning: CA Certificate not found at {CA_CERT_FILE}")
