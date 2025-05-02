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