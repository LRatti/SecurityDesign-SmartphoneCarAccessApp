from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
import time

class Server:
    def __init__(self):
        self.users = {}  # user_id: public_key
        self.cars = {}   # car_id: public_key
        self.license_status = {}  # user_id: bool

    def register_user(self, user_id, public_key):
        self.users[user_id] = public_key
        self.license_status[user_id] = True

    def register_car(self, car_id, public_key):
        self.cars[car_id] = public_key

    def verify_license(self, user_id):
        return self.license_status.get(user_id, False)

    def revoke_license(self, user_id):
        if user_id in self.license_status:
            self.license_status[user_id] = False

    def issue_delegation_token(self, owner_id, recipient_public_key, validity_seconds=3600):
        expiry = time.time() + validity_seconds
        return {'owner': owner_id, 'recipient_key': recipient_public_key, 'expires': expiry}
