from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
import os
from utils.crypto import generate_key_pair, sign_message
from server import Server
from car import Car


class App:
    def __init__(self, user_id, server: Server):
        self.user_id = user_id
        self.private_key, self.public_key = generate_key_pair()
        self.server = server
        self.server.register_user(self.user_id, self.public_key)

    def authenticate_to_car(self, car: Car):
        nonce = os.urandom(32)
        signature = sign_message(self.private_key, nonce)
        if car.verify_user(self.public_key, signature, nonce):
            print(f"{self.user_id} authenticated to car {car.car_id}!")
            return True
        else:
            print("Authentication failed!")
            return False

    def check_license(self):
        return self.server.verify_license(self.user_id)

    def biometric_verification(self):
        return True

    def fallback_pin_verification(self, entered_pin, real_pin="123456"):
        return entered_pin == real_pin