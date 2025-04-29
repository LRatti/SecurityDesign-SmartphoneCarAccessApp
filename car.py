from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from server import Server
from utils.crypto import generate_key_pair, verify_signature


class Car:
    def __init__(self, car_id, server: Server):
        self.car_id = car_id
        self.private_key, self.public_key = generate_key_pair()
        self.server = server
        self.server.register_car(self.car_id, self.public_key)

    def verify_user(self, user_public_key, signed_nonce, nonce):
        return verify_signature(user_public_key, signed_nonce, nonce)

    def unlock(self):
        print("Car unlocked!")

    def start(self):
        print("Car started!")
