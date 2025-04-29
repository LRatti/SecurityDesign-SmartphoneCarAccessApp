from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

def generate_key_pair():
    """Generate an ECC private/public key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message: bytes) -> bytes:
    """Sign a message using a private key."""
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

def verify_signature(public_key, signature: bytes, message: bytes) -> bool:
    """Verify a signature using a public key."""
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
    

### I dont know what this shit below does btw
def serialize_public_key(public_key):
    """Serialize public key to bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data: bytes):
    """Load a public key from bytes."""
    return serialization.load_pem_public_key(pem_data)