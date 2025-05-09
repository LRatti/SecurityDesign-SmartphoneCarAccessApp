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
    
def serialize_public_key_pem(public_key: ec.EllipticCurvePublicKey) -> str:
    """Serialize public key to PEM string."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def deserialize_public_key_pem(pem_data: str) -> ec.EllipticCurvePublicKey:
    """Load a public key from PEM string."""
    return serialization.load_pem_public_key(pem_data.encode('utf-8'))

### I dont know what this shit below does btw
def serialize_private_key_pem(private_key: ec.EllipticCurvePrivateKey, password: bytes | None = None) -> str:
    """Serialize private key to PEM string."""
    encryption_algo = serialization.NoEncryption()
    if password:
        encryption_algo = serialization.BestAvailableEncryption(password)

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8, # Or PrivateFormat.TraditionalOpenSSL for older formats
        encryption_algorithm=encryption_algo
    ).decode('utf-8')

def deserialize_private_key_pem(pem_data: str, password: bytes | None = None) -> ec.EllipticCurvePrivateKey:
    """Load a private key from PEM string."""
    return serialization.load_pem_private_key(pem_data.encode('utf-8'), password=password)
