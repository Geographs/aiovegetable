import base64
import hashlib
import hmac
import uuid
import sys

import rsa


__all__: list[str] = [
    "generate_random_string",
    "get_hwid",
    "verify_hmac",
    "get_hash",
    "decrypt_variable",
]


def generate_random_string() -> str:
    return str(uuid.uuid4())


def get_hwid() -> str:
    return str(uuid.getnode())


def verify_hmac(raw_body: bytes, client_signature: str, hmac_secret: bytes) -> bool:
    computed_sha: str = hmac.new(
        hmac_secret, raw_body, digestmod=hashlib.sha256
    ).hexdigest()
    return computed_sha == client_signature


def get_hash() -> str:
    return hashlib.sha256(open(sys.argv[0], "rb").read()).hexdigest()


def decrypt_variable(variable: str, key: rsa.PrivateKey) -> str:
    decoded = base64.b64decode(variable)
    decrypted_bytes = rsa.decrypt(decoded, key)
    return decrypted_bytes.decode()
