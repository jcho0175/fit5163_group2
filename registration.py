# from cryptography import x509
# from cryptography.x509.oid import NameOID
# from cryptography.hazmat.primitives import hashes
from random import Random
from encrypt_request_Test1 import RSAEncryptorDecryptor
from uuid import uuid4


class Registration:
    # Implement client registration functionality, allowing clients to provide their identity and public key.

    clients = []

    # Validity period, public key, identity from other parts
    def __init__(self, client_id):
        self.identity = client_id
        self.public_key = None

    def register_client(self):

        # Identity is something like monash ID, make it unique
        rsa = RSAEncryptorDecryptor()
        rsa.generate_key_pair()
        print("Public Key", rsa.public_key)
        self.clients.append(
            {
                "identity": self.identity,
                "pub_key": rsa.public_key
            }
        )


if __name__ == '__main__':

    def main():
        id = uuid4()
        registration = Registration(id)
        registration.register_client()

    main()
