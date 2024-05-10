# from cryptography import x509
# from cryptography.x509.oid import NameOID
# from cryptography.hazmat.primitives import hashes
from random import Random
from Issue_certificate import IssueCertificate
from encrypt_request_Test1 import RSAEncryptorDecryptor
from uuid import uuid4

from revoke_certificate import RevokeCertificate


class Registration:
    # Implement client registration functionality, allowing clients to provide their identity and public key.

    clients = []

    # Validity period, public key, identity from other parts
    def __init__(self):
        # Identity is just a UUID meant to mimick something akin to a monash ID
        self.identity = None
        self.public_key = None
        self.certificate = None

    def register_client(self):

        # Identity is something like monash ID, make it unique
        self.identity = str(uuid4())

        rsa = RSAEncryptorDecryptor()

        self.private_key, self.public_key = rsa.generate_key_pair()

        self.clients.append(
            {
                "identity": self.identity,
                "pub_key": self.public_key.decode()
            }
        )

    def register_for_certificate(self):
        pass

    def revoke_certificate(self):
        pass


def main():
    # Dup for second CA
    ca_1 = IssueCertificate()
    ca_1_private_key, ca_1_public_key = ca_1.generate_key_pair()
    ca_1.generate_session_key()

    revoke_certificate = RevokeCertificate()

    # Register 3 clients
    for i in range(3):
        client = Registration()
        client.register_client()
        certificate = ca_1.issue_certificate(
            client.identity, client.public_key, ca_1_private_key, ca_1_public_key, 365)
        print(certificate)
        revoke_certificate.revoke_certificate(
            client.identity, client.public_key, certificate)

        revoked = revoke_certificate.is_revoked(
            client.identity, client.public_key, certificate
        )
        print(revoked)


if __name__ == '__main__':
    main()
