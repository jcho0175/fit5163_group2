from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

class Registration:
    # Implement client registration functionality, allowing clients to provide their identity and public key.

    clients = []

    # Validity period, public key, identity from other parts
    def __init__(self, client_id):
        self.client_id = client_id
        self.identity = None
        self.public_key = None
        self.validity_period = None

    def register_client(self, identity, public_key):

        self.clients.append(
            {
                "id": self.client_id, 
                "identity": self.identity, 
                "pub_key": self.public_key
            }
        )



        
        
        


    