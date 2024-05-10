from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta
import json
import hashlib


class IssueCertificate():

    def generate_key_pair(self):
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return private_key, public_key

    def generate_session_key(self):
        return get_random_bytes(16)  # AES session key (16 bytes)

    def rsa_encrypt(self, data, public_key):
        # convert the string representation of the public key to an RSA public key object
        # otherwise AttributeError: 'str' object has no attribute 'n'
        if isinstance(public_key, str):
            public_key = RSA.import_key(public_key)

        cipher_rsa = PKCS1_OAEP.new(public_key)
        return cipher_rsa.encrypt(data)

    def rsa_decrypt(self, encrypted_data, private_key):
        # convert the string representation of the private key to an RSA private key object
        # otherwise AttributeError: 'str' object has no attribute 'n'
        if isinstance(private_key, str):
            private_key = RSA.import_key(private_key)

        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(encrypted_data)

    def aes_encrypt(self, data, session_key):
        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        ct_bytes = cipher_aes.encrypt(pad(data, AES.block_size))
        return ct_bytes, cipher_aes.iv

    def aes_decrypt(self, encrypted_data, session_key, iv):
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        return unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)

    def sign_data(self, data, private_key):
        # convert the string representation of the private key to an RSA private key object
        # otherwise AttributeError: 'str' object has no attribute 'n'
        if isinstance(private_key, str):
            private_key = RSA.import_key(private_key)

        # Not working
        h = SHA256.new(data)
        signature = pkcs1_15.new(private_key).sign(h)
        return signature

    def verify_signature(self, data, signature, public_key):
        if isinstance(public_key, str):
            public_key = RSA.import_key(public_key)
        h = SHA256.new(data)
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            print('Signature Verified')
            return True
        except Exception as e:
            print('Signature not verified', str(e))
            return False

    def verify_certificate(self, encrypted_session_key, encrypted_certificate_data, iv, signature, issuer_private_key, issuer_public_key):
        # decrypt session key with RSA
        session_key = self.rsa_decrypt(
            encrypted_session_key, issuer_private_key)

        # decrypt certificate data with AES
        decrypted_certificate_data = self.aes_decrypt(
            encrypted_certificate_data, session_key, iv)

        # verify signature
        if not self.verify_signature(decrypted_certificate_data, signature, issuer_public_key):
            return False, None, None

        # convert decrypted certificate data to dictionary
        # NameError: name 'RsaKey' is not defined
        # certificate_data = eval(decrypted_certificate_data.decode())
        try:
            certificate_data = json.loads(decrypted_certificate_data.decode())
        except json.JSONDecodeError as e:
            print('json.JSONDecodeError: ', str(e))
            return False, None, None

        # check validity period
        valid_from = datetime.strptime(
            certificate_data['valid_from'], "%Y-%m-%d %H:%M:%S")
        valid_to = datetime.strptime(
            certificate_data['valid_to'], "%Y-%m-%d %H:%M:%S")
        current_time = datetime.utcnow()

        if not (valid_from <= current_time <= valid_to):
            return False, None, None

        # reconstruct RSA public key from components
        public_key_components = certificate_data['public_key']
        public_key = RSA.construct(
            (public_key_components['n'], public_key_components['e']))

        # return client ID, public key, and certificate data
        return True, certificate_data['client_id'], public_key

    """
    # issue certificate using only public key libraries
    def issue_certificate(self, client_id, public_key, issuer_private_key, validity_days):
        # RSA public key
        public_key_obj = RSA.import_key(public_key)

        # validity period
        valid_from = datetime.utcnow()
        valid_to = valid_from + timedelta(days=validity_days)

        # certificate data including client ID, public key, and validity period.
        certificate_data = {
            "client_id": client_id,
            "public_key": public_key_obj,
            "valid_from": valid_from.strftime("%Y-%m-%d %H:%M:%S"),
            "valid_to": valid_to.strftime("%Y-%m-%d %H:%M:%S")
        }

        # sign the certificate with the issuer's private key
        cipher = PKCS1_OAEP.new(RSA.import_key(issuer_private_key))

        # "Plaintext is too long" error
        return cipher.encrypt(str(certificate_data).encode())
    """
    # issue certificate using public key libraries with a session key (AES)
    # referred https://lists.dlitz.net/pipermail/pycrypto/2012q2/000574.html

    def issue_certificate(self, client_id, public_key, issuer_private_key, issuer_public_key, validity_days):
        # generate session key
        session_key = self.generate_session_key()

        # encrypt session key with RSA
        encrypted_session_key = self.rsa_encrypt(
            session_key, issuer_public_key)

        # validity period
        valid_from = datetime.utcnow()
        valid_to = valid_from + timedelta(days=validity_days)

        # RSA public key
        public_key_obj = RSA.import_key(public_key)

        # export RSA public key to components
        public_key_components = {
            'n': public_key_obj.n,
            'e': public_key_obj.e
        }

        # certificate data including client ID, public key, and validity period.
        certificate_data = {
            "client_id": client_id,
            "public_key": public_key_components,
            "valid_from": valid_from.strftime("%Y-%m-%d %H:%M:%S"),
            "valid_to": valid_to.strftime("%Y-%m-%d %H:%M:%S")
        }
        # certificate_data_bytes = str(certificate_data).encode()
        certificate_data_json = json.dumps(
            certificate_data)  # Serialize to JSON

        # sign the certificate data
        signature = self.sign_data(
            certificate_data_json.encode('utf-8'), issuer_private_key)

        # encrypt the certificate data with AES
        encrypted_certificate_data, iv = self.aes_encrypt(
            certificate_data_json.encode(), session_key)

        # return encrypted session key, encrypted certificate data, iv, and signature
        return encrypted_session_key, encrypted_certificate_data, iv, signature

    def test(self):
        # one root CA
        root_private_key, root_public_key = self.generate_key_pair()

        # two sub-CA
        subca1_private_key, subca1_public_key = self.generate_key_pair()
        subca2_private_key, subca2_public_key = self.generate_key_pair()

        # three clients
        client1_private_key, client1_public_key = self.generate_key_pair()
        client2_private_key, client2_public_key = self.generate_key_pair()
        client3_private_key, client3_public_key = self.generate_key_pair()

        # issue certificates for clients
        #   client 1 with sub-CA1, valid for 30 days
        client1_cert = self.issue_certificate(
            "Client1", client1_public_key, subca1_private_key, subca1_public_key, 30)
        #   client 2 with sub-CA1, valid for 90 days
        client2_cert = self.issue_certificate(
            "Client2", client2_public_key, subca1_private_key, subca1_public_key, 90)
        #   client 3 with sub-CA2 private key, valid for 365 days
        client3_cert = self.issue_certificate(
            "Client3", client3_public_key, subca2_private_key, subca2_public_key, 365)

        # verify the certificate for client 1
        is_valid, client_id, client_public_key = self.verify_certificate(
            client1_cert[0],
            client1_cert[1],
            client1_cert[2],
            client1_cert[3],
            subca1_private_key,
            subca1_public_key
        )

        if is_valid:
            print("Certificate is valid.")
            print("Client ID:", client_id)
            print("Client Public Key:", client_public_key.export_key())
        else:
            print("Certificate is not valid.")
