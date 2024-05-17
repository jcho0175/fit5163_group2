"""
Group: 2
Authors: Jenny Choi 33945772
         Jay Pardeshi 34023891
         Ibrahim Ibrahim 33669546
         JiaxunYu 28099958
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta
import json

class PublicKeyCertSystem:
    """
    A class to define behaviors of the public key certificate system.
    Related functionalities for the Crypto package.

    Attributes
    ----------
    N/A

    Methods
    -------
    generate_key_pair()
        Generated RSA key pair (private key & public key).
    generate_key_pair_for_clients(public_key_provided)
        Generated RSA key pair for clients.
    rand_func_for_rsa(n)
        Random function for generating RSA key pair with given String-typed public key.
    random_func(seed)
        Convert a seed value to a byte.
    issue_certificate(client_id, public_key, validity_days, domain_name)
        Issue a certificate.
    generate_session_key()
        Generate a random session key for AES encryption.
    rsa_encrypt(data, public_key)
        Encrypt data using RSA public key.
    rsa_decrypt(encrypted_data, private_key)
        Decrypt data using RSA private key.
    sign_data(data, private_key)
        Sign data using RSA private key.
    aes_encrypt(data, session_key)
        Encrypt data using AES encryption.
    aes_decrypt(encrypted_data, session_key, iv)
        Decrypt data using AES decryption.
    request_encrypt(certificate_data_json, issuer_public_key, issuer_private_key)
        Encrypt certificate data and session key for secure transmission.
    verify_certificate(encrypted_session_key, encrypted_certificate_data, iv, signature,
                           issuer_private_key, issuer_public_key)
        Verify and decrypt the received certificate data.
    verify_signature(data, signature, public_key)
        Verify the signature using the public key.
    """

    # A key for Password-Based Key Derivation Functionality
    master_key = None
    # An incrementing counter variable to be attached to the salt value.
    counter = 0

    def generate_key_pair(self):
        """
        Generated RSA key pair (private key & public key).

        :return private_key: the generated private key.
        :return public_key: the generated public key.
        """
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return private_key, public_key

    # referred https://stackoverflow.com/questions/20483504/making-rsa-keys-from-a-password-in-python
    def generate_key_pair_for_clients(self, public_key_provided):
        """
        Generated RSA key pair for clients.

        :param public_key_provided: the public key client entered as a String object.

        :return private_key: the generated private key.
        :return public_key: the generated public key.
        """
        salt = "fit5163"
        self.master_key = PBKDF2(public_key_provided, salt, count=10000)
        key = RSA.generate(2048, randfunc=self.rand_func_for_rsa)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return private_key, public_key

    def rand_func_for_rsa(self, n):
        """
        Random function for generating RSA key pair with given String-typed public key.

        :param n: modulus (a product of two large prime numbers, p*q) in RSA key generation.

        :return PBKDF2 function: random value generated using PBKDF2.
        """
        # PBKDF2 with count=1 and incrementing salt as deterministic PRNG
        self.counter += 1
        return PBKDF2(self.master_key, "random_func:%d" % self.counter, dkLen=n, count=1)

    def random_func(self, seed):
        """
        Convert a seed value to a byte.

        :param seed: the seed value to be converted.

        :return: the byte representation of the seed value.
        """
        return seed.to_bytes((seed.bit_length() + 7) // 8, byteorder='big')

    def issue_certificate(self, client_id, public_key, validity_days, domain_name):
        """
        Issue a certificate.

        :param client_id: The unique identifier of the client.
        :param public_key: The public key of the one getting certificate issued.
        :param validity_days: The number of days for which the certificate is valid.
        :param domain_name: The domain name associated with the certificate.

        :return: JSON-formatted certificate data.
        """
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
            "valid_to": valid_to.strftime("%Y-%m-%d %H:%M:%S"),
            "domain_name": domain_name
        }

        # certificate_data_bytes = str(certificate_data).encode()
        certificate_data_json = json.dumps(
            certificate_data)  # Serialize to JSON

        return certificate_data_json

    def generate_session_key(self):
        """
        Generate a random session key for AES encryption.

        :return: randomly generated session key of 16 bytes for AES encryption.
        """
        return get_random_bytes(16)  # AES session key (16 bytes)

    def rsa_encrypt(self, data, public_key):
        """
        Encrypt data using RSA public key.

        :param data: data to be encrypted.
        :param public_key: RSA public key used for encryption.

        :return: encrypted data using RSA encryption.
        """
        # convert the string representation of the public key to an RSA public key object
        # otherwise AttributeError: 'str' object has no attribute 'n'
        if isinstance(public_key, str):
            public_key = RSA.import_key(public_key)

        cipher_rsa = PKCS1_OAEP.new(public_key)
        return cipher_rsa.encrypt(data)

    def rsa_decrypt(self, encrypted_data, private_key):
        """
        Decrypt data using RSA private key.

        :param encrypted_data: data to be decrypted.
        :param private_key: RSA private key used for decryption.

        :return: decrypted data using RSA decryption.
        """
        # convert the string representation of the private key to an RSA private key object
        # otherwise AttributeError: 'str' object has no attribute 'n'
        if isinstance(private_key, str):
            private_key = RSA.import_key(private_key)

        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(encrypted_data)

    def sign_data(self, data, private_key):
        """
        Sign data using RSA private key.

        :param data: data to be signed.
        :param private_key: RSA private key used for signing.

        :return: signature of the data using RSA signature.
        """
        # convert the string representation of the private key to an RSA private key object
        # otherwise AttributeError: 'str' object has no attribute 'n'
        if isinstance(private_key, str):
            private_key = RSA.import_key(private_key)

        h = SHA256.new(data)
        signature = pkcs1_15.new(private_key).sign(h)
        return signature

    def aes_encrypt(self, data, session_key):
        """
        Encrypt data using AES encryption.

        :param data: data to be encrypted.
        :param session_key: session key used for AES encryption.

        :return ct_bytes: encrypted data.
        :return cipher_aes.iv: initialization vector used for AES encryption.
        """
        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        ct_bytes = cipher_aes.encrypt(pad(data, AES.block_size))
        return ct_bytes, cipher_aes.iv

    def aes_decrypt(self, encrypted_data, session_key, iv):
        """
        Decrypt data using AES decryption.

        :param encrypted_data: data to be decrypted.
        :param session_key: session key used for AES decryption.
        :param iv: initialization vector used for AES decryption.

        :return: decrypted data using AES decryption.
        """
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        return unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)

    # encryption using RSA with a session key (AES)
    # referred https://lists.dlitz.net/pipermail/pycrypto/2012q2/000574.html
    def request_encrypt(self, certificate_data_json, issuer_public_key, issuer_private_key):
        """
        Encrypt certificate data and session key for secure transmission.

        :param certificate_data_json: JSON-formatted certificate data.
        :param issuer_public_key: public key of the certificate issuer.
        :param issuer_private_key: private key of the certificate issuer.

        :return encrypted_certificate_data: encrypted certificate data
        :return iv: initialization vector
        :return signature: the signature added
        :return encrypted_session_key: encrypted session key
        """
        # generate session key
        session_key = self.generate_session_key()
        print("     Session key created")

        # adding signature to the certificate
        signature = self.sign_data(
            certificate_data_json.encode('utf-8'), issuer_private_key)
        print("     Signature added")

        # encrypt the certificate data with AES
        encrypted_certificate_data, iv = self.aes_encrypt(
            certificate_data_json.encode(), session_key)
        print("     Certificate encrypted")

        # encrypt session key with RSA
        encrypted_session_key = self.rsa_encrypt(
            session_key, issuer_public_key)
        print("     Session key encrypted")

        # return encrypted session key, encrypted certificate data, iv, and signature
        return encrypted_certificate_data, iv, signature, encrypted_session_key

    def verify_certificate(self, encrypted_session_key, encrypted_certificate_data, iv, signature,
                           issuer_private_key, issuer_public_key):
        """
        Verify and decrypt the received certificate data.

        :param encrypted_session_key: encrypted session key.
        :param encrypted_certificate_data: encrypted certificate data.
        :param iv: initialization vector used for AES encryption.
        :param signature: signature of the encrypted certificate data.
        :param issuer_private_key: private key of the certificate issuer.
        :param issuer_public_key: public key of the certificate issuer.

        :return (True or False): verification result
        :return certificate_data['client_id']: client ID
        :return public_key: reconstructed public key
        """
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

    def verify_signature(self, data, signature, public_key):
        """
        Verify the signature using the public key.

        :param data: data to be verified.
        :param signature: signature to be verified.
        :param public_key: public key used for signature verification.

        :return: True if the signature is verified, False if not.
        """
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
