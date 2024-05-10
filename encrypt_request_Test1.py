from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii


class RSAEncryptorDecryptor:
    def __init__(self, key_size=2048):
        self.key_size = key_size

    def generate_key_pair(self):
        # Generate a public/private key pair using the specified key size
        key = RSA.generate(self.key_size)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()

        return self.private_key, self.public_key

    def save_keys_to_files(self, public_key_file, private_key_file):
        # Save public and private keys to files
        with open(public_key_file, 'wb') as file:
            file.write(self.public_key)
        with open(private_key_file, 'wb') as file:
            file.write(self.private_key)

    def encrypt_message(self, message, public_key):
        # Load recipient's public key
        recipient_public_key = RSA.import_key(public_key)

        # Encrypt the message using OAEP padding
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
        encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))

        return encrypted_message

    def decrypt_message(self, encrypted_message, private_key):
        # Load private key
        private_key = RSA.import_key(private_key)

        # Decrypt the encrypted message
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher_rsa.decrypt(encrypted_message)

        return decrypted_message.decode('utf-8')


if __name__ == '__main__':
    # Create an instance of RSAEncryptorDecryptor
    rsa_encryptor_decryptor = RSAEncryptorDecryptor()

    # Generate key pair
    rsa_encryptor_decryptor.generate_key_pair()
    print("Public Key:", rsa_encryptor_decryptor.public_key.decode('utf-8'))
    print("Private Key:", rsa_encryptor_decryptor.private_key.decode('utf-8'))

    # Save public and private keys to files
    rsa_encryptor_decryptor.save_keys_to_files(
        'ca_public_key.txt', 'ca_private_key.txt')
    print("Public and Private Keys saved to 'public_key.txt' and 'private_key.txt'")

    # Example message to be encrypted
    message = "This is a secret message: we want the code nowww!!"
    print("Original Message:", message)

    # Encrypt the message using the recipient's public key
    encrypted_message = rsa_encryptor_decryptor.encrypt_message(
        message, rsa_encryptor_decryptor.public_key)
    print("Encrypted Message:", binascii.hexlify(
        encrypted_message).decode('utf-8'))

    # Decrypt the encrypted message using the recipient's private key
    decrypted_message = rsa_encryptor_decryptor.decrypt_message(
        encrypted_message, rsa_encryptor_decryptor.private_key)
    print("Decrypted Message:", decrypted_message)
