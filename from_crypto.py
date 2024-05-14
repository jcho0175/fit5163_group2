from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import binascii

def generate_key_pair():
    # Generate a public/private key pair using 2048 bits key length (256 bytes)
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_certificate_request(request, public_key):
    # Load CA public key
    ca_public_key = RSA.import_key(public_key)

    # Encrypt the certificate request using OAEP padding
    cipher_rsa = PKCS1_OAEP.new(ca_public_key)
    encrypted_request = cipher_rsa.encrypt(request)

    # Return the encrypted request
    return encrypted_request

def decrypt_certificate_request(encrypted_request, private_key):
    # Load CA private key
    ca_private_key = RSA.import_key(private_key)

    # Decrypt the encrypted certificate request
    cipher_rsa = PKCS1_OAEP.new(ca_private_key)
    decrypted_request = cipher_rsa.decrypt(encrypted_request)

    # Return the decrypted request
    return decrypted_request

if __name__ == '__main__':
    # Generate CA key pair
    ca_private_key, ca_public_key = generate_key_pair()
    print("CA Private Key:", ca_private_key.decode('utf-8'))
    print("CA Public Key:", ca_public_key.decode('utf-8'))

    # Client generates certificate request
    client_request = b"This is a certificate request from the client"
    print("Client Certificate Request:", client_request.decode('utf-8'))

    # Encrypt the certificate request using CA public key
    encrypted_request = encrypt_certificate_request(client_request, ca_public_key)
    print("Encrypted Certificate Request:", binascii.hexlify(encrypted_request).decode('utf-8'))

    # CA decrypts the certificate request using its private key
    decrypted_request = decrypt_certificate_request(encrypted_request, ca_private_key)
    print("Decrypted Certificate Request:", decrypted_request.decode('utf-8'))
