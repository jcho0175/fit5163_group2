"""
Group: 2
Authors: Jenny Choi 33945772
         Jay Pardeshi 34023891
         Ibrahim Ibrahim 33669546
         JiaxunYu 28099958
Topic:
    Design a public key certificate system that involves one root CA, two sub-CA and three clients.

Suggestions:
    1) Add more fields in certificate ex) domain name / student id (implemented on May 17, 2024)
    2) Chain of verification: root - sub ca - client (implemented on May 17, 2024)
        Root CA: having its own certificate with digital signature
        Sub CA: having certificate signed by Root CA (need to have digital signature of the root CA)
        client: having certificate signed by a sub CA
    3) No need to choose sub CA (implemented on May 17, 2024)
    4) Revocation by root authority
"""

import json
from random import choice

from certificate_authority import CertificateAuthority
from client import Client
from public_key_cert_system import PublicKeyCertSystem

# Logic class
public_key_cert_system = PublicKeyCertSystem()
# List of client Registered
registered_client_list = []
# Default validity days
validity_days = 365
# Default domain name
domain_name = "student.monash.edu"

"""
Function a. Implement functionalities for the root CA to generate its own private/public key pair.
"""
def create_CAs():
    """
    Create one root CA and it 2 sub-CAs.
    """
    # a-1. Generate private/public key for the root CA
    print("Creating root CA ....")
    root_private_key, root_public_key = public_key_cert_system.generate_key_pair()

    # a-2. Creat root CA object.
    root_ca = CertificateAuthority("root", root_private_key, root_public_key)
    print(".... Root CA created")

    # a-3. Generate key pairs for 2 sub CAs.
    print("Creating sub CAs ....")
    sub1_private_key, sub1_public_key = public_key_cert_system.generate_key_pair()
    sub2_private_key, sub2_public_key = public_key_cert_system.generate_key_pair()

    # a-4. Create 2 sub CAs.
    sub_ca1 = CertificateAuthority("sub-CA1", sub1_private_key, sub1_public_key, root_ca)
    sub_ca2 = CertificateAuthority("sub-CA2", sub2_private_key, sub2_public_key, root_ca)

    # a-5. Create certificates and signature for Root CA
    root_ca_cert = public_key_cert_system.issue_certificate(
        "root_ca", root_public_key, validity_days, domain_name)
    root_encrypted_certificate_data, root_iv, root_signature, root_encrypted_session_key = public_key_cert_system.request_encrypt(
        root_ca_cert, root_public_key, root_private_key)

    root_ca.encrypted_cert = root_encrypted_certificate_data
    root_ca.signature = root_signature

    # a-6. Create certificates and signature for sub CAs (Sub-CAs' certificates: signed by the root).
    #   a-6-1. Sub CA 1
    sub_ca1_cert = public_key_cert_system.issue_certificate(
        "sub_ca1", sub1_public_key, validity_days, domain_name)
    sub1_encrypted_certificate_data, sub1_iv, sub1_signature, sub1_encrypted_session_key = public_key_cert_system.request_encrypt(
        sub_ca1_cert, root_public_key, root_private_key)

    sub_ca1.encrypted_cert = sub1_encrypted_certificate_data
    sub_ca1.signature = sub1_signature

    #   a-6-2. Sub CA 2
    sub_ca2_cert = public_key_cert_system.issue_certificate(
        "sub_ca2", sub2_public_key, validity_days, domain_name)
    sub2_encrypted_certificate_data, sub2_iv, sub2_signature, sub2_encrypted_session_key = public_key_cert_system.request_encrypt(
        sub_ca2_cert, root_public_key, root_private_key)

    sub_ca2.encrypted_cert = sub2_encrypted_certificate_data
    sub_ca2.signature = sub2_signature

    # a-7. Add sub CAs to the root CA's subordinate CA list.
    root_ca.add_sub_ca(sub_ca1)
    root_ca.add_sub_ca(sub_ca2)
    print(".... Sub CAs created")

    # a-8. Print info of each CA
    print("\nCertificate authorities created >>>")
    #   a-8-1. Root CA
    print(root_ca.__str__())
    #   a-8-2. Sub CA 1
    print(sub_ca1.__str__())
    #   a-8-3. Sub CA 2
    print(sub_ca2.__str__())

    # a-9. Return the root CA object.
    return root_ca

"""
Function b. Develop functions for issuing certIficates for clients, 
            including necessary attributes such as client ID, public key, and validity period.
"""
def issue_certificate(root_ca, client):
    """
    Issue the certificate for the client.
    :param root_ca: Root CA object.
    :param client: Client object.
    """
    # b-1. Choose a sub CA randomly to issue certificate from.
    client.ca = choice(root_ca.sub_ca_list)

    print()
    print("Client Information >>> \n" + client.__str__())

    # b-2. Issue certificate for the client.
    print("Issuing certificate ....")
    certificate_data_json = public_key_cert_system.issue_certificate(
        client.client_id, client.public_key, validity_days, domain_name)
    print(".... Certificate issued")

    # b-3. Print out the certificate.
    print("\n=== Certificate ===")
    print(certificate_data_json)
    return client, certificate_data_json

"""
Function c. Implement client registration functionality, allowing clients to provide their identity and public key.
"""
def client_registration():
    """
    Register a client to the system.
    """
    # c-1. Client provides their identity.
    while (True):
        client_id = input("Please enter your client ID to register: ").strip()
        if client_id == "":
            print("Empty string cannot be a client ID.")
            continue
        else:
            break

    # c-2. Client provides their public key.
    while (True):
        public_key_provided = input("Please enter your public key to register: ").strip()
        if public_key_provided == "":
            print("Empty string cannot be a public key.")
            continue
        else:
            break

    # c-3. Generate key pair for the client.
    print("Generating key pair ....")
    private_key, public_key = public_key_cert_system.generate_key_pair_for_clients(public_key_provided)
    print(".... Key pair generated")
    print()

    # c-4. Register client.
    if len(registered_client_list) == 3:
        # 3 clients only.
        print("System only accepts up to 3 clients.\nPlease try again.")
        return None
    else:
        client = Client(client_id, private_key, public_key)
        registered_client_list.append(client)
        print("Registered successfully: Client ID [", client_id, "]")
        return client

def start_program():
    """
    Method to start the program.
    System specifications:
        a. Implement functionalities for the root CA to generate its own private/public key pair.

        b. Develop functions for issuing certificates for clients, including necessary
        attributes such as client ID, public key, and validity period.

        c. Implement client registration functionality, allowing clients to provide their identity and public key.

        d. Develop a mechanism for clients to submit certificate requests to the CA. The request should be encrypted.

        e. Develop methods for validating certificates using the corresponding public keys and CA signatures.

        f. Implement mechanisms for certificate revocation in case of compromise or expiration.
    """
    print("===== FIT5163 Group2: Public key certificate system =====")
    # Function a
    root_ca = create_CAs()
    # Function c
    client = client_registration()
    # Function b
    client, certificate_data_json = issue_certificate(root_ca, client)
    print("=== Client Info ===")
    print("Client CA: ", client.ca.ca_type)
    print("Client public key: ", client.public_key)
    print("Client private key: ", client.private_key)

    sub_ca_list = root_ca.sub_ca_list
    client_sub_ca = CertificateAuthority()
    for sub_ca in sub_ca_list:
        if sub_ca.ca_type == client.ca.ca_type:
            client_sub_ca = sub_ca
            break
    print("Sub-ca public key: ", client_sub_ca.public_key)
    print("Sub-ca private key: ", client_sub_ca.private_key)

    # Function d
    print()
    print("Request certificate encryption ....")
    encrypted_certificate_data, iv, signature, encrypted_session_key = public_key_cert_system.request_encrypt(
        certificate_data_json, client_sub_ca.public_key, client_sub_ca.private_key)
    print(".... Encrypted successfully")

    # Function e
    print()
    is_valid, client_id, client_public_key = public_key_cert_system.verify_certificate(
        encrypted_session_key,
        encrypted_certificate_data,
        iv,
        signature,
        client_sub_ca.private_key,
        client_sub_ca.public_key
    )

    if is_valid:
        print("Certificate is valid.")
        print("Client ID:", client_id)
        print("Client Public Key:", client_public_key.export_key())
    else:
        print("Certificate is not valid.")

    # Function f: Revoking a certificate (for demonstration purposes)
    # Check revocation status
    print()
    certificate_dict = json.loads(certificate_data_json)
    revoked, reason = root_ca.check_revocation_status(client_id, certificate_dict["valid_to"])
    if revoked:
        print(f"The certificate {client_id} is revoked or expired due to: {reason}")
    else:
        print(f"The certificate {client_id} is not revoked.")

    # Revoking a certificate (for demonstration purposes)
    certificate_id_to_revoke = input("Enter the client ID of the certificate to revoke (if any): ")
    if certificate_id_to_revoke:
        reason_for_revocation = input("Enter the reason for revocation: ")
        root_ca.revoke_certificate(certificate_id_to_revoke, reason_for_revocation)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    start_program()

