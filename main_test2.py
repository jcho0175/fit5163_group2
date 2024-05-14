import pprint

from certificate_authority import CertificateAuthority
from client import Client
from public_key_cert_system import PublicKeyCertSystem
from csr_handler import CSRHandler

public_key_cert_system = PublicKeyCertSystem()
registered_client_list = []

 
"""
Function a. Implement functionalities for the root CA to generate its own private/public key pair.
"""
def create_CAs():
    
    # a-1. Generate private/public key for the root CA
    print("Creating root CA ....")
    root_private_key, root_public_key = public_key_cert_system.generate_key_pair()

    # a-2. Create root CA object.
    root_ca = CertificateAuthority("root", root_private_key, root_public_key)
    print(".... Root CA created")

    # a-3. Generate key pairs for 2 sub CAs.
    print("Creating sub CAs ....")
    sub1_private_key, sub1_public_key = public_key_cert_system.generate_key_pair()
    sub2_private_key, sub2_public_key = public_key_cert_system.generate_key_pair()

    # a-4. Create 2 sub CAs.
    sub_ca1 = CertificateAuthority("sub-CA1", sub1_private_key, sub1_public_key, root_ca)
    sub_ca2 = CertificateAuthority("sub-CA2", sub2_private_key, sub2_public_key, root_ca)

    # a-5. Add sub CAs to the root CA's subordinate CA list.
    root_ca.add_sub_ca(sub_ca1)
    root_ca.add_sub_ca(sub_ca2)
    print(".... Sub CAs created")

    # a-6. Print info of each CA
    print("\nCertificate authorities created >>>")
    #   a-6-1. Root CA
    print(root_ca.__str__())
    #   a-6-2. Sub CA 1
    print(sub_ca1.__str__())
    #   a-6-3. Sub CA 2
    print(sub_ca2.__str__())

    # a-7. Return the root CA object.
    return root_ca

"""
Function b. Develop functions for issuing certIficates for clients, 
            including necessary attributes such as client ID, public key, and validity period.
"""
def issue_certificate(root_ca, client):
    # b-1. Choose a sub CA to issue certificate from.
    while (True):
        1= input("Please select a sub CA\n1.Sub-CA1\n2.Sub-CA2\nYour choice:")
        if chosen_sub_ca == '1':
            client.ca = root_ca.sub_ca_list[0]
        elif chosen_sub_ca == '2':
            client.ca = root_ca.sub_ca_list[1]
        else:
            print("There are only 2 Sub-CAs in the system.")
            continue
        break
    print("Client Information >>> \n" + client.__str__())
    

    # b-2. Set a validity period (30 days).
    validity_days = 30

    # b-3. Issue certificate for the client.
    print("Issuing certificate ....")
    encrypted_session_key, encrypted_certificate_data, iv, signature = public_key_cert_system.issue_certificate(
        client.client_id, client.public_key, client.ca.private_key, client.ca.public_key, validity_days)
    print(".... Certificate issued")

    # b-4. Print out the certificate.
    print("\n=== Certificate ===")
    decrypted_certificate = public_key_cert_system.decrypt_certificate_data(
        encrypted_certificate_data, encrypted_session_key, iv, client.ca.private_key)
    pprint.PrettyPrinter(width=20).pprint(decrypted_certificate)

"""
Function c. Implement client registration functionality, allowing clients to provide their identity and public key.
"""
def client_registration():
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
    
def client_certificate_request(client, chosen_sub_ca):
    # d-1. Client generate CSR(Certificate Signing request)
    print("\n===== Generating CSR =====")
    client_csr = CSRHandler.generate_csr(client)
    pprint.PrettyPrinter(width=20).pprint(client_csr)

    # d-2. Encryption of CSR.
    print("\n===== Encrypting CSR =====")
    encrypted_csr = CSRHandler.encrypt_csr(client_csr, chosen_sub_ca)
    pprint.PrettyPrinter(width=20).pprint(encrypted_csr)

    # d-3. Submit CSR
    print("\n===== Submitting CSR =====")
    CSRHandler.submit_csr(encrypted_csr)

    # d-4. CA receives and decrypt CSR.
    print("\n===== Receiving and Decrypting CSR =====")
    decrypted_csr = CSRHandler.receive_and_decrypt_csr()
    pprint.PrettyPrinter(width=20).pprint(decrypted_csr)

    return decrypted_csr

    # e-1.Client certificate validation.
    # e-2.Use of Public Key and CA Signature.
    # e-3.Validity Check.

    # d-1.Reasons for Revocation
    # d-2.Certificate Revocation List (CRL)
    # d-1.Checking Revocation Status

    

def start_program():
    
    
    
    """
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
    issue_certificate(root_ca, client)
    #function d
    client_certificate_request(client, chosen_sub_ca)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    start_program()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
