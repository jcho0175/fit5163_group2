# This is a sample Python script.
import pprint
import json
from CertificateAuthority import CertificateAuthority
from Client import Client
from PublicKeyCertSystem import PublicKeyCertSystem
from task2 import HybridEncrypt
from validator import CertificateValidator
from Crypto.PublicKey import RSA

public_key_cert_system = PublicKeyCertSystem()
registered_client_list = []

"""
Function a. Implement functionalities for the root CA to generate its own private/public key pair.
"""
def create_CAs():
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
        chosen_sub_ca = input("Please select a sub CA\n1.Sub-CA1\n2.Sub-CA2\nYour choice:")
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

   
    
    return client, decrypted_certificate

    

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
    
def request_encrypt(client, sub_ca_pu, sub_ca_pr, decrypted_certificate):
    try:
        # Retrieve client information
        print("\n-- Now encrypting certificate --")
        if registered_client_list:  
            # Convert the decrypted_certificate to a dictionary if it's a string
            if isinstance(decrypted_certificate, str):
                decrypted_cert = json.loads(decrypted_certificate)
            else:
                decrypted_cert = decrypted_certificate

            print("Decrypted Certificate Request:", decrypted_cert)
            print("Type of Decrypted Certificate:", type(decrypted_cert))

            # Encrypt the certificate request using hybrid encryption
            encrypted_aes_key, nonce, aes_tag, encrypted_request = HybridEncrypt.encrypt_certificate_request(json.dumps(decrypted_cert), sub_ca_pu)

            # Send the encrypted request to CA
            HybridEncrypt.send_encrypted_request_to_ca(encrypted_request)

            # Decrypt the encrypted request
            decrypted_cert = HybridEncrypt.decrypt_certificate_request(encrypted_aes_key, nonce, aes_tag, encrypted_request, sub_ca_pr)

            print("Decrypted Certificate Request:", decrypted_cert)
            print("Type of Decrypted Certificate:", type(decrypted_cert))

            #  decrypted_cert is a dictionary
            if isinstance(decrypted_cert, str):
                decrypted_cert = json.loads(decrypted_cert)

            # Generate CA signature for the decrypted certificate
            print("\n-- Now generating signature --")
            signature = HybridEncrypt.generate_ca_signature(decrypted_cert, sub_ca_pr)
            signature = '121ese1123sd'
            # Attach CA signature to the decrypted certificate
            print("\n-- Now attaching signature to certificate --")
            decrypted_cert_with_signature = HybridEncrypt.attach_ca_signature(decrypted_cert, signature)
            print(decrypted_cert_with_signature)
            
            # Extract the signature from the certificate
            signature = decrypted_cert_with_signature.get('signature')
            

            return decrypted_cert_with_signature
        else:
            print("No clients registered. Please register a client first.")
        
    except Exception as e:
        print("Error:", e)



        

def validation(decrypted_cert_with_signature, client_sub_ca_pu,signature):
   # Validate the certificate with CA signature
        print("\n-- Now extracting certificate data --")
        # Extract the signature from the certificate
        
        valid_cert = CertificateValidator.validate_certificate(decrypted_cert_with_signature, client_sub_ca_pu,signature)
            
        if valid_cert:
            print("Certificate is valid.")
        else:
            print("Certificate validation failed.")

#def revoke(certificate_id, reason="Compromised", auth_token=None):
 #   ca_instance = CertificateAuthority()  # Create an instance of the CertificateAuthority class
    # Create an instance of the CertificateAuthority class with the required parameters
  #  ca_type = 
  #  private_key = "your_private_key"
  #  public_key = "your_public_key"
   # ca_instance = CertificateAuthority(ca_type, private_key, public_key)
    # Revoke a certificate using the instance
   # ca_instance.revoke_certificate(certificate_id, reason, auth_token)

    # Check revocation status
   # revoked, reason = ca_instance.check_revocation_status(certificate_id)
    #if revoked:
 #       print(f"The certificate {certificate_id} is revoked due to: {reason}")
   # else:
   #     print(f"The certificate {certificate_id} is not revoked.")





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
    # Function a
    root_ca = create_CAs()
    # Function c
    
    client = client_registration()
    
    # Function b
    client, decrypted_certificate = issue_certificate(root_ca, client)
    print("client CA: ", client.ca.__str__)
    print("client public key: ", client.public_key)
    print("client private key: ", client.private_key)

    sub_ca_list = root_ca.sub_ca_list
    
    for sub_ca in sub_ca_list:
        if sub_ca.ca_type == client.ca:
            client_sub_ca = sub_ca
            
            break
    print("sub ca public key: ", sub_ca.public_key)
    print("sub ca private key: ", sub_ca.private_key)

    client_sub_ca_pu = sub_ca.public_key
    sub_ca_pr = sub_ca.private_key

    if client_sub_ca_pu:
        # Call request_encrypt() with the selected client and sub-CA
        decrypted_cert_with_signature = request_encrypt(client, client_sub_ca_pu, sub_ca_pr, decrypted_certificate)
        # Extract the signature from the decrypted certificate with signature
        signature = decrypted_cert_with_signature.get('signature')
        # Call the validation function
        val = validation(decrypted_cert_with_signature, client_sub_ca_pu, signature)
    else:
        print("Sub-CA not found for the client.")
        
    print(registered_client_list)
    



    




# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    start_program()