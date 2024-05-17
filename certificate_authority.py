"""
Group: 2
Authors: Jenny Choi 33945772
         Jay Pardeshi 34023891
         Ibrahim Ibrahim 33669546
         JiaxunYu 28099958
"""
from datetime import datetime

class CertificateAuthority:
    """
    A class to define behaviors of a Certificate Authority.

    Attributes
    ----------
    N/A

    Methods
    -------
    __str__()
        Method to return the CertificateAuthority object in a String form.
    revoke_certificate(certificate_id, reason)
        Revoke a certificate.
    check_revocation_status(certificate_id, valid_to)
        Check if a certificate is revoked or expired.
    add_sub_ca(sub_ca)
        Method to add a sub-CA to the CertificateAuthority object.
    """

    # Dictionary to store revoked certificates {certificate_id: reason}
    revoked_certificates = {}

    def __init__(self, ca_type="", private_key="", public_key="", cert_from=None):
        """
        Create a CertificateAuthority object.

        :param ca_type: the identity of the CA.
        :param private_key: the private key of the CA.
        :param public_key: the public key of the CA.
        :param cert_from: certificate authority the CA is signed by.
        """
        self.ca_type = ca_type
        self.cert_from = cert_from
        self.private_key = private_key
        self.public_key = public_key
        self.sub_ca_list = []
        self.encrypted_cert = None
        self.signature = None

    def __str__(self):
        """
        Method to return the CertificateAuthority object in a String form.

        :return return_str: the CertificateAuthority object in a String form.
        """
        return_str = "Authority type: " + self.ca_type + "\n"
        if self.cert_from is not None:
            return_str += "Parent Authority: " + self.cert_from.ca_type + "\n"
        if self.public_key != "":
            return_str += "Public Key: " + self.public_key[0:40] + "...\n"
        if self.private_key != "":
            return_str += "Private Key: " + self.private_key[0:40] + "...\n"
        if len(self.sub_ca_list) > 0:
            return_str += "Subordinate CAs:\n"
            for sub_ca in self.sub_ca_list:
                return_str += "     " + sub_ca.ca_type + "\n"

        return return_str

    def revoke_certificate(self, certificate_id, reason):
        """
        Revoke a certificate.

        :param certificate_id: ID of the certificate to be revoked.
        :param reason: Reason for revocation.
        """
        self.revoked_certificates[certificate_id] = reason
        print(f"Certificate {certificate_id} revoked due to: {reason}")

    def check_revocation_status(self, certificate_id, valid_to):
        """
        Check if a certificate is revoked or expired.

        :param certificate_id: ID of the certificate to check.
        :param valid_to: Expiry date of the certificate.

        :return: True if the certificate is revoked or expired, False otherwise. Also, return the reason if revoked.
        """
        current_time = datetime.utcnow()
        if certificate_id in self.revoked_certificates:
            return True, self.revoked_certificates[certificate_id]

        valid_to_date = datetime.strptime(valid_to, "%Y-%m-%d %H:%M:%S")
        if current_time > valid_to_date:
            return True, "Expired"

        return False, None

    def add_sub_ca(self, sub_ca):
        """
        Method to add a sub-CA to the CertificateAuthority object.

        :param sub_ca: a sub-CA object to add to the sub-CA list.
        """
        self.sub_ca_list.append(sub_ca)
