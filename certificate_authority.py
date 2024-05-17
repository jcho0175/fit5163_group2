from Crypto.PublicKey import RSA
from datetime import datetime, timedelta
import json

class CertificateAuthority:
    def __init__(self, ca_type="", private_key="", public_key="", cert_from=None):
        self.ca_type = ca_type
        self.cert_from = cert_from
        self.private_key = private_key
        self.public_key = public_key
        self.sub_ca_list = []
        self.encrypted_cert = None
        self.signature = None

    def __str__(self):
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

    revoked_certificates = {}  # Dictionary to store revoked certificates {certificate_id: reason}

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
        self.sub_ca_list.append(sub_ca)
