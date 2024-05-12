from Crypto.PublicKey import RSA
from datetime import datetime, timedelta
import json

class CertificateAuthority:
    def __init__(self, ca_type, private_key, public_key, cert_from=None):
        self.ca_type = ca_type
        self.cert_from = cert_from
        self.private_key = private_key
        self.public_key = public_key
        self.sub_ca_list = []

    def __str__(self):
        return_str = "Authority type: " + self.ca_type + "\n"
        if self.cert_from is not None:
            return_str += "Parent Authority: " + self.cert_from.ca_type + "\n"
        if self.public_key != "":
            return_str += "Public Key: generated\n"
        if self.private_key != "":
            return_str += "Private Key: generated\n"
        if len(self.sub_ca_list) > 0:
            return_str += "Subordinate CAs:\n"
            for sub_ca in self.sub_ca_list:
                return_str += "     " + sub_ca.ca_type + "\n"

        return return_str

    def add_sub_ca(self, sub_ca):
        self.sub_ca_list.append(sub_ca)
