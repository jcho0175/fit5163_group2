class Client:
    def __init__(self, client_id, private_key, public_key, ca=None):
        self.client_id = client_id
        self.private_key = private_key
        self.public_key = public_key
        self.ca = ca

    def __str__(self):
        return_str = "Client ID: " + self.client_id + "\n"
        if self.public_key != "":
            return_str += "Public Key: generated\n"
        if self.private_key != "":
            return_str += "Private Key: generated\n"
        return_str += "Certificate Authority: " + self.ca.ca_type + "\n"

        return return_str
