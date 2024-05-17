"""
Group: 2
Authors: Jenny Choi 33945772
         Jay Pardeshi 34023891
         Ibrahim Ibrahim 33669546
         JiaxunYu 28099958
"""
class Client:
    """
    A class to define behaviors of a Client.

    Attributes
    ----------
    N/A

    Methods
    -------
    __str__()
        Method to return the client object in a String form.
    """
    def __init__(self, client_id, private_key, public_key, ca=None):
        """
        Create a Client object.

        :param client_id: the client ID.
        :param private_key: the private key of the client.
        :param public_key: the public key of the client.
        :param ca: certificate authority the client is signed by.
        """
        self.client_id = client_id
        self.private_key = private_key
        self.public_key = public_key
        self.ca = ca

    def __str__(self):
        """
        Method to return the client object in a String form.

        :return return_str: the client object in a String form.
        """
        return_str = "Client ID: " + self.client_id + "\n"
        if self.public_key != "":
            return_str += "Public Key: " + self.public_key[0:40] + "...\n"
        if self.private_key != "":
            return_str += "Private Key: " + self.private_key[0:40] + "...\n"
        return_str += "Certificate Authority: " + self.ca.ca_type + "\n"

        return return_str
