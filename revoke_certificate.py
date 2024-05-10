
class RevokeCertificate:

    revoked_certificate = []

    def revoke_certificate(self, identity, public_key, certificate):
        certificate = {
            "identity": identity,
            "pub_key": public_key,
            "certificate": certificate.certificate_data,
            "iv": certificate.iv,
            "signature": certificate.signature
        }
        certificate.append(certificate)

    def is_revoked(self, identity, public_key, certificate):
        if (identity, public_key, certificate.certificate_dat) in self.revoked_certificate:
            return True
        return False
