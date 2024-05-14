from datetime import datetime

class CertificateAuthority:
    def __init__(self, admin_token):
        self.admin_token = admin_token
        self.revoked_certificates = {}

    def revoke_certificate(self, certificate_id, reason="Compromised", auth_token=None):
        if auth_token != self.admin_token:
            print("Unauthorized to revoke certificates.")
            return

        if certificate_id in self.revoked_certificates:
            print("Certificate is already revoked.")
        else:
            # Store the revocation record
            self.revoked_certificates[certificate_id] = {
                'reason': reason,
                'timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            }
            print("Certificate revoked successfully.")

    def is_certificate_revoked(self, certificate_id):
        return certificate_id in self.revoked_certificates

    def check_revocation_status(self, certificate_id):
        if certificate_id in self.revoked_certificates:
            return True, self.revoked_certificates[certificate_id]['reason']
        else:
            return False, None

# Example usage
ca = CertificateAuthority(admin_token="your_admin_token")
certificate_id = "123456789"
auth_token = "admin_token"  # Replace with the appropriate admin token
ca.revoke_certificate(certificate_id, auth_token=auth_token)

# Check revocation status
revoked, reason = ca.check_revocation_status(certificate_id)
if revoked:
    print(f"The certificate {certificate_id} is revoked due to: {reason}")
else:
    print(f"The certificate {certificate_id} is not revoked.")
