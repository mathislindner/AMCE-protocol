from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import base64
import json

class jws_creator():
    def __init__(self):
        self.private_key, self.public_key = self.get_keys()
        return None
    
    def get_keys(self):
        #create a private key using elliptic curve cryptography
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key
        
    def get_jwk(self):
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": base64.urlsafe_b64encode(self.public_key.public_numbers().x.to_bytes(32, byteorder="big")).decode("utf-8").replace("=", ""),
            "y": base64.urlsafe_b64encode(self.public_key.public_numbers().y.to_bytes(32, byteorder="big")).decode("utf-8").replace("=", "")
        }
    def get_jwk_thumbprint(self):
        return json.dumps({
            'crv': 'P-256',
            'kty': 'EC',
            'x': base64.urlsafe_b64encode(self.public_key.public_numbers().x.to_bytes(32, byteorder="big")).decode("utf-8").replace("=", ""),
            'y': base64.urlsafe_b64encode(self.public_key.public_numbers().y.to_bytes(32, byteorder="big")).decode("utf-8").replace("=", "")
        })
    def get_jwk_thumbprint_encoded(self):
        return base64.urlsafe_b64encode(self.get_jwk_thumbprint().encode("utf-8")).decode("utf-8").replace("=", "")
    
    def get_signature(self, protected_b64, payload_b64):
        """_summary_
        Get the signature
        Returns:
            _type_: str
        """
        #create the signing input
        signing_input = protected_b64 + "." + payload_b64
        #sign the signing input
        signature = self.private_key.sign(signing_input.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        #decode the signature
        r, s = decode_dss_signature(signature)
        #return the signature
        return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
        
    def create_protected_header(self, nonce,url, kid=None):
        """_summary_
        Create the protected header
        Returns:
            _type_: dict
        """
        protected_dict = {
            "alg": "ES256",
            "nonce": nonce,
            "url": url       
        }
        if kid != None:
            protected_dict["kid"] = kid
        else:
            protected_dict["jwk"] = self.get_jwk()
            
        return protected_dict
        
    def get_jws(self, payload_dict, nonce, url, kid=None):
        """_summary_
        Create a jws
        Returns:
            _type_: dict
        """

        protected_dict = self.create_protected_header(nonce, url, kid)
        
        #get the protected header in base64
        protected_b64 = base64.urlsafe_b64encode(json.dumps(protected_dict).encode("utf-8")).decode("utf-8").replace("=", "")
        #get the payload in base64
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_dict).encode("utf-8")).decode("utf-8").replace("=", "")
        #edge case for empty payload
        if payload_dict == {}:
            payload_b64 = ""
        #get the signature
        signature = self.get_signature(protected_b64, payload_b64)
        signature_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").replace("=", "")
        
        #create the jws
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64
        }
        return json.dumps(jws)
    
    def generate_CSR(self, domains):
        """_summary_
        Generate a certificate signing request
        Returns:
            _type_: str
        """
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        #hadnle wildcard domains
        domain = domains[0]
        if domain[0][:2] == "*.":
            domain = domain[0][2:]
        #create the private key
        server_private_key = ec.generate_private_key(ec.SECP256R1())
        #save the private key
        path_private_key = "certs/server_private_key" + domain + ".pem"
        with open(path_private_key, "wb") as f:
            f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))

        #create the csr
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain) for domain in domains
            ]),
            critical=False,
        ).sign(server_private_key, hashes.SHA256(), default_backend())
        #save the csr
        path_csr = "certs/CSR" + domain + ".csr"
        with open(path_csr, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        return path_csr
    