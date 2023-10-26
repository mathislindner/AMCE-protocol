import requests
import json
#CRYPTOGRAPHY
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import base64

class Authentificator():
    def __init__(self):
        self.private_key, self.public_key = self.create_keys()
        self.jwk = self.set_jwk()
        self.jwk_thumbprint = self.set_jwk_thumbprint()
        
    def create_keys(self):
        """_summary_
        Create the keys
        Returns:
            _type_: tuple
        """
        #create a private key using elliptic curve cryptography
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key
        
    def set_jwk(self):
        """_summary_
        Get the jwk
        Returns:
            _type_: dict
        """
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": base64.urlsafe_b64encode(self.public_key.public_numbers().x.to_bytes(32, byteorder="big")).decode("utf-8").replace("=", ""),
            "y": base64.urlsafe_b64encode(self.public_key.public_numbers().y.to_bytes(32, byteorder="big")).decode("utf-8").replace("=", "")
        }
        
    def set_jwk_thumbprint(self):
        """_summary_
        Get the jwk thumbprint
        Returns:
            _type_: str
        """
        return json.dumps({
            'crv': 'P-256',
            'kty': 'EC',
            'x': base64.urlsafe_b64encode(self.public_key.public_numbers().x.to_bytes(32, byteorder="big")).decode("utf-8").replace("=", ""),
            'y': base64.urlsafe_b64encode(self.public_key.public_numbers().y.to_bytes(32, byteorder="big")).decode("utf-8").replace("=", "")
        })
        
    def sign(self, protected_dict, payload_dict):
        """_summary_
        Sign the payload
        Returns:
            _type_: str
        """
        protected_b64 = base64.urlsafe_b64encode(json.dumps(protected_dict).encode("utf-8")).decode("utf-8").replace("=", "")
        #get the payload in base64
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_dict).encode("utf-8")).decode("utf-8").replace("=", "")
        #edge case for empty payload
        if payload_dict == {}:
            payload_b64 = ""
            
        #create the signing input
        signing_input = protected_b64 + "." + payload_b64
        #sign the signing input
        signature = self.private_key.sign(signing_input.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        #decode the signature
        r, s = decode_dss_signature(signature)
        signature =  r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
        signature_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").replace("=", "")
        
        #create jws
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64
        }
        return json.dumps(jws).encode("utf-8")

class Client():
    def __init__(self, dir_url, pem_path, record):
        self.pem_path = pem_path
        self.record = record
        self.CA_domains = requests.get(dir_url, verify=self.pem_path).json()
        self.authentificator = Authentificator()
        self.nonce = requests.head(self.CA_domains["newNonce"], verify=self.pem_path).headers["Replay-Nonce"]
        
        self.dns_address = "http://" + record + ":10035"
        self.http_address = "http://" + record + ":5002"
        
        self.kid = self.create_account()
        
    def create_account(self):
        """_summary_
            creates an account, returns the jik
        """
        headers = {
            "Content-Type": "application/jose+json"
        }
        #create the payload
        payload_for_new_acc = {
            "termsOfServiceAgreed": True
        }
        #create the protected header
        protected_for_new_acc = {
            "alg": "ES256",
            "jwk": self.authentificator.jwk, #since we don t have a jik yet...
            "nonce": self.nonce,
            "url": self.CA_domains["newAccount"]
        }
        signed_payload = self.authentificator.sign(protected_for_new_acc, payload_for_new_acc)
        #create the request
        response = requests.post(self.CA_domains["newAccount"], headers=headers, data=signed_payload, verify=self.pem_path)
        #update the nonce
        self.nonce = response.headers["Replay-Nonce"]
        if response.status_code == 201:
            return response.headers["Location"]
        else:
            raise Exception("Error creating account", response.json())
    
        
        
