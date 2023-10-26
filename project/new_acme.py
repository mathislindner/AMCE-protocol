import requests
import json
import time
from time import sleep
import logging
#CRYPTOGRAPHY
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import base64

#set logging level
logging.basicConfig(level=logging.INFO)
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
    def __init__(self, dir_url, pem_path, record, given_challenge_type):
        self.logger = logging.getLogger("ACMECLIENT")
        self.pem_path = pem_path
        self.record = record
        self.given_challenge_type = given_challenge_type
        self.CA_domains = requests.get(dir_url, verify=self.pem_path).json()
        self.authentificator = Authentificator()
        self.nonce = requests.head(self.CA_domains["newNonce"], verify=self.pem_path).headers["Replay-Nonce"]
        
        self.dns_address = "http://" + record + ":10035"
        self.http_address = "http://" + record + ":5002"
        
        self.orders = []
        self.authz = []
        self.challenges = []
        
        self.kid = self.create_account()
    
    #-------------------------------------------------------------------------------------------------------------------
    #Helpers to get the certificate
    
    #-------------------------------------------------------------------------------------------------------------------
    # Sequence of steps to get a certificate
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
            self.logger.info("Account created")
            return response.headers["Location"]
        else:
            self.logger.error("Error while creating the account: " + response.text)
    
    def submit_order(self, domains):
        headers = {
            "Content-Type": "application/jose+json"
        }
        #create the payload to create one order for all the domains
        payload_for_order = {
            "identifiers": [
                {
                    "type": 'dns', #TODO: SHOULD THIS BE CHANGED??????
                    "value": domain
                }for domain in domains
            ],
            "notBefore": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "notAfter": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400))
        }
        protected_for_order = {
            "alg": "ES256",
            "kid": self.kid,
            "nonce": self.nonce,
            "url": self.CA_domains["newOrder"]
        }
        signed_payload = self.authentificator.sign(protected_for_order, payload_for_order)
        #create the request
        response = requests.post(self.CA_domains["newOrder"], headers=headers, data=signed_payload, verify=self.pem_path)
        #update the nonce
        self.nonce = response.headers["Replay-Nonce"]
        if response.status_code == 201:
            #add order to orders
            self.orders.append(response.json())
            self.logger.info("Order created")
        else:
            self.logger.error("Error while creating the order: " + response.text)          
    
    def fetch_challenges(self):
        headers = {
            "Content-Type": "application/jose+json"
        }
        #Get authz
        for order in self.orders:
            for authz_url in order["authorizations"]:
                payload_for_authz = {}
                protected_for_authz = {
                    "alg": "ES256",
                    "kid": self.kid,
                    "nonce": self.nonce,
                    "url": authz_url
                }
                signed_payload = self.authentificator.sign(protected_for_authz, payload_for_authz)
                r = requests.post(authz_url, headers=headers, data=signed_payload, verify=self.pem_path)
                self.nonce = r.headers["Replay-Nonce"]
                if r.status_code == 200:
                    self.authz.append(r.json())
                else:
                    self.logger.error("Error while fetching the authz: " + response.text)
        #extract challenges from authz
        for authz in self.authz:
            for challenge in authz["challenges"]:
                if challenge["type"] == self.given_challenge_type:
                    self.challenges.append((challenge, authz["identifier"]["value"]))
                
    def complete_challenges(self):
        for challenge, domain in self.challenges:
            challenge_type = challenge["type"]
            if challenge_type[:-3] == "dns":
                completed = self.respond_to_dns_challenge(challenge,domain)
            elif challenge_type[:-3] == "http":
                completed = self.respond_to_http_challenge(challenge,domain)
            if not completed:
                self.logger.error("Error while responding to challenge: " + challenge)

    def respond_to_challenges(self):
        """_summary_
        create POST requests to tell that the challenges have been completed
        """
        for challenge, _ in challenges:
            pass

        
    def poll_for_status(self):
        """_summary_
        """
                    
    def finalize_order(self):
        pass
    
    def download_certificate(self):
        pass
    
    #-------------------------------------------------------------------------------------------------------------------
