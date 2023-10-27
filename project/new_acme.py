import requests
import json
import time
from time import sleep
import logging
#CRYPTOGRAPHY
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import hashlib
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.backends import default_backend
import base64

#set logging level
logging.basicConfig(level=logging.INFO)
class Authentificator():
    def __init__(self):
        self.private_key, self.public_key = self.create_keys()
        self.jwk = self.set_jwk()
        self.encodedtp = self.set_encoded_thumbprint()
        
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
        
    def set_encoded_thumbprint(self):
        """_summary_
        set the encoded thumbprints
        Returns:
            _type_: str
        """
        tp_encoded = json.dumps({
            "crv": "P-256",
            "kty": "EC",
            "x": base64.urlsafe_b64encode(self.public_key.public_numbers().x.to_bytes(32, byteorder="big")).decode("utf-8").replace("=", ""),
            "y": base64.urlsafe_b64encode(self.public_key.public_numbers().y.to_bytes(32, byteorder="big")).decode("utf-8").replace("=", "")
        }, sort_keys=True).encode("utf-8")
        hashed = hashlib.sha256(tp_encoded).digest()
        b64_encoded = base64.urlsafe_b64encode(hashed).decode("utf-8").replace("=", "")
        return b64_encoded
        
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
        if payload_dict == None:
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
    def complete_http_challenge(self, challenge, authorization_key):
        #get the token from the challenge
        token = challenge["token"]
        #form a post request to the http server including the token and the authorization
        url = self.http_address + "/allocate_challenge"
        url = url + "?path=" + token + "&authorization=" + authorization_key
        r = requests.get(url)
        return True
        """
        #verify that the server managed to allocate the challenge
        if r.status_code == 200:
            url = self.http_address + "/.well-known/acme-challenge/" + token
            r = requests.get(url)
            if r.status_code == 200:
                #check if the authorization is in the response
                if authorization_key in r.text:
                    print("HTTP challenge added to the https server")
            return True 
        else:
            return False"""
    def complete_dns_challenge(self, challenge, authorization_key, domain):
        """_summary_
        Add a line in the records.txt file with the authorization key for the domain
        """
        f = open("project/records.txt", "a")
        f.write(domain + " 60 IN TXT " + authorization_key+"\n")
        f.close()
        return True
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
                payload_for_authz = None
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
                if challenge["type"][:-3] == self.given_challenge_type[:-2]:
                    self.challenges.append((challenge, authz["identifier"]["value"]))
                
    def complete_challenges(self):
        for challenge, domain in self.challenges:
            completed = False
            challenge_type = challenge["type"]
            #keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))
            authorization_key = challenge["token"] + "." + self.authentificator.encodedtp
            print(authorization_key)
            if challenge_type[:-3] == "dns":
                completed = self.complete_dns_challenge(challenge, authorization_key,domain=domain)
            elif challenge_type[:-3] == "http":
                completed = self.complete_http_challenge(challenge, authorization_key)
            if not completed:
                self.logger.error("Error while responding to challenge: " + json.dumps(challenge))
        
    def respond_to_challenges(self):
        """_summary_
        create POST requests to tell that the challenges have been completed
        POST authorization challenge   | 200   
        """
        headers = {
            "Content-Type": "application/jose+json"
        }
        for challenge, _ in self.challenges:
            challenge_url = challenge["url"]
            payload_for_challenge = {}
            protected_for_challenge = {
                "alg": "ES256",
                "kid": self.kid,
                "nonce": self.nonce,
                "url": challenge_url
            }
            signed_payload = self.authentificator.sign(protected_for_challenge, payload_for_challenge)
            r = requests.post(challenge_url, headers=headers, data=signed_payload, verify=self.pem_path)
            self.nonce = r.headers["Replay-Nonce"]
            if r.status_code == 200:
                pass
            else:
                self.logger.error("Error while responding to challenge: " + response.text)
        return

        
    def poll_for_status(self):
        """_summary_
        check if the challenges have been completed by sending POST-as-GET requests to the challenge URLs
        """
        headers = {
            "Content-Type": "application/jose+json"
        }
        for challenge, _ in self.challenges:
            challenge_url = challenge["url"]
            payload_for_challenge = None
            protected_for_challenge = {
                "alg": "ES256",
                "kid": self.kid,
                "nonce": self.nonce,
                "url": challenge_url
            }
            signed_payload = self.authentificator.sign(protected_for_challenge, payload_for_challenge)
            r = requests.post(challenge_url, headers=headers, data=signed_payload, verify=self.pem_path)
            self.nonce = r.headers["Replay-Nonce"]
            if r.status_code == 200:
                if r.json()["status"] == "valid":
                    self.logger.info("Challenge completed")
                else:
                    self.logger.error("Challenge not completed: " + json.dumps(challenge))
            else:
                self.logger.error("Error while polling for status: " + response.text)
        return
                    
    def finalize_order(self):
        pass
    
    def download_certificate(self):
        pass
    
    #-------------------------------------------------------------------------------------------------------------------
