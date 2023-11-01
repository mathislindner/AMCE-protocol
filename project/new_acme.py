import requests
import json
import time
import os
from time import sleep
import logging
#CRYPTOGRAPHY
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import hashlib
from Crypto.Hash import SHA256
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
        }, sort_keys=True).replace(" ", "")
        hashed = SHA256.new(tp_encoded.encode("utf-8")).digest()
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
    
    def generate_CSR(self, domains):
        """_summary_
        Generate a certificate signing request
        Returns:
            _type_: str
        """
        #hadnle wildcard domains
        domain = domains[0]
        if domain[0][:2] == "*.":
            domain = domain[0][2:]
        #create the private key
        server_private_key, server_public_key = self.create_keys()
        #save the private key
        os.makedirs("certs", exist_ok=True)
        path_private_key = "certs/private_key" + domain + ".pem"
        with open(path_private_key, "wb") as f:
            f.write(server_private_key.private_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM, 
                                                     format=cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL, 
                                                     encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption()))
        #create the csr
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"CH"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"Zurich"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, domain),
        ])).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain) for domain in domains
            ]),
            critical=False,
        ).sign(server_private_key, hashes.SHA256())
        #save the csr
        path_csr = "certs/CSR" + domain + ".der"
        with open(path_csr, "wb") as f:
            f.write(csr.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER))
        return path_csr
    
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
        self.http_shut_down_adress = "http://" + record + ":5003"
        self.http_address = "http://" + record + ":5002"
        self.https_address = "https://" + record + ":5001"
        
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
            
    def complete_dns_challenge(self, challenge, to_allocate, domain):
        """_summary_
        Add a line in the records.txt file with the authorization key for the domain
        """
        f = open("project/records.txt", "a")
        f.write("_acme-challenge." + domain + ". 300 IN TXT " + to_allocate + "\n")
        f.close()
        return True
    
    
    def answer_and_verify_challenges(self):
        """_summary_
        Answer the challenges and verify that the answers are correct sequentially
        Combines client.complete_challenges(), client.respond_to_challenges(), client.poll_for_status() sequentially
        """
        for challenge in self.challenges:
            if self.complete_challenge(challenge[0], challenge[1]):
                if self.respond_to_challenge(challenge[0], challenge[1]):
                    sleep(2)
                    if self.poll_for_status_challenge(challenge[0]):
                        self.logger.info("Challenge completed")
                    else:
                        self.logger.error("Challenge could not be completed")
                else:
                    self.logger.error("Challenge could not be responded to")
            
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
                    "type": 'dns',
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
                
    def complete_challenge(self, challenge, domain):
        completed = False
        challenge_type = challenge["type"]
        #keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))
        authorization_key_raw = challenge["token"] + "." + self.authentificator.encodedtp
        
        if challenge_type[:-3] == "dns":
            #compute 256 sha digest
            to_allocate =  base64.urlsafe_b64encode(SHA256.new(authorization_key_raw.encode("utf-8")).digest()).decode("utf-8").replace("=", "")
            completed = self.complete_dns_challenge(challenge, to_allocate ,domain=domain)
        elif challenge_type[:-3] == "http":
            completed = self.complete_http_challenge(challenge, authorization_key_raw)
        if not completed:
            self.logger.error("Error while responding to challenge: " + json.dumps(challenge))
        return completed
            
        
    def respond_to_challenge(self, challenge, domain):
        """_summary_
        create POST requests to tell that the challenge has been completed
        POST authorization challenge   | 200   
        """
        headers = {
            "Content-Type": "application/jose+json"
        }
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
            return True
        self.logger.error("Error while responding to challenge: " + response.text)
        return False

        
    def poll_for_status_challenge(self, challenge):
        """_summary_
        check if the challenges have been completed by sending POST-as-GET requests to the challenge URLs
        """
        headers = {
            "Content-Type": "application/jose+json"
        }
        for i in range(4):
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
                    return True
                else:
                    self.logger.error("Challenge not completed yet try nr{}: ".format(i) + json.dumps(challenge))
                    sleep(3)
            else:
                self.logger.error("Error while polling for status: " + response.text)
        self.logger.error("Challenge could not be completed after 3 tries: " + json.dumps(challenge))
        return False
                    
    def finalize_order(self):
        """_summary_
        Finalize the order
        """
        csr_path = self.authentificator.generate_CSR([authz["identifier"]["value"] for authz in self.authz])
        csr = open(csr_path, "rb").read()
        headers = {
            "Content-Type": "application/jose+json"
        }
        for order in self.orders:
            payload_for_order = {
                "csr": base64.urlsafe_b64encode(csr).decode("utf-8").replace("=", "")
            }
            protected_for_order = {
                "alg": "ES256",
                "kid": self.kid,
                "nonce": self.nonce,
                "url": order["finalize"]
            }
            signed_payload = self.authentificator.sign(protected_for_order, payload_for_order)
            r = requests.post(order["finalize"], headers=headers, data=signed_payload, verify=self.pem_path)
            self.nonce = r.headers["Replay-Nonce"]
            if r.status_code == 200:
                self.logger.info("Order finalized")
                return True
            else:
                self.logger.error("Error while finalizing the order: " + r.text)
                
    def get_certificate_urls(self):
        """_summary_
        Update the order status and return certificate url        
        """
        certificate_urls = []
        headers = {
            "Content-Type": "application/jose+json"
        }
        for order in self.orders:
            for i in range(4):
                payload_for_order = None
                protected_for_order = {
                    "alg": "ES256",
                    "kid": self.kid,
                    "nonce": self.nonce,
                    "url": order["Location"]
                }
                signed_payload = self.authentificator.sign(protected_for_order, payload_for_order)
                r = requests.post(order["Location"], headers=headers, data=signed_payload, verify=self.pem_path)
                self.nonce = r.headers["Replay-Nonce"]
                if r.status_code == 200:
                    self.logger.info("Order status updated")
                    status = r.json()["status"]
                    if status == "valid":
                        certificate_urls.append(r.json()["certificate"])
                        break
                if i == 3:
                    self.logger.error("Order status was not valid after 3 tries")
                    return None  
                else:
                    self.logger.error("Error while updating the order status: " + r.text)
                
        return certificate_urls
        
    def download_certificate(self):
        """_summary_
        Download the certificate
        """
        headers = {
            "Content-Type": "application/jose+json"
        }
        order=self.orders[0] #TODO: check if this is correct
        self.logger.info(order)
        for order in self.orders:
            payload_for_order = None
            protected_for_order = {
                "alg": "ES256",
                "kid": self.kid,
                "nonce": self.nonce,
                "url": order["certificate"]
            }
            signed_payload = self.authentificator.sign(protected_for_order, payload_for_order)
            r = requests.post(order["certificate"], headers=headers, data=signed_payload, verify=self.pem_path)
            self.nonce = r.headers["Replay-Nonce"]
            if r.status_code == 200:
                self.logger.info("Certificate downloaded")
                print(r.text)
                return certificate
            else:
                self.logger.error("Error while downloading the certificate: " + r.text)
    
    #-------------------------------------------------------------------------------------------------------------------