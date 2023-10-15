import requests
from dependencies.jws import jws_creator
import json

class Client():
    def __init__(self, dir_address, pem_path):
        #get the domains from the CA
        self.pem_path = pem_path
        self.dir_address = dir_address
        self.CA_domains = self.get_domains_from_CA()
        #create a jws signer
        self.jws = jws_creator()
        #create a new account
        self.kid = self.create_new_account()
        #orders
        self.orders = []
        #challenges
        self.challenges = []

    def get_domains_from_CA(self):
        #establish an https connection with pebble and get the dir
        r = requests.get(self.dir_address, verify=self.pem_path)
        return r.json()

    def get_nonce_from_CA(self):
        #establish an https connection with pebble and get the dir
        nonce_url = self.CA_domains["newNonce"]
        r = requests.head(nonce_url, verify=self.pem_path)
        return r.headers["Replay-Nonce"]

    def create_new_account(self):
        """_summary_
        Create a new account with the CA returns the kid and the account url
            Returns:
            _type_: str, str
        """
        #set header to application/jose+json
        headers = {
            "Content-Type": "application/jose+json"
        }
        #create the payload
        payload_for_new_acc = {
            "termsOfServiceAgreed": True
        }
        new_account_jws = self.jws.get_jws(payload_for_new_acc, self.get_nonce_from_CA(), self.CA_domains["newAccount"])
        #send the jws to the CA
        r = requests.post(self.CA_domains["newAccount"], data=new_account_jws, headers=headers, verify=self.pem_path)
        if r.status_code == 201:
            print("New account created")
            #get the kid from the response
            return r.headers["Location"]
        else:
            throw("Error creating new account")
        
    def placing_order(self, domain):
        """_summary_
        Get a challenge from the CA
            Returns:
            _type_: dict
        """
        #establish an https connection and ask for a challenge from the CA
        pem_path = "project/pebble.minica.pem"
        #use the kid to sign the request
        headers = {
            "Content-Type": "application/jose+json",
            "Kid": self.kid
        }
        #create the payload for the challenge
        payload_for_challenge = {
            "identifiers": [
                {
                    "type": "dns",
                    "value": "example.com"
                }
            ]
        }
        #create the jws for the challenge
        challenge_jws = self.jws.get_jws(payload_for_challenge, self.get_nonce_from_CA(), self.CA_domains["newOrder"], self.kid)
        
        r = requests.post(self.CA_domains["newOrder"], data=challenge_jws, headers=headers, verify=pem_path)
        return r.json()
    
    def challenge_accepted(self, challenge):
        """_summary_
        Takes on the awesome challenge, DNS or HTTP, I can handle it all!
            Returns:
            _type_: dict
        """
        if challenge["identifier"]["type"] == "dns":
            solver = DNS_challenge_solver(challenge)
            solver.solve_challenge()
        elif challenge["identifier"]["type"] == "http":
            solver = HTTP_challenge_solver(challenge)
            solver.solve_challenge()