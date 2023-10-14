import requests
from dependencies.jws import jws_creator
import json

ACME_server_address = "localhost"
ACME_server_port = 14000
pem_path = "pebble.minica.pem"
class Client():
    def __init__(self, ip_address, port, pem_path):
        self.pem_path = "pebble.minica.pem"
        self.ip_address = ip_address
        self.port = port
        self.CA_domains = self.get_domains_from_CA()
        #create jws object to sign the requests
        self.jws = jws_creator()
        #create a new account
        self.kid = self.create_new_account()


    def get_domains_from_CA(self):
        #establish an https connection with pebble and get the dir
        r = requests.get(f"https://{ACME_server_address}:{ACME_server_port}/dir", verify=self.pem_path)
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
        #remove spaces from the jws
        new_account_jws = json.dumps(new_account_jws)
        #send the jws to the CA
        r = requests.post(self.CA_domains["newAccount"], data=new_account_jws, headers=headers, verify=self.pem_path)
        if r.status_code == 201:
            print("New account created")
            #get the kid from the response
            return r.headers["Location"]
        else:
            throw("Error creating new account")
        
    def get_challenge():
        """_summary_
        Get a challenge from the CA
            Returns:
            _type_: dict
        """
        #establish an https connection and ask for a challenge from the CA
        pem_path = "project/pebble.minica.pem"
        r = requests.post(CA_domains["getChallenge"], verify=pem_path)
        return r.json()

client = Client(ACME_server_address, ACME_server_port, pem_path)
