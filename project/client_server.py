import requests
from dependencies.jws import jws_creator
import json
import queue
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
        self.orders = queue.Queue()
        #challenges
        self.challenges = queue.Queue()

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
            raise("Error creating new account", r.status_code, r.text)
        
    def place_order(self, domain, challenge_type, record):
        """_summary_
        Get a challenge from the CA
            Returns:
            _type_: dict
        """
        #remove the 01 from the challenge type
        challenge_type = challenge_type[:-2]
        #use the kid to sign the request
        headers = {
            "Content-Type": "application/jose+json",
            "Kid": self.kid
        }
        #create the payload for the challenge
        payload_for_order = {
            "identifiers": [
                {
                    "type": challenge_type,
                    "value": domain
                }
            ]
        }
        #create the jws for the challenge
        challenge_jws = self.jws.get_jws(payload_for_order, self.get_nonce_from_CA(), self.CA_domains["newOrder"], self.kid)
        
        r = requests.post(self.CA_domains["newOrder"], data=challenge_jws, headers=headers, verify=self.pem_path)
        if r.status_code == 201:
            #add the order to the queue
            self.orders.put(r.json())
            print("Order placed")
        else:
            raise Exception("Error placing order", r.status_code, r.text)
    
    def update_challenges_from_order(self, order):
        """_summary_
        Get a challenge from the CA
            Returns:
            _type_: dict
        """
        print(order)
        #access authorization url
        for auth_url in order["authorizations"]:
            #add the kid to the header
            headers = {
                "Content-Type": "application/jose+json",
                "Kid": self.kid
            }
            #create the payload to get the challenge
            payload = {}
            #create the jws for the challenge
            challenge_jws = self.jws.get_jws(payload, self.get_nonce_from_CA(), auth_url, self.kid)
            r = requests.post(auth_url, data=challenge_jws, headers=headers, verify=self.pem_path)
            if r.status_code == 200:     
                challenges = r.json()["challenges"]
                for challenge in challenges:
                    #add the challenge to the queue
                    self.challenges.put(challenge)
                    print("Challenge added to queue")
            else:
                raise Exception("Error getting challenge", r.status_code, r.text)
    def complete_dns_challenge(self, challenge):
        """_summary_
        Get a challenge from the CA
            Returns:
            _type_: dict
        """
        print("solving dns challenge", challenge)
        return
        #get the token from the challenge
        token = challenge["token"]
        #get the key authorization
        key_authorization = token + "." + self.jws.get_thumbprint()
        #get the domain
        domain = challenge["identifier"]["value"]
        #get the dns record
        record = challenge["dnsRecord"]
        #get the kid
        kid = self.kid
        #create the payload for the challenge
        payload_for_challenge = {
            "keyAuthorization": key_authorization
        }
        #create the jws for the challenge
        challenge_jws = self.jws.get_jws(payload_for_challenge, self.get_nonce_from_CA(), challenge["url"], kid)
        #send the jws to the CA
        r = requests.post(challenge["url"], data=challenge_jws, verify=self.pem_path)
        if r.status_code == 200:
            print("Challenge completed")
            #add the challenge to the queue
            self.challenges.task_done()
        else:
            raise Exception("Error completing challenge", r.status_code, r.text)
        
    def complete_http_challenge(self, challenge):
        pass
    
    def check_queues(self):
        #check the if the challenges are ready from the order queue
        if not self.orders.empty():
            #get the order
            order = self.orders.get()
            self.update_challenges_from_order(order)
            
        #complete challenges
        if not self.challenges.empty():
            #get the challenge
            challenge = self.challenges.get()
            #if the challenge is a dns challenge
            if challenge["type"] == "dns-01":
                #complete the dns challenge
                self.complete_dns_challenge(challenge)
            #if the challenge is a http challenge
            elif challenge["type"] == "http-01":
                #complete the http challenge
                self.complete_http_challenge(challenge)
            else:
                #remove challenge from queue
                print("Challenge type not supported", challenge["type"])
                self.challenges.task_done()
                #raise Exception("Challenge type not supported", challenge["type"])
            