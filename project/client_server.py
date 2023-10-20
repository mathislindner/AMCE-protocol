import requests
from dependencies.jws import jws_creator
import json
from time import sleep
import queue
import asyncio
import os
class Client():
    def __init__(self, dir_address, pem_path, record):
        #get the domains from the CA
        self.pem_path = pem_path
        self.dir_address = dir_address
        self.dns_address = "http://" + record + ":10035"
        self.http_address = "http://" + record + ":5002"
        self.CA_domains = self.get_domains_from_CA()
        #create a jws signer
        self.jws = jws_creator()
        #create a new account
        self.nonce = self.get_nonce_from_CA()
        self.kid = self.create_new_account()
        #orders
        self.orders = queue.Queue()
        #challenges
        self.challenges = queue.Queue()

    def get_domains_from_CA(self):
        #establish an https connection with pebble and get the dir
        print("current path " + os.getcwd())
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
        new_account_jws = self.jws.get_jws(payload_for_new_acc, self.nonce, self.CA_domains["newAccount"])
        #send the jws to the CA
        r = requests.post(self.CA_domains["newAccount"], data=new_account_jws, headers=headers, verify=self.pem_path)
        self.nonce = r.headers["Replay-Nonce"]
        if r.status_code == 201:
            print("New account created")
            #get the kid from the response
            return r.headers["Location"]
        else:
            raise("Error creating new account", r.status_code, r.text)
        
    def place_order(self, domains, challenge_type, record):
        """_summary_
        Get a challenge from the CA
            Returns:
            _type_: dict
        """
        #use the kid to sign the request
        headers = {
            "Content-Type": "application/jose+json",
            "Kid": self.kid
        }
        #create the payload to create one order for all the domains
        payload_for_order = {
            "identifiers": [
                {
                    "type": 'dns',
                    "value": domain
                }for domain in domains
            ]
        }
        #create the jws for the challenge
        new_order_jws = self.jws.get_jws(payload_for_order, self.nonce, self.CA_domains["newOrder"], self.kid)
        
        r = requests.post(self.CA_domains["newOrder"], data=new_order_jws, headers=headers, verify=self.pem_path)
        self.nonce = r.headers["Replay-Nonce"]
        if r.status_code == 201:
            #add the order to the queue
            self.orders.put(r.json())
            print("Order placed")
        elif r.json()["type"] == "urn:ietf:params:acme:error:badNonce":
            #retry the request
            print("Bad nonce, retrying")
            self.place_order(domains, challenge_type, record)
            #hope that this doesn't start an infinite loop :D
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
            challenge_jws = self.jws.get_jws(payload, self.nonce, auth_url, self.kid)
            r = requests.post(auth_url, data=challenge_jws, headers=headers, verify=self.pem_path)
            self.nonce = r.headers["Replay-Nonce"]
            if r.status_code == 200:     
                challenges = r.json()["challenges"]
                for challenge in challenges:
                    #add the challenge to the queue
                    self.challenges.put(challenge)
                    print("Challenge added to queue")
            else:
                #TODO:retry
                raise Exception("Error getting challenge", r.status_code, r.text)
            
    def complete_dns_challenge(self, challenge, authorization):
        """_summary_
        send the dns record to the dns server on port
            Returns:
            _type_: dict
        """
        print("solving dns challenge", challenge)
        #get the token from the challenge
        token = challenge["token"]
        #get url from the challenge
        url = challenge["url"]
        #add to record.txt for dns server
        #_acme-challenge.example.com. IN TXT "your-key-authorization-value-here"
        with open("record.txt", "w") as f:
            f.write(url + " IN TXT " + token)
        #print the record from the txt file to be sure it is correct
        print("record.txt")
        with open("record.txt", "r") as f:
            print(f.read())
        #tell the ACME server that the challenge is complete
        headers = {
            "Content-Type": "application/jose+json",
            "Kid": self.kid
        }
        #create the payload for the challenge
        payload_for_order = {}
        #create the jws for the challenge
        challenge_jws = self.jws.get_jws(payload_for_order, self.nonce, url, self.kid)
        #wait for the dns server to update
        sleep(5)
        r = requests.post(url, data=challenge_jws, headers=headers, verify=self.pem_path)
        self.nonce = r.headers["Replay-Nonce"]
        if r.status_code == 200:
            print(r.json())
            #if status is valid
            if r.json()["status"] == "valid":
                self.challenges.task_done()
        else:
            raise Exception("Error completing challenge", r.status_code, r.text)
        
    def complete_http_challenge(self, challenge, authorization):
        #get the token from the challenge
        token = challenge["token"]
        uri = token + "&keyauth=" + authorization
        #talk to the http server
        r = requests.get(self.http_address + "/http_challenge?path=" + uri)
        return True
    
    
    #function to do it sequentially
    def answer_challenges(self, revoke=False):
        #get orders
        while not self.orders.empty():
            order = self.orders.get()
            self.update_challenges_from_order(order)
        print("Challenges in queue", self.challenges.qsize())
        print(self.challenges.queue)
        #complete challenges
        while not self.challenges.empty():
            challenge = self.challenges.get()
            key_authorization = challenge["token"] + "." + self.jws.get_jwk_thumbprint_encoded()
            if challenge["type"] == "dns-01":
                #complete the dns challenge
                self.complete_dns_challenge(challenge, key_authorization)
            elif challenge["type"] == "http-01":
                #complete the http challenge
                self.complete_http_challenge(challenge, key_authorization)
            else:
                print ("Challenge type not supported", challenge["type"])
                #remove the challenge from the queue
                self.challenges.task_done()
                #raise Exception("Challenge type not supported", challenge["type"])
        #wait for the servers to update
        sleep(2)
        #Check if the Challenges are complete
        #revoke cert
        if revoke:
            self.revoke_cert()
        
    def revoke_cert(self):
        print("Revoking cert")
        pass