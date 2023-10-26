import requests
from dependencies.jws import jws_creator
import json
import time
from time import sleep
import queue
import os
class Client():
    def __init__(self, dir_address, pem_path, record):
        #get the domains from the CA
        self.pem_path = pem_path
        self.dir_address = dir_address
        self.dns_address = "http://" + record + ":10035"
        self.http_address = "http://" + record + ":5002"
        self.CA_domains = self.get_domains_from_CA()
        #create a jws signer object
        self.jws = jws_creator()
        self.nonce = self.get_nonce_from_CA()
        self.kid = self.create_new_account()
        self.orders = queue.Queue()
        self.challenges_todo = queue.Queue()
        self.challenges_executed = queue.Queue()
        self.certs = []

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
    
    def check_challenge_url(self, challenge_url):
        """_summary_
        Check on all status of all the authorizations
            Returns:
            _type_: list
        """
        #send the request to the to get the status
        headers = {
            "Content-Type": "application/jose+json"
        }
        #create the payload to check the order status
        payload = {}
        #create the jws for the challenge
        signed_data = self.jws.get_jws(payload, self.nonce, challenge_url, kid = self.kid)
        r = requests.post(challenge_url, data=signed_data, headers=headers, verify=self.pem_path)
        self.nonce = r.headers["Replay-Nonce"]
        if r.status_code == 200:
            print(r.json())
            print("Status of authorization: " + r.json().get("status"))
            return r.json().get("status")
        elif r.json()["type"] == "urn:ietf:params:acme:error:badNonce":
            #retry the request
            print("Bad nonce, retrying...")
            self.check_challenge_url(challenge_url)
        else:
            raise Exception("Error checking order status", r.status_code, r.text)
    

    def check_all_challenges(self):
        sleep(5)
        while not self.challenges_executed.empty():
            challenge_to_check = self.challenges_executed.queue[0]
            print("Checking challenge: " + challenge_to_check["type"])
            if self.check_challenge_url(challenge_to_check["url"]) == "valid":
                self.challenges_executed.get()
            else:
                print("Challenge not valid yet")
                sleep(5)
      
    def update_challenges_from_order(self, order):
        """_summary_
        Get a challenge from the CA
            Returns:
            _type_: dict
        """
        #access authorization url
        for auth_url in order["authorizations"]:
            #add the kid to the header
            headers = {
                "Content-Type": "application/jose+json"
            }
            #create the payload to get the challenge
            payload = {}
            #create the jws for the challenge
            auth_jws = self.jws.get_jws(payload, self.nonce, auth_url, self.kid)
            r = requests.post(auth_url, data=auth_jws, headers=headers, verify=self.pem_path)
            self.nonce = r.headers["Replay-Nonce"]
            if r.status_code == 200:     
                challenges = r.json()["challenges"]
                for challenge in challenges:
                    #add the challenge to the queue
                    self.challenges_todo.put(challenge)
            else:
                #TODO:retry
                raise Exception("Error getting challenge", r.status_code, r.text)
            
    def complete_dns_challenge(self, challenge, authorization_key, domain):
        """_summary_
        send the dns record to the dns server on port
            Returns:
            _type_: dict
        """
        print("solving dns challenge")
        #get the token from the challenge
        token = challenge["token"]
        url = "_acme-challenge." + domain + "."
        #_acme-challenge.example.com. IN TXT "your-key-authorization-value-here"
        rec_file = open("dns_records.txt", "a")
        rec_file.write(url + " 60 IN TXT " + authorization_key +"\n")  
        return True
        
    def complete_http_challenge(self, challenge, authorization_key):
        #get the token from the challenge
        token = challenge["token"]
        #form a post request to the http server including the token and the authorization
        url = self.http_address + "/allocate_challenge"
        url = url + "?path=" + token + "&authorization=" + authorization_key
        r = requests.get(url)
        #verify that the server managed to allocate the challenge
        if r.status_code == 200:
            url = self.http_address + "/.well-known/acme-challenge/" + token
            r = requests.get(url)
            if r.status_code == 200:
                #check if the authorization is in the response
                if authorization_key in r.text:
                    print("HTTP challenge added to the https server")
        return True
    
    """Once the client believes it has fulfilled the server's requirements,
   it should send a POST request to the order resource's finalize URL.
   The POST body MUST include a CSR:
    """
    def finalize_order(self, order):
        """
        Finalize the order by asking the CA to issue the certificate after all the challenges are done
        """
        #get the csr
        csr = generate_CSR.get_csr(order.domains)
        #communicate to finalize order url
        headers = {
            "Content-Type": "application/jose+json",
            "Kid": self.kid
        }
        #create the payload to finalize the order
        payload_for_order = {
            "csr": csr
        }
        #create the jws for the challenge
        signed_data = self.jws.get_jws(payload_for_order, self.nonce, order.finalize, self.kid)
        r = requests.post(order.finalize, data=signed_data, headers=headers, verify=self.pem_path)
        self.nonce = r.headers["Replay-Nonce"]
        if r.status_code == 200:
            #retrun the certificate url to download the certificate
            return r.json()["certificate"]
        
        elif r.json()["type"] == "urn:ietf:params:acme:error:badNonce":
            #retry the request
            print("Bad nonce, retrying...")
            self.finalize_order(order)
        else:
            raise Exception("Error finalizing order", r.status_code, r.text)

    def download_certificate(self, certificate_url):
        """
        Download the certificate from the url
        """
        r = requests.get(certificate_url)
        if r.status_code == 200:
            #save the certificate
            certificate_file = open("project/certificate.crt", "w")
            certificate_file.write(r.text)
            certificate_file.close()
            return True
        else:
            raise Exception("Error downloading certificate", r.status_code, r.text)
        
    def start_https_server(self, certificat_path, key_path, domain):
        """
        Start the https server to listen for the challenges
        """
        #create the server
        httpd = HTTPServer((self.http_address, self.http_port), MyHandler)
        #set the certificate and the key
        httpd.socket = ssl.wrap_socket(httpd.socket, certfile=certificat_path, keyfile=key_path, server_side=True)
        #set the domain
        httpd.domain = domain
        #start the server
        httpd.serve_forever()
        
    #function to do it sequentially
    def answer_challenges(self, challenge_type, revoke=False):
        #get orders
        while not self.orders.empty():
            order = self.orders.get()
            self.update_challenges_from_order(order)
            print("Challenges in queue", self.challenges_todo.qsize())
            #created 2 different queues to keep track of the challenges that we think are done
            #so we don t have to iterate and the complete and then iterate...
            while not self.challenges_todo.empty():
                challenge = self.challenges_todo.queue[0]
                key_authorization = challenge["token"] + "." + self.jws.get_jwk_thumbprint_encoded()
                if challenge["type"] == "dns-01" and challenge_type == "dns01":
                    #complete the dns challenge
                    #TODO verify the domain to challenge for
                    self.complete_dns_challenge(challenge, key_authorization, domain=order["identifiers"][0]["value"] )
                    self.challenges_executed.put(challenge)
                    self.challenges_todo.get()
                elif challenge["type"] == "http-01" and challenge_type == "http01":
                    #add the domain to the DNS server to point to the http server
                    self.complete_http_challenge(challenge, key_authorization)
                    self.challenges_executed.put(challenge)
                    self.challenges_todo.get()
                else:
                    #remove the challenge from the queue since we were not ask to do it
                    self.challenges_todo.get()
            #wait for the servers to update
            #TODO: check the status of the authorizations
            if not self.check_all_challenges():
                raise Exception("Error completing challenges")
                exit()
            else:
                #since all the challenges are completed, finalize the order
                print("finalizing order")
                certificate_url = self.finalize_order(order)
                self.download_certificate(certificate_url, order.domains)


    def revoke_cert(self):
        print("Revoking cert")
        pass