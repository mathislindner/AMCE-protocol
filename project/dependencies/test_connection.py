import requests
import certifi
import cryptography

ip_address = "localhost"
port = 14000

def get_domains_from_CA():
    #establish an https connection with pebble and get the dir
    pem_path = "project/pebble.minica.pem"
    r = requests.get(f"https://{ip_address}:{port}/dir", verify=pem_path)
    return r.json()

def create_new_account():
    CA_domains = get_domains_from_CA()
    #prepare the payload
    payload = {
        "termsOfServiceAgreed": True
    }
    #establish an https connection with pebble and create a new account
    pem_path = "project/pebble.minica.pem"
    #set header to application/jose+json
    headers = {
        "Content-Type": "application/jose+json"
    }
    #create new key pair
    private_key, public_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(), cryptography.hazmat.backends.default_backend()), cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(), cryptography.hazmat.backends.default_backend())
    #create a jws
    #jws = cryptography.
    
    #send the jws to the CA
    r = requests.post(CA_domains["newAccount"], data=jws, headers=headers, verify=pem_path)
    return r.json()

    
response= create_new_account()
print(response)



