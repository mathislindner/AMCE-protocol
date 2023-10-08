import requests
import certifi
import cryptography
import base64
import json
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

ip_address = "localhost"
port = 14000

def get_domains_from_CA():
    #establish an https connection with pebble and get the dir
    pem_path = "project/pebble.minica.pem"
    r = requests.get(f"https://{ip_address}:{port}/dir", verify=pem_path)
    return r.json()

# not sure if i wanna keep this here (but i don t want to call it every time i need it)
CA_domains = get_domains_from_CA()
print(CA_domains)

def test_wellformedness():
    pem_path = "project/pebble.minica.pem"
    headers = {
        "Content-Type": "application/jose+json"
    }
    payload = {
        "termsOfServiceAgreed": True
    }
    signature = {
        "test": "test"
    }
        
    # sth like this
    body = {
        "protected": base64.urlsafe_b64encode(json.dumps(headers).encode("utf-8")),
        "payload": base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")),
        "signature": base64.urlsafe_b64encode(json.dumps(signature).encode("utf-8"))
    }
    r = requests.post(CA_domains["newAccount"], data=body, headers=headers, verify=pem_path)
    return r.json()

def get_private_and_public_key():
    #create a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    #get the public key
    public_key = private_key.public_key()
    return private_key, public_key

    """5.1.  Message Signature or MAC Computation

   To create a JWS, the following steps are performed.  The order of the
   steps is not significant in cases where there are no dependencies
   between the inputs and outputs of the steps.

   1.  Create the content to be used as the JWS Payload.

   2.  Compute the encoded payload value BASE64URL(JWS Payload).

   3.  Create the JSON object(s) containing the desired set of Header
       Parameters, which together comprise the JOSE Header (the JWS
       Protected Header and/or the JWS Unprotected Header).

   4.  Compute the encoded header value BASE64URL(UTF8(JWS Protected
       Header)).  If the JWS Protected Header is not present (which can
       only happen when using the JWS JSON Serialization and no
       "protected" member is present), let this value be the empty
       string.

   5.  Compute the JWS Signature in the manner defined for the
       particular algorithm being used over the JWS Signing Input
       ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
       BASE64URL(JWS Payload)).  The "alg" (algorithm) Header Parameter
       MUST be present in the JOSE Header, with the algorithm value
       accurately representing the algorithm used to construct the JWS
       Signature.

   6.  Compute the encoded signature value BASE64URL(JWS Signature).

   7.  If the JWS JSON Serialization is being used, repeat this process
       (steps 3-6) for each digital signature or MAC operation being
       performed.

   8.  Create the desired serialized output.  The JWS Compact
       Serialization of this result is BASE64URL(UTF8(JWS Protected
       Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS
       Signature).  The JWS JSON Serialization is described in
       Section 7.2.
    """
    


def get_header():
    #encode the header
    protected = {
        "alg": "RS256",
        "jwk": "test",
        "nonce": "456g45gsfd45gf45gfds454565rh4",
        "url": CA_domains["newAccount"]
    }
    protected_b64 = base64.urlsafe_b64encode(json.dumps(protected).encode("utf-8"))
    return protected_b64

def get_payload():
    #prepare the payload
    payload = {
        "termsOfServiceAgreed": True,
        "contact": [
            "mailto:test@test.com"
        ]
    }
    #encode the payload
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
    return payload_b64

    """Computing the HMAC of the JWS Signing Input ASCII(BASE64URL(UTF8(JWS
   Protected Header)) || '.' || BASE64URL(JWS Payload)) with the HMAC
   SHA-256 algorithm using the key specified in Appendix A.1 and
   base64url-encoding the result yields this BASE64URL(JWS Signature)
    """
def get_signature(protected_b64, payload_b64):
    private_key, public_key = get_private_and_public_key()
    #Computing the HMAC of the JWS Signing Input ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)) with the HMAC SHA-256 algorithm using the key specified in Appendix A.1 and base64url-encoding the result yields this BASE64URL(JWS Signature)
    signature = private_key.sign(
        (protected_b64 + "." + payload_b64).encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature
          

def get_jws():
    """_summary_
    Create a jws
    Returns:
        _type_: dict
    """
    protected_b64 = get_header()
    payload_b64 = get_payload()
    signature = get_signature(protected_b64, payload_b64)
    #create the jws
    jws = {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature
    }
    return jws

def create_new_account():
    """_summary_
    Create a new account with the CA
        Returns:
        _type_: dict
    """
    #establish an https connection with pebble and create a new account
    pem_path = "project/pebble.minica.pem"
    #set header to application/jose+json
    headers = {
        "Content-Type": "application/jose+json"
    }
    #get the jws
    jws = get_jws()
    print(jws)
    #send the jws to the CA
    r = requests.post(CA_domains["newAccount"], data=jws, headers=headers, verify=pem_path)
    return r.json()

print(create_new_account())

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

