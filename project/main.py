import argparse
import asyncio
import client_server
import DNS_server
import HTTP_server
import subprocess
import os
from time import sleep

if __name__ == '__main__':
    """
    Positional arguments:
    Challenge type
    (required, {dns01 | http01}) indicates which ACME challenge type the client should perform. Valid options are dns01 and http01 for the dns-01 and http-01 challenges, respectively.

    Keyword arguments:
    --dir DIR_URL
    (required) DIR_URL is the directory URL of the ACME server that should be used.

    --record IPv4_ADDRESS
    (required) IPv4_ADDRESS is the IPv4 address which must be returned by your DNS server for all A-record queries.

    --domain DOMAIN
    (required, multiple) DOMAIN  is the domain for  which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net.

    --revoke
    (optional) If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("challenge_type", help="Challenge type (required, {dns01 | http01}) indicates which ACME challenge type the client should perform. Valid options are dns01 and http01 for the dns-01 and http-01 challenges, respectively.")
    parser.add_argument("--dir", dest= 'dir_url', help="DIR_URL is the directory URL of the ACME server that should be used.")
    parser.add_argument("--record", help="IPv4_ADDRESS is the IPv4 address which must be returned by your DNS server for all A-record queries.")
    parser.add_argument("--domain", action='append', help="DOMAIN  is the domain for  which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net.")
    parser.add_argument("--revoke", help="If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate", action='store_true')
    args = parser.parse_args()
    #additionals
    pem_path = "project/pebble.minica.pem"
    #TODO:add logic for commands
    #start server through the command line as a subprocess
    subprocess.Popen(["python", "project/DNS_server.py", "--record", args.record])
    subprocess.Popen(["python", "project/HTTP_server.py", "--record", args.record])
    #wait for the servers to start
    sleep(2)
    #create account for client if it doesn't exist and set some constants
    client = client_server.Client(args.dir_url, pem_path, args.record)
    
    #place order for certificate
    print(args.challenge_type)
    client.place_order(args.domain, args.challenge_type, args.record)
    client.answer_challenges(revoke=args.revoke)
    #loop to check on the orders and challenges
    #asyncio.run(client.check_queues(revoke=args.revoke))
    
    
    
    
    
    