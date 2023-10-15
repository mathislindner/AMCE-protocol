import argparse
from dnslib import DNSRecord, RR
from dnslib.server import DNSServer, DNSLogger

# Define a function to handle DNS queries
def dns_handler(request, address):
    reply = request.reply()

    for question in request.questions:
        qname = question.qname
        qtype = question.qtype

        if qtype == 1:  # A-record query
            reply.add_answer(RR(qname, qtype, rdata=IPv4_ADDRESS, ttl=60))
        else:  # For all other query types (e.g., TXT), return a sample response
            reply.add_answer(RR(qname, qtype, rdata="Sample Response", ttl=60))

    return reply

if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--record", help="IPv4_ADDRESS is the IPv4 address which must be returned by your DNS server for all A-record queries.")
    args = argparser.parse_args()
    IPv4_ADDRESS = args.record
    # Create a DNS server
    dns_server = DNSServer(dns_handler, address='localhost', port=10053)
    
    # Create a logger to display incoming queries (optional)
    logger = DNSLogger(prefix=False)
    dns_server.logger = logger
    
    # Start the server
    dns_server.start()
    
    
    
