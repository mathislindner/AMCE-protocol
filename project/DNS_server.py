from dnslib.server import BaseResolver, DNSServer, DNSHandler, DNSLogger
from dnslib import RR
from time import sleep
import argparse

# Define a custom DNS handler
class SimpleAddResolver(BaseResolver):
    def __init__(self):
        pass

    def resolve(self, request, handler):
        records_string =  open(file="record.txt", mode="r").read()
        records = RR.fromZone(records_string)
        reply = request.reply()
        qname = request.q.qname
        
        #check if the domain is in the records
        if qname in self.records:
            reply.add_answer(*self.records[qname])
        else:
            #if not, return the 404
            reply.add_answer(*self.records["404"])
        return reply
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start the dns server')
    parser.add_argument('--record', type=str, help='The ip address of the dns server')
    args = parser.parse_args()
    resolver = SimpleAddResolver()
    logger = DNSLogger(prefix=False)
    # Create a DNS server instance on ip_address and port 10053
    print("DNS server is running on port 10035...")
    dns_server = DNSServer(resolver, port=10035, address=args.record, logger=logger)
    dns_server.start_thread()
    
