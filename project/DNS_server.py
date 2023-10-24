from dnslib.server import BaseResolver, DNSServer, DNSHandler, DNSLogger
from dnslib import RR
from time import sleep
import argparse

# Define a custom DNS handler
class SimpleAddResolver(BaseResolver):
    def __init__(self):
        #call the super constructor
        super().__init__()

    def resolve(self, request, handler):
        records_string =  open(file="project/record.txt", mode="r").read()
        records = RR.fromZone(records_string)
        reply = request.reply()
        qname = request.q.qname
        print("handling request for: " + str(qname))
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
    dns_server = DNSServer(resolver, port=10035, address=args.record, logger=logger)
    dns_server.start_thread()
    print("DNS server is running on " + args.record + ":10035")
