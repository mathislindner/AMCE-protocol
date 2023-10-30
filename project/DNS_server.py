from dnslib.server import BaseResolver, DNSServer, DNSHandler
import logging
from dnslib import RR
from time import sleep
import argparse
dns_logger = logging.getLogger("DNS")
logging.basicConfig(level=logging.INFO)

# Define a custom DNS resolver
class SimpleAddiResolver(BaseResolver):
    def resolve(self, request, handler):
        print("handling request for: ")
        records_string =  open(file="project/records.txt", mode="r").read()
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
    
    testing = args.record
    
    resolver = SimpleAddiResolver()
    dns_server = DNSServer(resolver, port=10035, address=testing)
    dns_server.start_thread()
    
    
    dns_logger.info("DNS server started on address:{} port:{}".format(testing, 10035))
    
    while dns_server.isAlive():
        pass
        
        
