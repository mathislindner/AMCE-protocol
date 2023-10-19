from dnslib.server import BaseResolver, DNSServer, DNSHandler, DNSLogger
from dnslib import RR
from time import sleep

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
    

def start_DNS_server(default_a_record_ip):
    resolver = SimpleAddResolver()
    logger = DNSLogger(prefix=False)
    # Create a DNS server instance on ip_address and port 10053
    print("DNS server is running on port 10035...")
    dns_server = DNSServer(resolver, port=10035, address=default_a_record_ip, logger=logger)
    dns_server.start_thread()
    
    return dns_server
    
