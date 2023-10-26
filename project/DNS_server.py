from dnslib.server import BaseResolver, DNSServer, DNSHandler, DNSLogger
from dnslib import RR
from time import sleep
import argparse

# Define a custom DNS resolver
class SimpleAddiResolver(BaseResolver):
    def __init__(self):
        print("initializing resolver")

    def resolve(self, request, handler):
        print("handling request for: ")
        records_string =  open(file="project/record.txt", mode="r").read()
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
    resolver = SimpleAddiResolver()
    dns_server = DNSServer(resolver, port=10035, address=args.record, tcp=False)
    dns_server.start_thread()
    print("DNS server is running on " + args.record + ":10035")
    try:
        while 1:
            sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        dns_server.stop()
        
