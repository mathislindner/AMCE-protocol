from dnslib.server import DNSServer, DNSHandler
from dnslib.dns import DNSRecord
from time import sleep
# Define a custom DNS handler
class SimpleDNSServerHandler(DNSHandler):

    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    def resolve(self, request, handler):
        # This is where you handle DNS queries and generate responses.
        # For a simple example, we'll return a hardcoded A record.
        #read the record from the file
        records = []
        with open("record.txt", "r") as file:
            records = file.readlines()
        #find the record that matches the query
        for record in records:
            if request.q.qname == record.split(" ")[0]:
                #create the response
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                reply.add_answer(*RR.fromZone(record))
                return reply
        #if no record is found, return a 404
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        reply.header.rcode = 3
        return reply

if __name__ == '__main__':
    # Create a DNS server instance on ip_address and port 53
    server = DNSServer(SimpleDNSServerHandler, port=10035)
    print("DNS server is running on port 10035...")
    #start the server in the background
    server.start()
    
