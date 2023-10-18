from dnslib import DNSRecord
from socket import socket, AF_INET, SOCK_DGRAM

# Define the DNS server's IP address and port
dns_server_ip = '127.0.0.1'
dns_server_port = 10035

# Create a DNS query packet
request = DNSRecord(q=DNSRecord.question("example.com"))

# Create a UDP socket to send the DNS query
udp_socket = socket(AF_INET, SOCK_DGRAM)

try:
    # Send the DNS query to the custom DNS server
    udp_socket.sendto(request.pack(), (dns_server_ip, dns_server_port))

    # Receive the response from the DNS server
    data, _ = udp_socket.recvfrom(1024)

    # Parse the response packet
    response = DNSRecord.parse(data)

    # Print the response
    print("Response from custom DNS server:")
    print(response)

except Exception as e:
    print("An error occurred:", str(e))

finally:
    udp_socket.close()
