import requests
import certifi

ip_address = "localhost"
port = 14000

#establish an https connection with pebble and get the dir
pem_path = "project/pebble.minica.pem"
r = requests.get(f"https://{ip_address}:{port}/dir", verify=pem_path)
print(r.json())
