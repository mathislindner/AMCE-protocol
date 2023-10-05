import requests

ip_address = "0.0.0.0"
port = 15000

#establish connection with pebble
def test_connection():
    try:
        r = requests.get(f"http://{ip_address}:{port}/test")
        if r.status_code == 200:
            print("Connection established with pebble")
            return True
        else:
            print("Connection could not be established with pebble")
            return False
    except:
        print("Connection could not be established with pebble")
        return False
    
test_connection()