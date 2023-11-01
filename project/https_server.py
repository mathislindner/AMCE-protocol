import argparse
from flask import flask

@app.route('/')
def index():
    return 'Flask is running!'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=str)
    parser.add_argument("--domain")
    
    args = parser.parse_args()
    
    certificat_path = f"project/certificates/{args.domain}.crt"
    key_path = f"project/certificates/server_private_key{args.domain}.pem"
    app.run(host=args.record, port=5001)