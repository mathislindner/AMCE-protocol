#server to handle http requests to answer the challenges
import flask
import json
import argparse

app = flask.Flask(__name__)
challs = {}

@app.route("/.well-known/acme-challenge/<token>")
def answer_challenge(token):
    if token in challs:
        return challs[token]
    return "404"
    
@app.route("/allocate_challenge", methods=["GET"])
def allocate_challenge():
    if flask.request.method == 'GET':
        #read from url
        token = flask.request.args.get('token')
        key_auth = flask.request.args.get('authorization')
        if token != None and key_auth != None:
            challs[token] = key_auth
            return json.dumps({"status": "ok"})
    else:
        return json.dumps({"status": "error"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start the http server')
    parser.add_argument('--record', type=str, help='The ip address of the dns server')
    args = parser.parse_args()
    app.run(host=args.record, port=5002)