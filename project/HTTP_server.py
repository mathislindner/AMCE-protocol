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
    
@app.route('/http_challenge', methods=["POST"])
def answer_challenge_post():
    path = flask.request.form["path"]
    key_auth = flask.request.form["key_auth"]
    if path != None and key_auth != None:
        challs[path] = key_auth
        return json.dumps({"status": "ok"})
    else:
        return json.dumps({"status": "error"})
    


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start the http server')
    parser.add_argument('--record', type=str, help='The ip address of the dns server')
    args = parser.parse_args()
    app.run(host=args.record, port=5002)