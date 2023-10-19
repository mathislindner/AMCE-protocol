#server to handle http requests to answer the challenges
import flask
import json

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
    


def start_HTTP_server(record):
    app.run(host=record, port=5002)
    return app