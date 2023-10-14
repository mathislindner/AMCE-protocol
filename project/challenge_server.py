# Challenge HTTP server: An HTTP server to respond to http-01 queries of the ACME server.
import flask

app = flask.Flask(__name__)

@app.route("/.well-known/acme-challenge/<token>", methods=["GET"])
def challenge(token):
    return token

if __name__ == "__main__":
    app.run(host="", port=80)