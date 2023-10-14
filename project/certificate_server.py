# Certificate HTTPS server: An HTTPS server which uses a certificate obtained by the ACME client.
import flask

app = flask.Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return "index"

if __name__ == "__main__":
    app.run(host="", port=443, ssl_context=("./cert.pem", "./key.pem"))