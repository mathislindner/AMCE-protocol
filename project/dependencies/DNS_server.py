#create a DNS server which resolves the DNS queries of the ACME server.
import flask

app = flask.Flask(__name__)

@app.route("/dns-query", methods=["GET"])
def dns_query():
    return "dns-query"
