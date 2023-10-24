#Shutdown HTTP server:  An HTTP server to receive a shutdown signal.
import flask
import argparse

app = flask.Flask(__name__)

@app.route("/shutdown", methods=["GET"])
def shutdown():
    shutdown_server()
    return "shutdown"

def shutdown_server():
    #not implemented
    raise NotImplementedError
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start the http server')
    parser.add_argument('--record', type=str, help='The ip address of the dns server')
    args = parser.parse_args()
    app.run(host=args.record, port=5003)