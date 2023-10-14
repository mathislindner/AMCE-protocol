#Shutdown HTTP server:  An HTTP server to receive a shutdown signal.
import flask

app = flask.Flask(__name__)

@app.route("/shutdown", methods=["GET"])
def shutdown():
    shutdown_server()
    return "shutdown"

def shutdown_server():
    #not implemented
    raise NotImplementedError
    
if __name__ == "__main__":
    app.run(host="127.0.0.23", port=80)