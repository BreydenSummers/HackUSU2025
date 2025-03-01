from flask import Flask, jsonify, request


app = Flask(__name__)


@app.route("/endpoint", methods=["GET"])                    # Declares the name of the endpoint to be routed to the given function.
def json_endpoint():
    arg1 = request.args.get("arg1")                         # Arguments are extracted from the request with request.args.get("[ARGUMENT_NAME]").
    arg2 = request.args.get("arg2")
    return jsonify({"json": str(arg1) + str(arg2)}), 200    # Returns a json object to the requester.


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)          # Starts the flask server on the given port, allowing all hosts, with debug enabled.

                                                            # API call signiture: GET "http://[ENDPOINT_IP]:5000/endpoint?arg1=Hello &arg2=World!"
                                                            # Returned json signiture: {"json" : "Hello World!"}