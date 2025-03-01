from flask import Flask, request
import json
import datetime
from factory import Factory


app = Flask(__name__)


@app.route("/get_factory_state", methods=["GET"])  
def get_factory_state():
    factory_id = int(request.args.get("id"))
    factory = factories[factory_id]
    return factory.get_state_json()


@app.route("/get_upgrades", methods=["GET"])  
def get_upgrades():
    factory_id = int(request.args.get("id"))
    factory = factories[factory_id]
    return factory.get_upgrades_json()


start_time = datetime.datetime.now()
factories = [
        Factory("factory_0", start_time),
        Factory("factory_1", start_time)
    ]


def main():
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)  # Sets up flask server on port 5000

if __name__ == "__main__":
    main()