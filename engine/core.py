from flask import Flask, request
import json
import datetime
from factory import Factory


app = Flask(__name__)


@app.route("/add_team", methods=["GET"])
def add_team():
    team_name = request.args.get("team_id")
    if team_name in factories:
        return json.dumps({ "result" : False })
    factories[team_name] = Factory(team_name, start_time)
    return json.dumps({ "result" : True })

@app.route("/get_factory_state", methods=["GET"])  
def get_factory_state():
    factory_id = request.args.get("team_id")
    factory = factories[factory_id]
    return factory.get_state_json()

@app.route("/get_upgrades", methods=["GET"])  
def get_upgrades():
    factory_id = request.args.get("team_id")
    factory = factories[factory_id]
    return factory.get_upgrades_json()

@app.route("/purchase_upgrade", methods=["GET"])  
def purchase_upgrade():
    factory_id = request.args.get("team_id")
    category = request.args.get("category")
    upgrade_id = int(request.args.get("upgrade_id"))
    factory = factories[factory_id]
    result = factory.purchase_upgrade(category, upgrade_id)
    return json.dumps({ "result" : result })

@app.route("/get_messages", methods=["GET"])
def get_messages():
    factory_id = request.args.get("team_id")
    factory = factories[factory_id]
    return factory.get_messages_json()



start_time = datetime.datetime.now()
factories = {}



def main():
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)  # Sets up flask server on port 5000

if __name__ == "__main__":
    main()