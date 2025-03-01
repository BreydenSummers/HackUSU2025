from flask import Flask, request
import json
import datetime
from factory import Factory


app = Flask(__name__)


@app.route("/add_team", methods=["GET"])
def add_team():
    team_name = request.args.get("team_id")
    port = int(request.args.get("port"))
    if team_name in factories:
        return json.dumps({ "result" : False })
    factories[team_name] = Factory(team_name, start_time, port)
    return json.dumps({ "result" : True })

@app.route("/get_teams", methods=["GET"])
def get_teams():
    return json.dumps({
        "teams" : [factories[key].id for key in factories]
    })

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

@app.route("/send_message", methods=["GET"])
def send_message():
    factory_id = request.args.get("team_id")
    sender = request.args.get("sender")
    subject = request.args.get("subject")
    body = request.args.get("body")
    factory = factories[factory_id]
    result = factory.send_message(sender, subject, body)
    return json.dumps({ "result" : result })

@app.route("/get_attacks", methods=["GET"])
def get_attacks():
    return test_factory.get_attacks_json()

@app.route("/send_attack", methods=["GET"])
def send_attack():
    factory_id = request.args.get("team_id")
    index = int(request.args.get("attack_index"))
    factory = factories[factory_id]
    result = factory.attack(index)
    return json.dumps({ "result" : result })



start_time = datetime.datetime.now()
test_factory = Factory("test", start_time, 1000)
factories = {}



def main():
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)  # Sets up flask server on port 5000

if __name__ == "__main__":
    main()