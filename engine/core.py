from flask import Flask, jsonify, request
import json
from time import time, sleep
from random import random
import datetime


app = Flask(__name__)
UPDATE_INTERVAL = 5


class Machine:
    def __init__(self, id):
        self.id = id
        self.enabled = False
        self.operational_cost = 8500
        self.product = "square"
        self.speed = 1500


    def get_dict(self):
        return {
            self.id : {
                "enabled" : self.enabled,
                "operational_cost" : self.operational_cost,
                "product" : self.product,
                "speed" : self.speed
            }
        }

    def get_json(self):
        return json.dumps(self.get_dict())



class Factory:
    def __init__(self, id, start_time):
        self.start_time = start_time
        self.total_updates = 0

        self.id = id
        self.money = 100000
        self.purchase_prices = {
            "square" : 10,
            "circle" : 40
        }
        self.sales_prices = {
            "square" : 18,
            "circle" : 75
        }
        self.machines = [
            Machine("machine_1"),
            Machine("machine_2"),
            Machine("machine_3")
        ]


    def update_factory(self):
        time = datetime.datetime.now()                  # Gets the time right now
        time_delta = (time - self.start_time).seconds   # Delta time in seconds
        updates = time_delta // UPDATE_INTERVAL         # Floor divide delta time by the update interval to get the total number of updates since the factory started
        new_updates = updates - self.total_updates      # Gets the number of updates needed to catch up
        self.total_updates = updates                    # Sets total finished updates to the new total

        for _ in range(updates):
            for machine in self.machines:
                if not machine.enabled:
                    continue
                self.money -= self.purchase_prices[machine.product] * machine.speed
                self.money += self.sales_prices[machine.product] * machine.speed
                self.money -= machine.operational_cost

    def get_dict(self):
        self.update_factory()

        return {
            self.id : {
                "money" : self.money,
                "purchase_prices" : self.purchase_prices,
                "sales_prices" : self.sales_prices,
                "machines" : {
                    "machine_1" : self.machines[0].get_dict(),
                    "machine_2" : self.machines[1].get_dict(),
                    "machine_3" : self.machines[2].get_dict()
                }
            }
        }

    def get_json(self):
        return json.dumps(self.get_dict())


@app.route("/get_factory_state", methods=["GET"])  
def get_factory():
    factory_id = int(request.args.get("id"))

    factory = factories[factory_id]

    return factory.get_json()


start_time = datetime.datetime.now()
factories = [
        Factory("factory_0", start_time),
        Factory("factory_1", start_time)
    ]



def main():
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)  # Sets up flask server on port 5000

if __name__ == "__main__":
    main()