import json
import datetime
import random
import time
from upgrades import upgrades


UPDATE_INTERVAL = 1
RANDOMNESS_COEFFICIENT = 0.02


def random_offset():
    return ((random.random() - 0.5) * RANDOMNESS_COEFFICIENT) + 1


class Message:
    def __init__(self, subject, body):
        self.timestamp = str(datetime.datetime.now())
        self.subject = subject
        self.body = body

    def get_dict(self):
        return {
            "timestamp" : self.timestamp,
            "subject" : self.subject,
            "body" : self.body
        }


class Nerf:
    def __init__(self, id, delay=0, duration=0, effect=1.0):
        self.delay = delay
        self.duration = duration
        self.effect = effect
        self.id = id


class Process:
    def __init__(self):
        self.multiplier = 1.0
        self.stats = 1.0
        self.nerf = Nerf(0)

    def get_multiplier(self):
        if self.nerf.duration == 0:
            return self.multiplier
        if self.nerf.delay == 0:
            self.nerf.duration -= 1
            return self.multiplier * self.nerf.effect
        self.nerf.delay -= 1
        return self.multiplier
    
    def __repr__(self):
        return str(self.stats)
    
    def __str__(self):
        return str(self.stats)


class Factory:
    def __init__(self, id, start_time):
        self.start_time = start_time
        self.total_updates = 0

        self.id = id
        self.money = 100000
        self.base_income = 1000

        self.processes = {
            "purchasing" : Process(),
            "manufacturing" : Process(),
            "assembly" : Process(),
            "packing" : Process(),
            "warehouse" : Process(),
            "shipping" : Process()
        }

        self.attacks = []

        self.upgrades = upgrades
        self.messages = [
            Message("Test Email", "Great job, you learned how to check your email! Make sure you come back here often to check for important updates!")
        ]

    def update_factory(self):
        time = datetime.datetime.now()                  # Gets the time right now
        time_delta = (time - self.start_time).seconds   # Delta time in seconds
        updates = time_delta // UPDATE_INTERVAL         # Floor divide delta time by the update interval to get the total number of updates since the factory started
        new_updates = updates - self.total_updates      # Gets the number of updates needed to catch up


        self.attacks = []

        if new_updates == 0:
            return None
        for _ in range(new_updates):
            self.total_updates += 1
            random.seed(self.total_updates)
            subtotal = self.base_income
            for key, step in self.processes.items():    # Iterates through every process and applies the multiplier with a small random coefficient
                subtotal *= (step.get_multiplier() * random_offset())
                if step.nerf.delay == 0 and not step.nerf.duration == 0:
                    if not step.nerf.id in self.attacks:
                        self.attacks.append(step.nerf.id)
            print(subtotal)
            self.money += subtotal
            self.money = int(self.money)

    def purchase_upgrade(self, category, id):
        upgrade = self.upgrades[category][id]
        if self.money < upgrade.cost:
            return False
        if category == "production":
            self.processes[upgrade.process].multiplier = upgrade.effect(self.processes[upgrade.process].multiplier)
            upgrade.cost = int(upgrade.scale(upgrade.cost))
        return True

    def get_state_json(self):
        return json.dumps({
            "id" : self.id,
            "money" : int(self.money),
            "processes" : {key : str(value) for key, value in self.processes.items()},
            "attacks" : self.attacks
        })
    
    def get_upgrades_json(self):
        return json.dumps({
            "production" : [upgrade.get_dict() for upgrade in self.upgrades["production"]],
            "defense" : [upgrade.get_dict() for upgrade in self.upgrades["defense"]],
            "offense" : [upgrade.get_dict() for upgrade in self.upgrades["offense"]]
        })
    
    def get_messages_json(self):
        return json.dumps({
            "messages" : [message.get_dict() for message in self.messages]
        })



if __name__ == "__main__":
    test_factory = Factory("test", datetime.datetime.now())
    test_factory.processes["purchasing"].nerf = Nerf(1001, 3, 3, 0.2)

    time.sleep(2)
    test_factory.update_factory()
    print(test_factory.get_state_json())