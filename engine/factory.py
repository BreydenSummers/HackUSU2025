import json
import datetime
import random
import time
from upgrades import upgrades
import attack


UPDATE_INTERVAL = 5
RANDOMNESS_COEFFICIENT = 0.02


def random_offset():
    return ((random.random() - 0.5) * RANDOMNESS_COEFFICIENT) + 1


class Message:
    def __init__(self, sender, subject, body):
        self.timestamp = str(datetime.datetime.now()).split(".")[0]
        self.sender = sender
        self.subject = subject
        self.body = body

    def get_dict(self):
        return {
            "timestamp" : self.timestamp,
            "sender" : self.sender,
            "subject" : self.subject,
            "body" : self.body
        }


class Nerf:
    def __init__(self, id=random.randint(100000, 999999), delay=0, duration=0, effect=1.0, message=None):
        self.delay = delay
        self.duration = duration
        self.effect = effect
        self.id = id
        self.message = message
        self.attack_id = None


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

attack_map = {
    "purchasing" : "brute_force",
    "manufacturing" : "malware_activity",
    "assembly" : "ddos_attack",
    "packing" : "data_exfiltration",
    "warehouse" : "privilege_escalation",
    "shipping" : "insider_threat"
}

class Factory:
    def __init__(self, id, start_time, wazuh_port):
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
            Message("Admin", "Welcome!", "Great job, you learned how to check your email. Make sure you come back here often to check for important updates!")
        ]

        self.simulator = attack.FactoryAttackSimulator(host='localhost', port=wazuh_port)

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
                step.stats = 1
                subtotal *= (step.get_multiplier() * random_offset())
                if step.nerf.duration and not step.nerf.attack_id:
                    step.nerf.attack_id = self.simulator.start_attack(attack_map[key], section=key)
                    print(f"Starting attack {attack_map[key]} on {self.id}.")
                if step.nerf.delay == 0 and not step.nerf.duration == 0:
                    step.stats = 0
                    if not step.nerf.id in self.attacks: # Attack starts
                        self.attacks.append(step.nerf.id)
                elif step.nerf.delay == 0 and step.nerf.duration == 0 and step.nerf.message: # Attack ends
                    print(f"Stopping attack {step.nerf.attack_id} on {self.id}.")
                    self.simulator.stop_attack(step.nerf.attack_id)
                    self.messages.append(step.nerf.message)
                    step.nerf = Nerf()
            self.money += subtotal
            self.money = int(self.money)

    def purchase_upgrade(self, category, id):
        upgrade = self.upgrades[category][id]
        if self.money < upgrade.cost:
            return False
        if category == "production":
            self.money -= upgrade.cost
            self.processes[upgrade.process].multiplier = upgrade.effect(self.processes[upgrade.process].multiplier)
            upgrade.cost = int(upgrade.scale(upgrade.cost))
        if category == "defense":
            self.money -= upgrade.cost
            self.processes[upgrade.process].nerf.duration = 0
            self.processes[upgrade.process].nerf.delay = 0
            upgrade.cost = int(upgrade.cost * 1.5)
        return True

    def get_state_json(self):
        self.update_factory()
        return json.dumps({
            "id" : self.id,
            "money" : int(self.money),
            "processes" : {key : str(value) for key, value in self.processes.items()},
            "attacks" : self.attacks
        })
    
    def get_upgrades_json(self):
        return json.dumps({
            "production" : [upgrade.get_dict() for upgrade in self.upgrades["production"]],
            "defense" : [upgrade.get_dict() for upgrade in self.upgrades["defense"]]
        })
    
    def get_messages_json(self):
        return json.dumps({
            "messages" : [message.get_dict() for message in self.messages.copy()]
        })
    
    def send_message(self, sender, subject, body):
        message = Message(sender, subject, body)
        self.messages.append(message)
        return True
    
    def get_attacks_json(self):
        return json.dumps({
            "attacks" : [attack.get_dict() for attack in attack_list["attacks"]]
        })

    def attack(self, attack_index):
        attack = attack_list["attacks"][attack_index]
        self.processes[attack.surface].nerf = attack.nerf
        return True



class Attack:
    def __init__(self, id, surface, nerf):        # factory.Nerf(randint(10000, 99999), 3, 3, 0.5)
        self.id = id
        self.surface = surface
        self.nerf = nerf
    
    def get_dict(self):
        return {
            "id" : self.id,
            "surface" : self.surface
        }

attack_list = {
    "attacks" : [
        Attack(0, "purchasing", Nerf(random.randint(10000, 99999), 3, 999, 0.5, Message("Info-Sec", "Threat Detected", "We were able to detect an intrusion on the network."))),
        Attack(1, "manufacturing", Nerf(random.randint(10000, 99999), 3, 999, 0.5, Message("Info-Sec", "Threat Detected", "We were able to detect an intrusion on the network."))),
        Attack(2, "assembly", Nerf(random.randint(10000, 99999), 0, 999, 0.5, Message("Info-Sec", "Threat Detected", "We were able to detect an intrusion on the network."))),
        Attack(3, "packing", Nerf(random.randint(10000, 99999), 3, 999, 0.5, Message("Info-Sec", "Threat Detected", "We were able to detect an intrusion on the network."))),
        Attack(4, "warehouse", Nerf(random.randint(10000, 99999), 3, 999, 0.5, Message("Info-Sec", "Threat Detected", "We were able to detect an intrusion on the network."))),
        Attack(5, "shipping", Nerf(random.randint(10000, 99999), 3, 999, 0.5, Message("Info-Sec", "Threat Detected", "We were able to detect an intrusion on the network.")))
    ]
}
if __name__ == "__main__":
    test_factory = Factory("test", datetime.datetime.now(), 0000)
    test_factory.attack(2)
 
    while True:
        time.sleep(1)
        test_factory.update_factory()
        print(test_factory.get_state_json(), test_factory.get_messages_json())