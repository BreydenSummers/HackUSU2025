from factory import Message, Nerf
from random import randint

class Attack:
    def __init__(self, id, surface, nerf, message):        # Nerf(randint(10000, 99999), 3, 3, 0.5)
        self.id = id
        self.surface = surface
        self.nerf = nerf
        self.message = message



attacks = {
    "attacks" : [
        Attack(0, "production", Nerf(randint(10000, 99999), 3, 3, 0.5), Message("Info-Sec", "Threat Detected", "We were able to detect an intrusion on the network.")),
        Attack(1, "manufacturing", Nerf(randint(10000, 99999), 3, 3, 0.5), Message("Info-Sec", "Threat Detected", "We were able to detect an intrusion on the network.")),
        Attack(2, "assembly", Nerf(randint(10000, 99999), 3, 3, 0.5), Message("Info-Sec", "Threat Detected", "We were able to detect an intrusion on the network.")),
        Attack(3, "packing", Nerf(randint(10000, 99999), 3, 3, 0.5), Message("Info-Sec", "Threat Detected", "We were able to detect an intrusion on the network.")),
        Attack(4, "warehouse", Nerf(randint(10000, 99999), 3, 3, 0.5), Message("Info-Sec", "Threat Detected", "We were able to detect an intrusion on the network.")),
        Attack(5, "shipping", Nerf(randint(10000, 99999), 3, 3, 0.5), Message("Info-Sec", "Threat Detected", "We were able to detect an intrusion on the network."))
    ]
}