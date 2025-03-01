class Upgrade:
    def __init__(self, id, name, description, cost, process, effect, scale):
        self.id = id
        self.name = name
        self.description = description
        self.cost = cost
        self.process = process
        self.effect = effect
        self.scale = scale

    def get_dict(self):
        return {
            "id" : self.id,
            "name" : self.name,
            "description" : self.description,
            "cost" : self.cost
        }


upgrades = {
    "production" : [
        Upgrade(0, "Purchasing Cost", "Decreases the cost of materials in the production line by 10%.", 10000, "purchasing", lambda a : a * 1.1, lambda a : a * 1.25),
        Upgrade(1, "Manufacturing Efficiency", "Increases manufacturing efficiency by 5%.", 2500, "manufacturing", lambda a : a * 1.05, lambda a : a * 1.1),
        Upgrade(2, "Assembly Speed", "Increases assembly speed by 10 items/minute.", 1000, "assembly", lambda a : a + 0.1, lambda a : a + 1000),
        Upgrade(3, "Packing Space", "Allows you to pack boxes with 10% less free space.", 7500, "packing", lambda a : a + ((a-2)/4), lambda a : a + 2500),
        Upgrade(4, "Warehouse Size", "Adds 1000 square feet to your warehouse.", 1000, "warehouse", lambda a : a * 1.02, lambda a : a + 1000),
        Upgrade(5, "Shipping Fleet", "Adds an additional vehicle to your shipping fleet.", 25000, "shipping", lambda a : a + ((a-3)/10), lambda a : a * 1.1),
    ],
    "defense" : [
        Upgrade(0, "Password Policy", "Protects against phishing attempts.", 5000, "purchasing", 1, lambda a : a * 1.5),
        Upgrade(1, "Network Segmentation", "Seperates vulnerable equipment from compromised networks.", 5000, "manufacturing", 1, lambda a : a * 1.5),
        Upgrade(2, "System Hardening", "Decreases attack surface by disabling non-esential services.", 5000, "assembly", 1, lambda a : a * 1.5),
        Upgrade(3, "Access Control", "Prevents users from accessing unnecesary resources.", 5000, "packing", 1, lambda a : a * 1.5),
        Upgrade(4, "Firewall", "Only allows certain services to be accesed through the internet.", 5000, "warehouse", 1, lambda a : a * 1.5),
        Upgrade(5, "Hardware Upgrades", "Protects against zero-day vulnerabilities.", 5000, "shipping", 1, lambda a : a * 1.5)
    ]
}





