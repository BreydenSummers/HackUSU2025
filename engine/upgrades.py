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
        Upgrade(1, "Manufacturing Efficiency", "Increases manufacturing efficiency by 5%.", 2500, "purchasing", lambda a : a * 1.05, lambda a : a * 1.1),
        Upgrade(2, "Assembly Speed", "Increases assembly speed by 10 items/minute.", 1000, "assembly", lambda a : a + 0.1, lambda a : a + 1000),
        Upgrade(3, "Packing Space", "Allows you to pack boxes with 10%\ less free space.", 7500, "packing", lambda a : a + ((a-2)/4), lambda a : a + 2500),
        Upgrade(4, "Warehouse Size", "Adds 1000 square feet to your warehouse.", 1000, "warehouse", lambda a : a * 1.02, lambda a : a + 1000),
        Upgrade(5, "Shipping Fleet", "Adds an additional vehicle to your shipping fleet.", 25000, "shipping", lambda a : a + ((a-3)/10), lambda a : a * 1.1),
    ],
    "defense" : [],
    "offense" : []
}