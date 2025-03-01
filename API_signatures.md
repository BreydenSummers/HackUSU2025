# API Signatures

## Factory

### Get Factory State

#### Call Signiture
```
GET http://[IP]:5000/get_factory_state?id=0
```
#### Return json Format
```json
{
   "id":"factory_0",
   "money":100000,
   "processes":{
      "purchasing":"1.0",
      "manufacturing":"1.0",
      "assembly":"1.0",
      "packing":"1.0",
      "warehouse":"1.0",
      "shipping":"1.0"
   },
   "attacks":[]
}
```

### Get Upgrades

#### Call Signiture
```
GET http://[IP]:5000/get_upgrades?id=0
```
#### Return json Format
```json
{
   "production" : [
    {"id":0, "name":"[NAME]", "description":"[DESCRIPTION]", "cost":1000},
    {"id":1, "name":"[NAME]", "description":"[DESCRIPTION]", "cost":2500}
   ],
   "defense" : [
    {"id":0, "name":"[NAME]", "description":"[DESCRIPTION]", "cost":1000},
    {"id":1, "name":"[NAME]", "description":"[DESCRIPTION]", "cost":2500}
   ],
   "offense" : [
    {"id":0, "name":"[NAME]", "description":"[DESCRIPTION]", "cost":1000},
    {"id":1, "name":"[NAME]", "description":"[DESCRIPTION]", "cost":2500}
   ]
}
```

### Purchase Upgrade

#### Call Signiture
```
GET http://[IP]:5000/purchase_upgrade?factory_id=0&category=production&upgrade_id=0
```
#### Return json Format
```json
{ "success" : true }
```