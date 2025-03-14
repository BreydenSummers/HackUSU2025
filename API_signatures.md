# API Signatures

## Factory

### Add Team

#### Call Signature
```
GET http://[IP]:5000/add_team?team_id=team_1&port=6105
```
#### Return json Format
```json
{ "success" : true }
```

### Get Teams

#### Call Signature
```
GET http://[IP]:5000/get_teams
```
#### Return json Format
```json
{ "teams" : ["team_1", "team_2"] }
```

### Get Factory State

#### Call Signature
```
GET http://[IP]:5000/get_factory_state?team_id=team_1
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

#### Call Signature
```
GET http://[IP]:5000/get_upgrades?team_id=team_1
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

#### Call Signature
```
GET http://[IP]:5000/purchase_upgrade?team_id=team_1&category=production&upgrade_id=0
```
#### Return json Format
```json
{ "success" : true }
```

### Get Messages

#### Call Signature
```
GET http://[IP]:5000/get_messages?team_id=team_1
```
#### Return json Format
```json
{
   "messages" : [
      {
         "timestamp":"[DATETIME]",
         "sender":"[SENDER]",
         "subject":"[SUBJECT]",
         "body":"[BODY]"
      },
      {
         "timestamp":"[DATETIME]",
         "sender":"[SENDER]",
         "subject":"[SUBJECT]",
         "body":"[BODY]"
      }
   ]
}
```

### Get Messages

#### Call Signature
```
GET http://[IP]:5000/send_message?team_id=team_1&sender=admin&subject=SUBJECT&body=BODY
```
#### Return json Format
```json
{ "success" : true }
```

### Get Attacks

#### Call Signature
```
GET http://[IP]:5000/get_attacks
```
#### Return json Format
```json
{
   "attacks":[
      {
         "id":0,
         "surface":"production"
      },
      {
         "id":1,
         "surface":"manufacturing"
      },
   ]
}
```

### Send Attack

#### Call Signature
```
GET http://144.39.111.253:5000/send_attack?team_id=team_1&attack_index=0
```
#### Return json Format
```json
{ "success" : true }
```