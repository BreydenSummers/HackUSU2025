# API Signatures

## Factory

### Call Signiture
```
GET http://[IP]:5000/get_factory_state?id=0
```

### Return json Format
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