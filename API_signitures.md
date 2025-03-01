# API Signatures

## Factory

### Call Signiture
GET http://\[IP\]:5000/get_factory_state?id=1

### Return json Format
```json
{
   "factory":{
      "purchase_prices":{
         "square":10,
         "circle":40
      },
      "sales_prices":{
         "square":18,
         "circle":75
      },
      "machines":{
         "machine_1":{
            "enabled":true,
            "operational_cost":8500,
            "product":"square",
            "speed":1500
         },
         "machine_2":{
            "enabled":true,
            "operational_cost":4000,
            "product":"circle",
            "speed":600
         },
         "machine_3":{
            "enabled":false,
            "operational_cost":0,
            "product":"square",
            "speed":0
         }
      }
   }
}
```