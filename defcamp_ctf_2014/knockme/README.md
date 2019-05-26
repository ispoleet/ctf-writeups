## DEFCAMP CTF 2014 - Knock me (Network 300)

##### 18-19/10/2014 (24hr)
___

### Description
```
	- Knock, knock!
	- Who's there?
	- Leet
	- Leet who?
	- Elite
	10.13.37.23
```


___
### Solution

It looks like a port knocking. We scan with nmap but all ports are closed.
So we try port knocking on ports 1337 and 31337:

```
	nmap -Pn --host_timeout 201 --max-retries 0 -p 1337  10.13.37.23
	nmap -Pn --host_timeout 201 --max-retries 0 -p 31337 10.13.37.23
```

If we see the packets on wireshark, we'll that after the 2 port knocks, server
10.20.0.1 attempts to connect to us to a local port. So we must configure our 
firewall to forward all incoming connections to a specified port.

First of all we enable port forwarding on eth0 and tun0 (the VPN connection) 
interfaces:
```
	echo '1' > /proc/sys/net/ipv4/conf/tun0/forwarding
	echo '1' > /proc/sys/net/ipv4/conf/eth0/forwarding
```

And we clear the iptable rules:
```	
    iptables -F
	iptables -X
	iptables -t nat -F
	iptables -t nat -X
	iptables -t mangle -F
	iptables -t mangle -X
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
```

Then we forward incoming connections on VPN (tun0) interface to ports 3000 through 
10000 to port 9999 on our machine (128.211.189.84):
```
	iptables -t nat -A PREROUTING -p tcp -i tun0 --dport 3000:10000 \
			 -j DNAT --to-destination 128.211.189.84:9999

	iptables -A FORWARD -p tcp -d 128.211.189.84 --dport 9999 -m state \
			 --state NEW,ESTABLISHED,RELATED -j ACCEPT
```

(we user nat table because we have a new incoming connection)
We can verify our rules by listing all the rules:
```
	iptables -L -t nat
```

```
		root@vasilikoula:~# iptables -L -t nat
		Chain PREROUTING (policy ACCEPT)
		target     prot opt source               destination         
		DNAT       tcp  --  anywhere             anywhere             tcp dpts:3000:webmin to:128.211.189.84:9999
		DNAT       tcp  --  anywhere             anywhere             tcp dpts:3000:webmin to:128.211.189.84:9999

		Chain INPUT (policy ACCEPT)
		target     prot opt source               destination         

		Chain OUTPUT (policy ACCEPT)
		target     prot opt source               destination         

		Chain POSTROUTING (policy ACCEPT)
		target     prot opt source               destination         
```

Then we setup a server on port 9999:
```
	nc -nlvv -p9999
```


And we make the port knocking:
```
	nmap -Pn --host_timeout 201 --max-retries 0 -p 1337  10.13.37.23;\
	nmap -Pn --host_timeout 201 --max-retries 0 -p 31337 10.13.37.23
```
We make it twice and we get on the listening port the following data:
```	
    770+1336 770+1336 0+0 770+1477 770+1477 0+0 770+1477 770+1477 770+1477 0+0 697+1336 
	697+1336 697+1336 0+0 770+1336 770+1336 0+0 697+1477 697+1477 0+0 697+1477 0+0 770+1477 
	770+1477 770+1477 0+0 852+1336 852+1336 0+0 852+1336 0+0
```

A quick search on google shows that these numbers are DTMF frequencies. Each pair 
corresponds to a digit in the keypad. We decode it:
```
	770+1336		==> 5
	770+1336 		==> 5
	0+0 			==> 0
	770+1477 		==> 6
	770+1477 		==> 6
	0+0 			==> 0
	770+1477 		==> 6
	770+1477 		==> 6
	770+1477 		==> 6
	0+0 			==> 0
	697+1336 		==> 2
	697+1336 		==> 2
	697+1336 		==> 2
	0+0 			==> 0
	770+1336 		==> 5
	770+1336 		==> 5
	0+0 			==> 0
	697+1477 		==> 3
	697+1477 		==> 3
	0+0				==> 0
	697+1477 		==> 3
	0+0 			==> 0
	770+1477 		==> 6
	770+1477 		==> 6
	770+1477 		==> 6
	0+0 			==> 0
	852+1336 		==> 8
	852+1336 		==> 8
	0+0 			==> 0
	852+1336 		==> 8
	0+0				==> 0
```

So the numbers are: 55 66 666 222 55 33 3 666 88 8
These are the buttons that pressed from a cell phone during a text message.
So 55 means that 5 pressed twice, so the character is 'k'. 66 means that 66
pressed twice and is the letter 'n'. We continue until we decrypt all the 
letters:
```
	55 66 666 222 55 33 3 666 88 8
	k  n  o   c   k  e  d o   u  t 
```

So the flag is `knockedout` :)

___
