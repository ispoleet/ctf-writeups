## Hack.lu CTF 2014 - Dalton's Corporate Security Safe for Business (Web 200)
##### 21-23/10/2014 (48hr)
___

### Description: 
The Dalton Brothers are tricking people into buying their “safe” locks. So they can 
rob them afterwards. The lock has some safety features, as it resets itself after a
few seconds. It also requires a lot of valid inputs before it's letting you open it. 
Please find out what their weakness is and report back.


___
### Solution

The password is generated with javascript. Unfortunately, the javascript is created 
randomly too. However there are some characteristics that allow us to break it. Let's 
start by writing the js code:

```javascript
	var f=c.getContext('2d');
	var i=f.createLinearGradient(0,0,c.width,0);
	i.addColorStop('0','#12112e');
	var g=/5/.source;
	i.addColorStop('1.0','#97e392');
	f.fillStyle=i;
	f.font='italic 13px courier';
	f.fillText(g,73,15);
	//-------------------------------------------------------------------
	var o=f.createLinearGradient(0,0,c.width,0);
	var e=atob('Yg==');
	o.addColorStop('0','#84cc99');
	o.addColorStop('1.0','#76bbe3');
	f.fillStyle=o;
	f.font='bold 12px helvetica';
	f.fillText(e,51,16);
	//-------------------------------------------------------------------
	var d=atob('Mg==');
	var l=f.createLinearGradient(0,0,c.width,0);
	l.addColorStop('0','#1b78ca');
	l.addColorStop('1.0','#0371e4');
	f.fillStyle=l;
	f.font='italic 14px verdana';
	f.fillText(d,35,17);
	//-------------------------------------------------------------------
	var u=f.createLinearGradient(0,0,c.width,0);
	var a=(7).toString(36);
	u.addColorStop('0','#c32394');
	u.addColorStop('1.0','#59609c');
	f.fillStyle=u;
	f.font='bold 14px sans-serif';
	f.fillText(a,21,19);
	//-------------------------------------------------------------------
	var l=f.createLinearGradient(0,0,c.width,0);
	l.addColorStop('0','#390abc');
	l.addColorStop('1.0','#fc7710');
	f.fillStyle=l;
	var d=(3).toString(36);
	f.font=' 16px sans-serif';
	f.fillText(d,64,15);
	//-------------------------------------------------------------------
	var v=String.fromCharCode(101);
	var t=f.createLinearGradient(0,0,c.width,0);
	t.addColorStop('0','#233a6b');
	t.addColorStop('1.0','#769c56');
	f.fillStyle=t;
	f.font='italic 11px helvetica';
	f.fillText(v,3,16);
	//-------------------------------------------------------------------
	var z=f.createLinearGradient(0,0,c.width,0);
	z.addColorStop('0','#f2b4db');
	z.addColorStop('1.0','#f89b8a');
	f.fillStyle=z;
	var h=atob('Yw==');
	f.font=' 12px arial';
	f.fillText(h,12,15);
	//-------------------------------------------------------------------
	var e=atob('OA==');
	var j=f.createLinearGradient(0,0,c.width,0);
	j.addColorStop('0','#1c40a7');
	j.addColorStop('1.0','#f31cf5');
	f.fillStyle=j;
	f.font='bold 12px arial';
	f.fillText(e,42,20);
	//-------------------------------------------------------------------
```

It's clear that the function fillText() (there are exactly 8 calls) is used to write 
the captcha characters. The 1st argument of fillText() indicates the character to print, 
while the 2nd argument, the x-position in the canvas object. 

The first problem is that the variables are re-used. This means that a variable 'x' can
contain a string character for the captcha and later reused to store a different letter.
So we can use the variable names to read the captcha characters.

Another problem is that the characters are not printed with the right-to-left order. So
we have to find out the correct order too.

```
NOTE 1: all capthca are strings, 1 characters long
NOTE 2: fillText is used to display the 1 character string
NOTE 3: there are exactly 8 fillText() calls
NOTE 4: the 1st argument on fillText() is a 1 character long variable
NOTE 5: the 2nd argument of fillText() indicates the x-coordinate. Sorting calls by
		this number can reveal the order
```

So what can we do? One solution is to log the calls to fillText(), and then recover
the captcha from the arguments. Another solution is to emulate the js code. We'll do
the 2nd approach (see the other writeup for the 1st solution).

Hint: We don't care how the numbers are calculated. We use eval() to force the numbers
to get calculated and then we see their value.

We'll run this script on Web Console on our browser. First of all we must isolate the 
js code (there's only one pair of <script> tags). Then for we emulate the js code and 
we stop at each call to fillText:
___


```javascript
// isolate js code
html = $('html').innerHTML.toString();
jscode = html.substr( html.search('<script>' ) + 8, 
                      html.search('</script>')-(html.search('<script>' ) + 8));

str = jscode;
unscrumble = [];						// store captcha here

for( ii=0; ii<8; ii++ )					// expect 8 captcha letters
{
	pat = str.search( ".fillText" );	// find next fillText()
	prev = str.substr( 0, pat-1 );		// get all the code before (without letter before '.')
	
	eval(prev);							// run the commands

	args = str.substr(pat+9, 9 );		// get arguments of fillText()

	// args are in form (a,11,22)
	
	char = eval( args[1] )				// get first argument value = get a captcha
	pos  = parseInt(args[3] + args[4])	// get x-coordinate
	
	unscrumble[ Math.floor(pos / 10) ] = char

	str = str.substr(pat+9) 			// go to the next fillText()
}

unscrumble.join("")						// convert to string

// set captcha to text object, and submit form 
document.getElementsByName("solution")[0].value = unscrumble.join("")
document.forms[0].submit()
```

So, all we have to do is to paste this code in the web console. The code will submit
the form with the correct captcha and then a new captcha will appear. We do this
several times, until the security zone button appeared, and we get the flag:

```
	https://wildwildweb.fluxfingers.net:1422/?login=rRrtTE0WYFh5bVHToYQwKyvP
	FLAG :D :D fef9565c97c3a62fe10d2a0084a9e8179d72f4a05084997cb80e900d1a77a42e3
```

The idea here, is to emulate the js code until the first occurence of fillText. 
Then we freeze the emulation and we extract the arguments of fillText(). Because
variable's name that contain the captcha is 1 character long we can get it's value:
```
	eval( args[1] )	
```


(we don't care how value is calculated. We let the script calculate the value and 
then we read it). Then we set the character into a table, and finally we sort the
table in order to get the final captcha.
