
## Olympic CTF 2014 - Find da key (Misc 200)
### 07-09/02/2014 (48hr)

___

### Description: 

Task is very unusual: find the key. stego.txt

___
### Solution
The file contains many lines of base64 encoded strings:

```
U3RlZ2Fub2dyYXBoeSBpcyB0aGUgYXJ0IGFuZCBzY2llbmNlIG9m
IHdyaXRpbmcgaGlkZGVuIG1lc3NhZ2VzIGluIHN1Y2ggYSB3YXkgdGhhdCBubyBvbmV=
LCBhcGFydCBmcm9tIHRoZSBzZW5kZXIgYW5kIGludGVuZGVkIHJlY2lwaWVudCwgc3VzcGU=
Y3RzIHRoZSBleGlzdGVuY2Ugb2YgdGhlIG1lc3M=
.....
```

We decode these lines: `cat stego.txt | base64 --decode`
And we get an article, talking about steganography. Nothing important here.

Then we continue by decoding each line separately:
```
awk '{system("echo " $0 "| base64 --decode" ); print "" }' stego.txt
```

The interesting point here, is that each line doesn't contain a whole word, but many words are
truncated:
```
.....
, apart from the sender and intended recipient, suspe
cts the existence of the mess
age, a form of security through obscurity. T
.....
```

The information may be hidden in the length, or in the last characters. Trying to get the length
from each line, and decode it as ASCII, base64 with no luck. Then we get the last character of each
decoded line:

```
awk '{printf substr($0, length($0), 1)  }' stego_decoded.txt 
```

```
feesTaowhagsiti.ern s ,fb.umnil o a af.ero  wfeeosgo.btd:aenn.noedoh,sosn.w .rsr. r.o.rpd ddT df. eoc leo,ae.ternt ao  i.-gy
```

But again, we can't get anything from there.

Then a small observation comes to help us:

Get the second line: `IHdyaXRpbmcgaGlkZGVuIG1lc3NhZ2VzIGluIHN1Y2ggYSB3YXkgdGhhdCBubyBvbmV=`
Decode it:  writing hidden messages in such a way that no one
Then encoded again: `IHdyaXRpbmcgaGlkZGVuIG1lc3NhZ2VzIGluIHN1Y2ggYSB3YXkgdGhhdCBubyBvbmU=`

What happened? The same message has not the same encoding! If we look carefully the 
way that base 64 encodes, we'll see the following:

encode 2 bytes AB: `a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8` (bits)
then: `a1a2a3a4a5a6 | a7a8b1b2b3b4 | b5b6b7b8p1p2`, where `p1p2` are 2 padding bits

encode 1 byte A: `a1a2a3a4a5a6a7a8` (bits)
then: `a1a2a3a4a5a6 | a7a8p1p2p3p4`, where `p1p2p3p4` are 4 padding bits. Thus the encoded strings:

```
IHdyaXRpbmcgaGlkZGVuIG1lc3NhZ2VzIGluIHN1Y2ggYSB3YXkgdGhhdCBubyBvbmU=
IHdyaXRpbmcgaGlkZGVuIG1lc3NhZ2VzIGluIHN1Y2ggYSB3YXkgdGhhdCBubyBvbmV=
IHdyaXRpbmcgaGlkZGVuIG1lc3NhZ2VzIGluIHN1Y2ggYSB3YXkgdGhhdCBubyBvbmW=
IHdyaXRpbmcgaGlkZGVuIG1lc3NhZ2VzIGluIHN1Y2ggYSB3YXkgdGhhdCBubyBvbmX=
```

have all the same decoded text. The same is true for the following:

```
aGUgd29yZCBzdGVnYW5vZ3JhcGh5IGlzIG9mIEdyZWVrIG9yaWdpbiBhbmQgbWVhbnMgImNvbmNlYW==
......
aGUgd29yZCBzdGVnYW5vZ3JhcGh5IGlzIG9mIEdyZWVrIG9yaWdpbiBhbmQgbWVhbnMgImNvbmNlYQ==
aGUgd29yZCBzdGVnYW5vZ3JhcGh5IGlzIG9mIEdyZWVrIG9yaWdpbiBhbmQgbWVhbnMgImNvbmNlYf==
```

It's clear now that there's some information on the padding bits. 
```
bmV=    ---> 27 38 21 => 21 is 010101  => 01   is info
YW==    ---> 24 22    => 22 is 010110  => 0110 is info
```

We extract all these bits:

```
01000010011000010111001101100101010111110111001101101001011110000111010001111001010111110110011
00110111101110101011100100101111101110000011011110110100101101110011101000101111101100110011010
0101110110011001010000000000
```

Then we convert them to base64 string: `QmFzZV9zaXh0eV9mb3VyX3BvaW50X2ZpdmUA`
Finally we decode this string, and we get our flag: `Base_sixty_four_point_five`.

___
