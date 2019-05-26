## PHDays Quals CTF 2014 - MiXer (RE 2000)
##### 25-27/01/2014 (48 hr)
___

### Description: 

Eventually we've put this elf in blender. Can you restore it for us?

___
### Solution

File is mixed. All we need to find how it's mixed and use the IDC script to unscramble it.

We know how a function starts (`push ebp`, and so on), so after a while we found
how code is mixed:

```
    55                    push   ebp
    89 e5                 mov    ebp,esp
    57                    push   edi
    56                    push   esi
    53                    push   ebx
    83 e4 f0              and    esp,0xfffffff0
    81 ec 30 04 00 00     sub    esp,0x430
```

Then we can apply the inverse transformation and we fix the binary.
Then we run it and we get the flag: `y0ur.f1rst.fl4g`.
___
