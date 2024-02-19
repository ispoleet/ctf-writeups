## Insomni'Hack CTF Finals 2022 - Echo (RE)
##### 25/03/2022 (10hr)
___

Binary consists of a single function (`main`) which is approximately `~138KB`. If we look at the
decompiled code we can observe some patterns:
```c
__int64 __fastcall main(int a1, char **a2, char **a3) {
  /* variable declarations */

  v3205 = __readfsqword(0x28u);
  v404 = 0;
  v2004 = a2[1];
  v2005 = &v405;
  v2006 = &v406;
  v2007 = &v407;
  v405 = 0x2AF5325514FC82F4LL;
  v406 = 0x240259D06F7FD4D6LL;
  v407 = 0x4EF78C25847C57CALL;
  if ( !*v2004 || (*v2004 ^ 0x1547DDD9782FDC18LL) != 0x1547DDD9782FDC21LL ) {
    do
      v3 = v404++;
    while ( v3 < *v2004 );
  }
  v2008 = &v409;
  v2009 = &v410;
  v2010 = &v411;
  v409 = 0x23456AB6D58328E5LL;
  v410 = 0x51A8DD0A661ACBB9LL;
  v411 = 0x74EE47C13B9DF49ELL;
  v408 = 0xAACA3AC8AF39AF5LL;
  if ( !v2004[1] || (v408 ^ v2004[1]) != 0xAACA3AC8AF39A91LL ) {
    do
      v4 = v404++;
    while ( v4 < v2004[1] );
  }  

  /* ... */

  v3199 = &v1997;
  v3200 = &v1998;
  v3201 = &v1999;
  v1997 = 0x1A318D066887C48CLL;
  v1998 = 0xB8DBD227820DFD0LL;
  v1999 = 0x25BF4A28E0A8A45CLL;
  v1996 = 0x727CB176D09442A4LL;
  if ( !v2004[398] || (v1996 ^ v2004[398]) != 0x727CB176D09442C1LL )
  {
    do
      v401 = v404++;
    while ( v401 < v2004[398] );
  }
  v3202 = &v2001;
  v3203 = &v2002;
  v3204 = &v2003;
  v2001 = 0x8E7FC8DCC9115A5LL;
  v2002 = 0x355CC3039E5F3779LL;
  v2003 = 0x3E44BF916AF04D1ELL;
  v2000 = 0x23BA8E8D371D2B1BLL;
  if ( !v2004[399] || (v2000 ^ v2004[399]) != 0x23BA8E8D371D2B7FLL )
  {
    do
      v402 = v404++;
    while ( v402 < v2004[399] );
  }

  if ( !v404 )
    system("cat flag");

  return 0LL;
}
```

Variable `v2004` holds the value of `argv[1]`. At each step we check the next character of `argv[1]`
and if it is not the expected one, we incremenet `v404`. To get the flag we need to make sure that
`v404` remains `0`. For the first one:
```c
v2005 = &v405;
v2006 = &v406;
v2007 = &v407;
v405 = 0x2AF5325514FC82F4LL;
v406 = 0x240259D06F7FD4D6LL;
v407 = 0x4EF78C25847C57CALL;
if ( !*v2004 || (*v2004 ^ 0x1547DDD9782FDC18LL) != 0x1547DDD9782FDC21LL ) {
  do
    v3 = v404++;
  while ( v3 < *v2004 );
}
```

We want: `*v2004` or `argv[1][0]` XORed with `0x18` to be `0x21`.
That is: `argv[1][0] == 0x18 ^ 0x21 == 0x39 == '9'`. Let's move on the second one:
```c
v2008 = &v409;
v2009 = &v410;
v2010 = &v411;
v409 = 0x23456AB6D58328E5LL;
v410 = 0x51A8DD0A661ACBB9LL;
v411 = 0x74EE47C13B9DF49ELL;
v408 = 0xAACA3AC8AF39AF5LL;
if ( !v2004[1] || (v408 ^ v2004[1]) != 0xAACA3AC8AF39A91LL ) {
  do
    v4 = v404++;
  while ( v4 < v2004[1] );
} 
```  

Here we want `v2004[1]` or `argv[1][1]` to be equal with `v408 ^ 0x91 == 0xF5 ^ 0x91 == 0x64 == 'd'`.
Obviously we cannot continue this manually as `argv[1]` contains `400` characters.

The simplest way to automate this process, is to use a regex to parse the decompiled code and
extract the values for each `argv[1]`.

By using the [echo_dump.py](./echo_dump.py) script we can recover the expected password:
```
9d1b26b0e8a7f0cfd00ad2914789b7e177c672d21c0e3cd40ce26b2327cb2558
a7dc49f17cc23315e2b2660dc1ca697f036b0fe01a39e5b7855d807a9fc31fd2
fe3c2d8c18010d69e54efcceb277a0cbd03b6a920ab0ce227829649e44dec721
8638c283ca13f96a1a0684576545ca900e991db8f4653f1e7b730ee7cb031917
75c66414decfbdb84bf4fdd3bbdef9d66b8d8c11bc1df5160c8be4a619c91ed0
e45ad1c8248e223a84ef2604ee1520adc23127e87d767f2315292e2b0782f06b
9f71a364bfadd8ed
```

We try this password on the remote server and we get the flag:
```
ispo@leet:~/ctf/insomnihack_2022/echo$ nc echo.insomnihack.ch 6666
9d1b26b0e8a7f0cfd00ad2914789b7e177c672d21c0e3cd40ce26b2327cb2558a7dc49f17cc23315e2b2660dc1ca697f036b0fe01a39e5b7855d807a9fc31fd2fe3c2d8c18010d69e54efcceb277a0cbd03b6a920ab0ce227829649e44dec7218638c283ca13f96a1a0684576545ca900e991db8f4653f1e7b730ee7cb03191775c66414decfbdb84bf4fdd3bbdef9d66b8d8c11bc1df5160c8be4a619c91ed0e45ad1c8248e223a84ef2604ee1520adc23127e87d767f2315292e2b0782f06b9f71a364bfadd8ed
INS{__0h_My_D34r!__D33p3R__d4ddy!$}^C
```
___

