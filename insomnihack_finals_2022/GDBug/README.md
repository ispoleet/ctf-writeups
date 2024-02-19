## Insomni'Hack CTF Finals 2022 - GDBug (RE)
##### 25/03/2022 (10hr)
___


We load the binary into IDA Pro. Binary is very small and easy to understand:
```c
__int64 __fastcall main(int argc, char **argv, char **argp) {
  __int64 result; // rax
  const char *v4; // rax
  int i; // [rsp+18h] [rbp-18h]
  int v6; // [rsp+1Ch] [rbp-14h]

  putchar(10);
  puts("      _/_/_/  _/_/_/    _/_/_/");
  puts("   _/        _/    _/  _/    _/  _/    _/    _/_/_/");
  puts("  _/  _/_/  _/    _/  _/_/_/    _/    _/  _/    _/");
  puts(" _/    _/  _/    _/  _/    _/  _/    _/  _/    _/");
  puts("  _/_/_/  _/_/_/    _/_/_/      _/_/_/    _/_/_/");
  puts("                                             _/");
  puts("                                        _/_/");
  putchar(10);

  if ( ptrace(PTRACE_TRACEME, 0LL, 1LL, 0LL) == -1 ) {
    puts("   [-] Registration unknown");
    puts("   [-] Dream flag is INS{W0ULDNT-1T-B3-T00-34SY}\n");
    result = 0xFFFFFFFFLL;
  } else {
    if ( argc == 2 ) {
      if ( !strcmp(argv[1], "--debug") ) {
        puts("   [-] Debug mode");
        v4 = u_xor_with_0x80(glo_fake_flag);
        printf("   [-] Current flag is %s\n\n", v4);
      } else {
        printf("[+] Checking serial %s\n", argv[1]);
        v6 = 1337;
        for ( i = 0; i < strlen(argv[1]); ++i )
          v6 += argv[1][i];
        if ( v6 == 2872
          && strlen(argv[1]) == 24              // serial form: ????-????-????-????-????
          && argv[1][4] == '-'
          && argv[1][9] == '-'
          && argv[1][14] == '-'
          && argv[1][19] == '-' ) {
          puts("   [-] Registration successful");
          printf("   [-] Your flag is INS{%s}\n\n", argv[1]);
        } else {
          puts("   [-] Registration failed");
          puts("   [-] Try again\n");
        }
      }
    } else {
      puts("Usage: ./GDBug <serial>\n");
    }
    result = 0LL;
  }
  return result;
}
```

Program first it uses the classic `ptrace` trick to check if it's being debugged and if so it
displays a fake flag: `INS{W0ULDNT-1T-B3-T00-34SY}`. Then it checks if the `--debug` command line
argument is present and if so it displays another fake flag: `INS{Th1$Fl4gSuck$}`. If none of these
happen it checks if `argv[1]` full fils the following requirements:

* It has 24 characters
* Characters at locations `4`, `9`, `14` and `19` are `-`
* The total sum of all characters (as ASCII values) is `2872 - 1337 = 1535`

That is, the flag/serial is in the form: `????-????-????-????-????` and the only requirement is 
the sum of all characters to be `1535`.  As you can expect there is an exponential number of flags.
Let's generate some of them:
```python
charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789'
serial = '....-....-....-....-....'
target_sum = 2872-1337 - 0x2D*4

def recursion(serial, target_sum):
    if len(serial) > 24-4: return
    elif target_sum < 0: return
    elif target_sum == 0:
        insert_into = lambda s, l, c: s[:l] + c + s[l:]
        # Insert dashes into serial
        serial = insert_into(serial, 4, '-')
        serial = insert_into(serial, 9, '-')
        serial = insert_into(serial, 14, '-')
        serial = insert_into(serial, 19, '-')

        print(f'[+] Serial Found: {serial}')

    for c in charset:
        recursion(serial + c, target_sum - ord(c))

recursion('', target_sum)
```

Below are some valid serials:
* `AAAA-AAAA-AAAA-AAAA-AFZZ`
* `AAAA-AAAA-AAAA-AAAA-AGYZ`
* `AAAA-AAAA-AAAA-AAAA-AGZY`
* `AAAA-AAAA-AAAA-AAAA-AHXZ`
* `AAAA-AAAA-AAAA-AAAA-AHYY`

Since we only check the sum of the serials any valid combination of them will also be a valid
serial. For example `AAAA-AAAA-AAAA-AAAA-AFZZ` --> `AAAA-AAZA-AAZA-AAFA-AAAA` is also valid. We
try them to verify that they are correct:
```
ispo@leet:~/ctf/insomnihack_2022/GDBug$ ./GDBug-fbb8d09b0f1d6a107327b6cfff2a63f19d398a7acba4efae26d56dcfe3c1ac4f AAAA-AAAA-AAAA-AAAA-AFZZ

      _/_/_/  _/_/_/    _/_/_/
   _/        _/    _/  _/    _/  _/    _/    _/_/_/
  _/  _/_/  _/    _/  _/_/_/    _/    _/  _/    _/
 _/    _/  _/    _/  _/    _/  _/    _/  _/    _/
  _/_/_/  _/_/_/    _/_/_/      _/_/_/    _/_/_/
                                             _/
                                        _/_/

[+] Checking serial AAAA-AAAA-AAAA-AAAA-AFZZ
   [-] Registration successful
   [-] Your flag is INS{AAAA-AAAA-AAAA-AAAA-AFZZ}

ispo@leet:~/ctf/insomnihack_2022/GDBug$ ./GDBug-fbb8d09b0f1d6a107327b6cfff2a63f19d398a7acba4efae26d56dcfe3c1ac4f AAAA-AAZA-AAZA-AAFA-AAAA

      _/_/_/  _/_/_/    _/_/_/
   _/        _/    _/  _/    _/  _/    _/    _/_/_/
  _/  _/_/  _/    _/  _/_/_/    _/    _/  _/    _/
 _/    _/  _/    _/  _/    _/  _/    _/  _/    _/
  _/_/_/  _/_/_/    _/_/_/      _/_/_/    _/_/_/
                                             _/
                                        _/_/

[+] Checking serial AAAA-AAZA-AAZA-AAFA-AAAA
   [-] Registration successful
   [-] Your flag is INS{AAAA-AAZA-AAZA-AAFA-AAAA}
```
___

