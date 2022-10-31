## Hack Lu CTF 2022 - Leaky Orders (RE 277)
##### 28/10 - 30/10/2022 (24hr)
___

### Description:

*Last week we switched over to a new dish order system. But the technician who installed the system made a mistake, and now our orders aren't arriving properly. All the plate numbers have leaked onto your screen, and now it's up to you to get them back in time.*

*Do you think you can help us send the right orders to the kitchen? If you can, we'll reward you with a freshly cooked flag!*

`nc flu.xxx 11201`
___

### Solution

Let's first connect to the server (we get a shell):
```
ispo@ispo-glaptop2:~/ctf/hack.lu_ctf_2022/LeakyOrders$ nc flu.xxx 11201
ctf@702ba9678252:/chal$ ls -l
    ls -l
    total 6
    -rwsr-xr-x 1 root root 14488 Oct 28 14:03 sigs
ctf@702ba9678252:/chal$ ./sigs
    ./sigs
    38 40 48
ctf@702ba9678252:/chal$ ls -l /
    ls -l /
    total 15
    lrwxrwxrwx    1 root   root      7 Oct 20 11:49 bin -> usr/bin
    drwxr-xr-x    2 root   root      2 Apr 18  2022 boot
    drwxr-xr-x    2 root   root      3 Oct 28 15:24 chal
    drwxr-xr-x    5 root   root    360 Oct 31 05:24 dev
    drwxr-xr-x   33 root   root     83 Oct 31 05:24 etc
    -r--------    1 root   root     43 Oct 28 13:14 flag
    drwxr-xr-x    3 root   root      3 Oct 28 15:24 home
    lrwxrwxrwx    1 root   root      7 Oct 20 11:49 lib -> usr/lib
    lrwxrwxrwx    1 root   root      9 Oct 20 11:49 lib32 -> usr/lib32
    lrwxrwxrwx    1 root   root      9 Oct 20 11:49 lib64 -> usr/lib64
    lrwxrwxrwx    1 root   root     10 Oct 20 11:49 libx32 -> usr/libx32
    drwxr-xr-x    2 root   root      2 Oct 20 11:49 media
    drwxr-xr-x    2 root   root      2 Oct 20 11:49 mnt
    drwxr-xr-x    2 root   root      2 Oct 20 11:49 opt
    dr-xr-xr-x 2261 nobody nogroup   0 Oct 31 05:24 proc
    drwx------    2 root   root      4 Oct 20 11:53 root
    drwxr-xr-x    5 root   root      5 Oct 20 11:53 run
    lrwxrwxrwx    1 root   root      8 Oct 20 11:49 sbin -> usr/sbin
    drwxr-xr-x    2 root   root      2 Oct 20 11:49 srv
    dr-xr-xr-x   13 nobody nogroup   0 Oct 31 05:24 sys
    drwxrwxrwt    2 root   root      2 Oct 20 11:53 tmp
    drwxr-xr-x   14 root   root     14 Oct 20 11:49 usr
    drwxr-xr-x   11 root   root     13 Oct 20 11:53 var
ctf@702ba9678252:/chal$ cat /flag
    cat /flag
    cat: /flag: Permission denied
ctf@702ba9678252:/chal$ exit
    exit
```

The `sigs` binary has the SUID bit set and the flag is only visible to root user, so
we have to make `sigs` binary to print the flag. Let's start from `main`:
```c
int __fastcall main(int argc, char **argv, char **argp) {
  /* ... */
  counter = 15;
  strcpy(flag, "/flag");
  fptrs[2] = u_set_glo_num2;
  *(__m128i *)fptrs = _mm_unpacklo_epi64(
                        (__m128i)(unsigned __int64)u_set_glo_num1,
                        (__m128i)(unsigned __int64)u_set_glo_num3);
  while ( 1 ) {
    buf = (unsigned int *)calloc(3uLL, 4uLL);
    seed = time(0LL);
    buf_ = buf;
    srand(seed);
    do {
      ++buf_;
      rnd = rand();
      n_sig = __libc_current_sigrtmax();        // return number of available real-time signal with lowest priority
      rnd_byte = rnd % (n_sig - __libc_current_sigrtmin() + 1);// 0x22
      *(buf_ - 1) = __libc_current_sigrtmin() + rnd_byte;
    }
    while ( buf + 3 != buf_ );
    if ( !buf )
      break;
    v10 = u_register_sig_handlers((int *)buf, 3u, fptrs);
    if ( !v10 )
    {
      free(buf);
      return 1;
    }
    num1 = *buf;
    num2 = buf[2];
    num3 = buf[1];
    printf("%d %d %d\n", *buf, num3, num2);
    sleep(1u);
    if ( __PAIR64__(num3, num1) != __PAIR64__(glo_expected_num3, glo_expected_num1) || num2 != glo_expected_num2 )
    {
      free(buf);
      free(v10);
      return 1;
    }
    *(_QWORD *)&glo_expected_num1 = 0LL;
    glo_expected_num2 = 0;
    free(buf);
    free(v10);
    if ( !--counter )
      return u_load_and_print_flag(flag);
  }
  return 1;
}
```

Program first generates **3** random numbers between `__libc_current_sigrtmin()`  (**0x22**)
and `__libc_current_sigrtmax()` (**0x40**) and registers a signal handler in each of them.
Let's see the signal handlers:
```c
void __fastcall u_set_glo_num1(int signo)
{
  glo_expected_num1 = signo;
}

void __fastcall u_set_glo_num3(int signo)
{
  glo_expected_num3 = signo;
}

void __fastcall u_set_glo_num2(int signo)
{
  glo_expected_num2 = signo;
}
```

```assembly
.bss:00005600BFC2C081                 align 8
.bss:00005600BFC2C088 glo_expected_num1 dd ?                  ; DATA XREF: main+118↑r
.bss:00005600BFC2C088                                         ; main+133↑w ...
.bss:00005600BFC2C08C glo_expected_num3 dd ?                  ; DATA XREF: main+121↑r
.bss:00005600BFC2C08C                                         ; u_set_glo_num3↑w
.bss:00005600BFC2C090 glo_expected_num2 dd ?                  ; DATA XREF: main+12A↑r
.bss:00005600BFC2C090                                         ; main+141↑w ...
.bss:00005600BFC2C094                 align 8
.bss:00005600BFC2C094 _bss            ends
```

Program prints these numbers and then goes to sleep for **1** second.
When it wakes up, it checks whether all `glo_expected_num*` are properly set:
```
if ( __PAIR64__(num3, num1) != __PAIR64__(glo_expected_num3, glo_expected_num1) || num2 != glo_expected_num2 )
{
  free(buf);
  free(v10);
  return 1;
}
```

If not program terminates, otherwise it advances to the next round. After **15** successful
rounds, it prints the flag:
```c
if ( !--counter )
    return u_load_and_print_flag(flag);
```

```c
int __fastcall u_load_and_print_flag(const char *flag) {
  /* ... */
  memset(buf, 0, 255);
  fd = open(flag, 0);
  result = 1;
  if ( fd )
  {
    read(fd, buf, 0xFFuLL);
    puts(buf);
    return 0;
  }
  return result;
}
```

In order to get the flag, we need to run the program, and within **1** second to send the **3**
random signals to the program. We have to do this **15** times.


### Simple & Slow Crack

The direct approach is to use python and the `subprocess` module:
```python
 with subprocess.Popen([f'./public/main'],
                        stdout=subprocess.PIPE,
                        shell = True) as process:
      line = process.stdout.readline().strip().split(b' ')
      num1 = int(line[0])
      num2 = int(line[1])
      num3 = int(line[2])
      print(f'[+] Got Numbers: {num1}, {num2}, {num3}')

      process.send_signal(num1)
      process.send_signal(num2)
      process.send_signal(num3)
```

Here, we just load the program, we read signal numbers, we send the appropriate signals
and we wait for the next iteration. However, program terminates after the first iteration.

The second approach, was to not wait for any input and simply send all possible signal
numbers (they are not many). However, we cannot send all possible signals within **1** 
seconds, so program terminated after the first iteration.

The third approach, was to predict the numbers (we can do that as long as we know the 
current timestamp; PRNG initialized using `srand(time(NULL))`). Unfortunately neither
this approach could go past the first iteration.

The problem is that `Popen` was very slow, so we need to follow a more hacky approach.


### Fast Crack

To do this fast, we will use a BASH script and a C program. The [rand.c](./rand.c)
program is used to quickly generate the next **3** random numbers (so we don't have
to wait to get printed and read them):
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {
  int max = __libc_current_sigrtmax();
  int min = __libc_current_sigrtmin();

  srand(atoi(argv[1]));

  int a = rand() % (max - min + 1) + min;
  int b = rand() % (max - min + 1) + min;
  int c = rand() % (max - min + 1) + min;

  printf("%d %d %d\n", a, b, c);

  return 0;
}
```

The random timestamp is taken from `argv[1]`, which is provided by the [crack.sh](./crack.sh)
BASH script:
```bash
./public/main &
#/chal/sigs &
PID=$!

echo "$> pid: $PID"

timestamp=$(date +%s)
for ((i=0; i<15; i++))
do
    NUMS=`./rand $((timestamp + 0))`
    # NUMS=`/tmp/rand $((timestamp + 0))`
    echo "$> Generate Numbers: $NUMS ~> (Iteration #$i)"

    ARR=($NUMS)
    echo "$> Array: ${ARR[0]} ${ARR[1]} ${ARR[2]}"

    # We need to play around with the sleep delay
    sleep 0.90

    timestamp=$(date +%s)

    kill -${ARR[0]} $PID
    kill -${ARR[2]} $PID
    kill -${ARR[1]} $PID

    echo '$> --------------------'
done

echo 'finito!'
sleep 2
kill -${ARR[1]} $PID
```

The `sleep` delay cannot be exactly **1** seconds, but a little bit less (we need to play
around with it; **0.9** is a good value). The script also does not work all the times; we need
to run it several times before it successfully pass all **15** iterations.


### Remote Cracking

This works nicely locally, but we need to run this on the server. And we have to do it
quickly. Therefore, we will not interact with the server manually, but we will use python
instead. The plan is to first send the `rand` binary (in **512** byte chunks; we cannot send
all of it at once) and then send the BASH script in `/tmp` directory.
Finally, we run the crack script multiple times, until we successfully pass all **15** iterations.

We do this and we get the flag: `flag{y0u_s3nt_s0_m4ny_s1ng4ls_1m_fl4tt3rd}`

For more details, please take a look at the [leaky_orders_crack.py](./leaky_orders_crack.py)
file.
___
