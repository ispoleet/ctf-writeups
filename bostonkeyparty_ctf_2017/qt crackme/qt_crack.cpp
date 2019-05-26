// ------------------------------------------------------------------------------------------------
// BostonKeyParty 2017
// qt crackme (Reversing 250)
//
// crack
// ------------------------------------------------------------------------------------------------
#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned long long int uint64;
typedef unsigned int uint;

uint A[] = { 
    0x90DF, 0x70BC, 0xEF57, 0x5A96, 0xCFEE, 0x5509, 0x80CE, 0x0D20,
    0xE14F, 0x070E, 0xA446, 0x2FC6, 0xECF0, 0x5355, 0x782B, 0x6457 
};

uint Cp[] = { 
    0x1380, 0x25FA, 0x0CAA, 0x00E2, 0x04E4, 0x56DA, 0x1A61, 0x123F,
    0x2709, 0x0103, 0x0E07, 0x00C0, 0x2035, 0x1531, 0x0020, 0x0DC7 
};

uint B[16], C[16], C1[16], C2[16],  E[16];

/* target array */
uint E_trg[] = { 
    0x146FC26A, 0x10766B04, 0x2AE5CE6C, 0x2DF5FCE4, 0x2434019A, 0x1F67E99D, 0x4048AA7F, 0x4C26C74C,
    0x16B2964E, 0x13905802, 0x33CF9B5F, 0x2CD5980F, 0x1DFCC164, 0x14A99DA3, 0x2C101662, 0x2BA9DEDB 
};

/* second target array */
uint C1_trg[] = { 
    0x4e55813a, 0x00000000, 0x36ef1c63, 0x00000000, 0xf8fdd873, 0x00000000, 0x845e5818, 0x00000000,
    0x720468be, 0x00000000, 0xa2f98568, 0x00000000, 0xf0edc8fa, 0x00000000, 0x213566b7, 0x00000000 
};

uint64 ctr;                                         // a counter

char charset[] = { "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-!@$" };
uint charset_len;

// ------------------------------------------------------------------------------------------------
int chk_1st_half( char key1[] )
{   
    uint i, __b, __d, __s, __p, _x, _x2, _y, _z, _w, v_E8, v_EC, v_108, v_128, v_128_2;
    uint64 carry;
    

    for( i=0; i<8; ++i ) B[i] = A[i] ^ key1[i];     // XOR each character with array A
    
    // PHASE 1: use the first 8 characters from input   
    __b = (B[6] << 16) + B[7];                      // set registers
    __d = (B[2] << 16) + B[3];
    __s = (B[4] << 16) + B[5];
    __p = (B[0] << 16) + B[1];

    _x   = 0x058ff310;                              // set variables
    v_E8  = 0x16D856AF;
    v_EC  = 0xD8E8367C;
    v_128 = 0x880F0E3A;

    for( i=0; i<32; i++ )                           // fill up first half of array C1
    {
        _y = ((__p << 24) | (__d >> 8)) + __b;
        
        carry = (uint64)((__p << 24) | (__d >> 8)) + __b;
        _z = ((__d << 24) | (__p >> 8)) + __s + (carry & 0x100000000 ? 1 : 0);

        v_108 = _z ^ v_EC;      
        v_128_2 = (v_E8 << 24) | (v_128 >> 8);

        C1[2] = ((__s << 3) | (__b >> 29)) ^ _z ^ v_EC;
        C1[4] = _x ^ _y;
        C1[6] = _z ^ v_EC;

        carry = (uint64)v_128_2 + _x;
        _w = ((v_128 << 24) | (v_E8 >> 8)) + v_EC + (carry & 0x100000000 ? 1 : 0);

        v_128 = (v_128_2 + _x) ^ i;
        v_E8 = _w;
        
        __b = ( (__b << 3) | (__s >> 29)) ^ _x  ^ _y;
        __d = C1[4];
        __s = C1[2];
        __p = v_108;
        _x2 = ((_x << 3) | (v_EC >> 29)) ^ v_128;
    
        v_EC = ((v_EC << 3) | (_x >> 29)) ^ v_E8;
        _x = _x2;
    }

    C1[0] = __b;

    /* check if C1 matches with the desired one */
    if( C1[0] == C1_trg[0] && C1[2] == C1_trg[2] &&  C1[4] == C1_trg[4] &&  C1[6] == C1_trg[6] )
        return 1;                                   // we have a match!

    return 0;                                       // failure
}
// ------------------------------------------------------------------------------------------------
int chk_2nd_half( char key2[] )
{
    uint i, __b, __d, __s, __p, _x, _y, _z, __b2, v_104, v_124, v_124_2, v_12C, v_12C_2, v_100;
    uint64 carry;
    
    
    for( i=8; i<16; ++i ) B[i] = A[i] ^ key2[i];    // XOR each character with array A

    // PHASE 2: use the rest of the characters from input   
    __b = (B[8]  << 16) + B[9];                     // set registers
    __d = (B[12] << 16) + B[13];
    __s = (B[10] << 16) + B[11];
    _x  = (B[14] << 16) + B[15];
    __p = 0x058ff310;

    v_100 = 0x16D856AF;                             // set variables
    v_124 = 0xD8E8367C;
    v_12C = 0x880F0E3A;

    for( i=0; i<32; i++ )                           // fill up second half of array C1
    {
        carry = (uint64)((__b << 24) | (__s >> 8)) + _x;

        _y = ((__s << 24) | (__b >> 8)) + __d + (carry & 0x100000000 ? 1 : 0);      
        __b2 = _y ^ v_124;

        C1[12] = (((__b << 24) | (__s >> 8)) + _x) ^ __p;
        C1[14] = _y ^ v_124;
        C1[10] = ((__d << 3) | (_x >> 29)) ^ _y ^ v_124;

        v_104 = C1[10];
        v_12C_2 = (v_100 << 24) | (v_12C >> 8);

        carry =  (uint64)v_12C_2 + __p;
        _z =  ((v_12C << 24) | (v_100 >> 8)) + v_124 + (carry & 0x100000000 ? 1 : 0);

        v_12C = (v_12C_2 + __p) ^ i;
        v_100 = _z;
        v_124_2 = ((v_124 << 3) | (__p >> 29)) ^ v_100;

        __s = (((__b << 24) | (__s >> 8)) + _x) ^ __p;
        __b = __b2;
        _x  = ((_x << 3) | (__d >> 29)) ^ C1[12];
        __d = v_104;
        __p = ((__p << 3) | (v_124 >> 29)) ^ v_12C;
        
        v_124 = v_124_2;
    }

    C1[8] = _x;

    /* check if C1 matches with the desired one */
    if( C1[8] == C1_trg[8] && C1[10] == C1_trg[10] &&  C1[12] == C1_trg[12] &&  C1[14] == C1_trg[14] )
        return 1;                                   // we have a match!

    return 0;                                       // failure
}
// ------------------------------------------------------------------------------------------------
int crack_it( char *key, int depth, int max, int (*func)(char*) )
{
    if(depth >= max)
    {
        if( ++ctr % 1000000 == 0 )                  // count iterations
            printf("Iteration #%llu. Key: %s\n", ctr, key );

        if( func(key) == 1 ) {                      // check key
            printf("\n\nKey Found: %s (after %lld iterations)\n\n\n", key, ctr);
            return 1;
        }

        return 0;
    }

    for( uint i=0; i<charset_len; ++i ) {           // for each char in charset
        key[depth] = charset[i];

        if( crack_it(key, depth+1, max, func) == 1 ) return 1;
    }

    return 0;                                       // failure
}

// ------------------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{   
    charset_len = strlen(charset);                  // set size of charset
    int start = 8;
    char key[32] = { 0 };
    

    key[0] = 'B';                                   // we know how flag starts
    key[1] = 'K';
    key[2] = 'P';
    key[3] = '{';

    printf("Cracking first half...\n");
    crack_it(key, 4, start, chk_1st_half); 

    if( argc == 2 ) {                               // if you want to hardcode some chars
        key[8] = argv[1][0];            
        start = 9;
    }

    key[15] = '}';                                  // and how it ends

    printf("Cracking second half...\n");
    crack_it(key, start, 15, chk_2nd_half); 

    return 0;
}
// ------------------------------------------------------------------------------------------------
