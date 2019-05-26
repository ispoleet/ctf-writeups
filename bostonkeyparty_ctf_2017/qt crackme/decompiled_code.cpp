// ------------------------------------------------------------------------------------------------
// BostonKeyParty 2017
// qt crackme (Reversing 250)
//
// decompiled code
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

uint B[16], C[16], C1[16], C2[16], E[16];

/* target array */
uint E_trg[] = { 
	0x146FC26A, 0x10766B04, 0x2AE5CE6C, 0x2DF5FCE4, 0x2434019A, 0x1F67E99D, 0x4048AA7F, 0x4C26C74C,
	0x16B2964E, 0x13905802, 0x33CF9B5F, 0x2CD5980F, 0x1DFCC164, 0x14A99DA3, 0x2C101662, 0x2BA9DEDB 
};

// ------------------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{	
//	char key[] = { "12345678KYRIAKOS" };
	char key[] = { "BKP{KYU7EC!PH3R}" };

	uint i, j;
	uint __b, __d, __s, __p, _x, _y, _z, _w, v_E8, v_EB, v_EC, v_108, v_128, v_128_2;
	uint v_104, v_124, v_124_2, v_12C, v_12C_2, v_130, v_100;
	uint _x2, __b2;
	uint64 carry;

	
	for( i=0; i<16; ++i ) B[i] = A[i] ^ key[i];		// XOR each character with A
	
	// PHASE 1: use the first 8 characters from input	
	__b = (B[6] << 16) + B[7];						// set registers
	__d = (B[2] << 16) + B[3];
	__s = (B[4] << 16) + B[5];
	__p = (B[0] << 16) + B[1];

	_x   = 0x058ff310;								// set variables
	v_E8  = 0x16D856AF;
	v_EC  = 0xD8E8367C;
	v_128 = 0x880F0E3A;

	for( i=0; i<32; i++ )							// fill up first half of array C1
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
	
	// PHASE 2: use the rest of the characters from input	
	__b = (B[8]  << 16) + B[9];						// set registers
	__d = (B[12] << 16) + B[13];
	__s = (B[10] << 16) + B[11];
	_x  = (B[14] << 16) + B[15];
	__p = 0x058ff310;

	v_100 = 0x16D856AF;								// set variables
	v_124 = 0xD8E8367C;
	v_12C = 0x880F0E3A;

	for( i=0; i<32; i++ )							// fill up second half of array C1
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

	// Now split C1 to 2 words
	for(i=0; i<8; i++) {
		uint v = C1[2*i];
				
		C1[2*i]   = v & 0xffff;
		C1[2*i+1] = v >> 16;		
	}

	// shuffle C1
	C2[0]  = C1[7];
	C2[1]  = C1[3];
	C2[2]  = C1[15];
	C2[3]  = C1[11];
	C2[4]  = C1[6];
	C2[5]  = C1[2];
	C2[6]  = C1[14];
	C2[7]  = C1[10];
	C2[8]  = C1[5];
	C2[9]  = C1[1];
	C2[10] = C1[13];
	C2[11] = C1[9];
	C2[12] = C1[4];
	C2[13] = C1[0];
	C2[14] = C1[12];
	C2[15] = C1[8];

	// shuffle C2 again
	for( i=0; i<4; ++i ) {
		 C[i*4 + 0] = C2[i + 0];
		 C[i*4 + 1] = C2[i + 4];
		 C[i*4 + 2] = C2[i + 8];
		 C[i*4 + 3] = C2[i + 12];
	}

	// multiply with Cp and generate E
	for( i=0; i<4; ++i )
		for( j=0; j<16; j+=4 )
			E[i + j] = C[i]*Cp[j] + C[i+4]*Cp[j+1] + C[i+12]*Cp[j+3] + C[i+8]*Cp[j+2];


	/* If E == E_trg, then key is correct */
	printf( "Generated E:\n" );
	
	for(i=0; i<16; ++i)
		printf( "%08X\n", E[i] );


	return 0;
}
// ------------------------------------------------------------------------------------------------
