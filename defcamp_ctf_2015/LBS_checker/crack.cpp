// ------------------------------------------------------------------------------------------------
#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int password_length = 1;
int product;
// ------------------------------------------------------------------------------------------------
int is_prime( int n )
{
    for(int i=2; i<=sqrt((double)n); ++i)
      if( !(n % i) )
          return 0;
  
    return 1;
}
// ------------------------------------------------------------------------------------------------
long long int get_product( char usr[] )
{
    long long int prod = 1;
    
    for(int i=0; usr[i]!='\0'; i++)
    {
        if( (prod *= usr[i]) >= 0x8000 )
        {
            long long int tmpA, tmpB;

            tmpA = ((((prod << 15) + prod) << 2) + prod) >> 0x20;
            tmpB = (tmpA + ((prod - tmpA) >> 1)) >> 14;
            prod = prod - ((tmpB << 15) - tmpB) + usr[i];
        
            password_length++;
        }
    }

    return prod * password_length;
}
// ------------------------------------------------------------------------------------------------
/*
** The original program has functions _1st, _2nd, _3rd, _4th and _5th. The only difference between
** these functions is the number which is added on at the end. I merge all these function in a
** single one.
*/
// ------------------------------------------------------------------------------------------------
int _ith( int idx )
{
    int prod = (int) product;
    int L, H, v4 = 0;
    
    while( prod > 0 )
    {
        H = ((long long int)prod * 0x66666667) >> 32;   // high 32 bits
        L = prod * 0x66666667;                          // low  32 bits

        v4 += prod - 10*(H >> 2);
        prod = H >> 2;
    }

    return v4 + idx;
}
// ------------------------------------------------------------------------------------------------
int soad( char ch )
{
    int v4 = 0;

    while( ch > 0 )
    {
        v4 += ch - 10*(((ch * 0x67) >> 8) >> 2);
        ch = (ch * 0x67) >> 10;
    }

    return v4;
}
// ------------------------------------------------------------------------------------------------
int cbc_password(int loc)
{
    char map[] = {"aBcDeFgHiJkLmNoPqRsTuVwXyZ1!2@3#4$5%6^7&8*9(0)_AbCdEfGhIjKlMnOpQrStUvWxYz[]{}-+=,.'><\0"};
    
    return map[ soad( map[loc*10] ) + _ith(loc + 1) ];
}
// ------------------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{
    char usr[] = { "Administrator" };   // #y1y3#y1y3##
    
    // strlen(usr) >= 5 and strlen(pwd) >= 5
    long long int p;
    int i;

    product = get_product( usr );
    
    for(i=product; i>=0; i-- )
        if( is_prime(i) )
            break;

    product = i;

    printf( "username: %s\n"
            "product : %x\n"
            "pwd len : %d\n"
            "password: ", usr, product, password_length );

    for(int i=0; i<password_length-1; i++)
        printf( "%c", cbc_password(i - (i*0xcccd >> 18)*5) );

    printf( "#\n\n\n" );            // finish with a '#'
    system("pause");
    return 0;
}
// ------------------------------------------------------------------------------------------------


//--------------------------------------------------------------------------------------------------