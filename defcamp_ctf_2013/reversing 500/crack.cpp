// ------------------------------------------------------------------------------------------------
// DFCT 2013 - (RE 500)
// ------------------------------------------------------------------------------------------------
#include <stdio.h>
#include <string.h>


char H[] = {

    "MANAAAFAAFAAFAweFAFFFFQGINKOQareIIIIIIITOKGNUQGNQKJsorryJJTKVWGI"
    "INRTQtoGGQJJJJIIIIIIIinterruptIITOKENHNQKAAAAyourAAAAAAAAAAAAAAA"
    "workAAAAAAAAAAbutAAAAAAweIIIIIwouldTUGGNOQVlikeWGNIMEEtoEEEEEEEE"
    "EtellEEEEEEEyouEEQGNFFFFthatFFFFFFFFFFtheFOFFFFFFFFinputFFFFFyou"
    "FFKKKKKareKKKKKKKQSORTsearchingINTUGNFFFFforFEEEEEEEEEEEconsists"
    "EEEEEEEEEEEEofEEEEEEEEEEonlyEEEEEElowercaseEQIIIIIhexIIIIITOAAch"
    "aractersAAAAfromAAAKGJaJIIItoIIJNOfKTFFandFFFFFFnumbersFFFFF0FFF"
    "FtoFFFFF9QNQW"
};

char L[] = {"abcdefghijklmnopqrstuvwxyz0123456789"};
char p[] = { "0123456789abcdef" };
char password[ 12 ];
// ------------------------------------------------------------------------------------------------
long long int hash( int h )
{
    long long int   v_40 = 1, v_50 = 0, v_80 = 0, v_c4 = 1, v_554 = 1;
    int             q = 0;

    for( int i=0; H[i]!='\0'; i++ )     // for each element of H
    {
        switch( H[i] )
        {
            case 'A': v_50 += v_554;    break;
            case 'B':                   break;
            case 'C':                   break;
            case 'D':                   break;
            case 'E': v_80 += v_554;    break;
            case 'F': v_80 -= v_554;    break;
            case 'G': v_c4 += v_554;    break;
            case 'H': v_c4 -= v_554;    break;
            case 'I': v_40 += v_554;    break;
            case 'J': v_40 -= v_554;    break;
            case 'K': v_50 += v_80;     break;
            case 'L':                   break;
            case 'M': v_50 = L[v_40-1]; break;
            case 'N': v_80 = password[v_c4-1];      break;
            case 'O': v_80 = (0xffffffffffffffff ^ v_80) &
                              0xffffffffffffffff;   break;
            case 'P':                   break;
            case 'Q': v_50 *= v_80;     break;
            case 'R': v_50  = v_80;     break;
            case 'S': v_80  = v_50;     break;
            case 'T': v_80  = L[v_40-1];break;
            case 'U': v_50 ^= v_80;     break;
            case 'V': if( v_50 < 0 ) v_50 = -v_50;  break;
            case 'W': // convert 8 MSBytes of v_50 to string
                        while( v_50 > 0xffffffff ) v_50 >>= 4;

                        if( q++ == h ) return v_50;
                        v_50 = 0;
                        break;
        }
    }

    return -1;              // function failure.
}
// ------------------------------------------------------------------------------------------------
int main( int argc, char *argv[] )
{
    printf("+--------------------------------------------------+\n");
    printf("|                     DCTF RE 500                  |\n");
    printf("|                 Hash Crack by ispo               |\n");
    printf("|                    December 2013                 |\n");
    printf("+--------------------------------------------------+\n");
    printf("Start Cracking....\n\n");


    for( int h=0; h<3; h++ )            // for each 4-byte digits of the password
    {
        // we need all possible passwords. So don't stop if we find a valid hash. Because next
        // hash is based on previous, each time we are searching for a hash the previous hash
        // must be vaild. To keep code simple we hardcode the first 2 4byte hashes.
        strcpy(password, "9a5ef40a0000");

        for( int i=0; i<16; i++ )       // generate all possible 4-byte hex digits
        for( int j=0; j<16; j++ )
        for( int k=0; k<16; k++ )
        for( int l=0; l<16; l++ )
        {
            password[4*h + 0] = p[i];   // set possible password
            password[4*h + 1] = p[j];
            password[4*h + 2] = p[k];
            password[4*h + 3] = p[l];

            // compare hashes
            if( h == 0 && hash(h) == 0xA70086D2 )
                printf("1st FOUR found: %c%c%c%c\n", p[i], p[j], p[k], p[l]);
            else if( h == 1 && hash(h) == 0x14F1163F )
                printf("2nd FOUR found: %c%c%c%c\n", p[i], p[j], p[k], p[l]);
            else if( h == 2 && hash(h) == 0x4108761A )
                printf("3rd FOUR found: %c%c%c%c\n", p[i], p[j], p[k], p[l]);
        }
    }

    return 0;
}
// ------------------------------------------------------------------------------------------------
