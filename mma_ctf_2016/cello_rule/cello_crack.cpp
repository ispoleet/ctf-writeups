// ------------------------------------------------------------------------------------------------
/* Tokyo Westerns / MMA CTF 2nd 2016
** Cello Rule (Reversing 250)
**
** Crack by ispo
**
** Flag: TWCTF{RNG_OF_RULE30_CA}
*/
// ------------------------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>

typedef unsigned long long int ullong;
typedef unsigned int uint;
// ------------------------------------------------------------------------------------------------
/* generate next XOR key and next seed from a given seed */
inline ullong next_key( ullong &seed )
{
    ullong orig_seed, key = 0;

    for( int i=63; i>=0; --i )
    {
        key |= (seed & 1) << i;

        orig_seed = seed;
        seed      = 0;

        for( int j=0; j<64; ++j )
        {
            uint shf = (orig_seed >> (j - 1)) | (orig_seed << (64 - (j - 1)));

            if( (0x1e >> (shf & 7)) & 1 )
                seed |= (ullong)(1) << j;
        }
    }

    return key;
}
// ------------------------------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    ullong  seed, key;
    uint    urandom, st, end;
    uint    progress, prev = 0;

    if( argc != 3 ) {
        printf("Usage: %s start end\n", argv[0]);
        return -1;
    }

    st  = strtoul(argv[1], NULL, 16);//*1000*1000;
    end = strtoul(argv[2], NULL, 16);//*1000*1000;

    /* brute force a range of urandom seeds */
    for(urandom=end; urandom>=st; --urandom)
    {
        progress = 100 - ((double)(urandom - st) / (end - st))*100 ;

        if( progress != prev ) {
            printf( "  %%%d Complete. Current: 0x%x\n", progress, urandom );
            prev = progress;
        }

        /* seed is generated from 32-bit random value.
         *
         * Many thanks to @_N4NU_ for his hint in seed generation.
         * My original seed was: seed = (~(ullong)urandom << 32) | urandom | 0x6e00000000;
         */
        seed = (~(ullong)urandom << 32) | urandom;
        key  = next_key( seed );                    // get first key

        // first 8 bytes of a png image are fixed. Check if decryption is correct
        if((key ^ 0x7be05d85a22c66a2) == 0x0a1a0a0d474e5089)
        {
            /* The urandom value is: 0x5d53c9a8 */
            printf("\n\t* SEED FOUND!!! %x\n\n", urandom);
            printf("Decryptng image...\n");

            FILE *in   = fopen("flag.png.enc", "rb");
            FILE *out  = fopen("flag.png", "wb");
            ullong data;

            if( in == NULL ) return -1;

            // reset seed, as next_key() modified it
            seed = (~(ullong)urandom << 32) | urandom;

            for( ; fread(&data, 8, 1, in) == 1; data ^= next_key(seed), fwrite(&data, 8, 1, out) )
                ;

            /* flag.png.enc size is multiple of 8 so there're no leftovers */

            fclose(in);
            fclose(out);

            printf("Done\n");
            return 1;
        }
    }

    return 0;
}
// ------------------------------------------------------------------------------------------------
