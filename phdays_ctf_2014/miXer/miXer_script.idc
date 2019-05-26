// ------------------------------------------------------------------------------------------------
// PhDays quals 2014 - miXer (RE 2000)
// ------------------------------------------------------------------------------------------------
#include <idc.idc>


static main()
{
    Message( "------------------------------------\n");

    auto i, d, x, fp;
    // 55 89 E5 83 E4 F0
    d = Byte( 0x804845C ); Message( "d = %x\t x = %x\n", d, d^0x55 );
    d = Byte( 0x804845D ); Message( "d = %x\t x = %x\n", d, d^0x89 );
    d = Byte( 0x804845E ); Message( "d = %x\t x = %x\n", d, d^0xE5 );
    d = Byte( 0x804845F ); Message( "d = %x\t x = %x\n", d, d^0x83 );
    d = Byte( 0x8048460 ); Message( "d = %x\t x = %x\n", d, d^0xE4 );
    d = Byte( 0x8048461 ); Message( "d = %x\t x = %x\n", d, d^0xF0 );
    
     // C9 C3 -> leave ret
    d = Byte( 0x804882E ); Message( "d = %x\t x = %x\n", d, d^0xC9 );
    d = Byte( 0x804882F ); Message( "d = %x\t x = %x\n", d, d^0xC3 );
    
    
    // key: B1 0A 15 D6 B3 15 AF 53
    
    //  fp = fopen( "mix.txt", "w" );
    auto b0, b1, b2, b3, b4, b5, b6, b7, b8, b9;
    
    for( i=0x804845C; i<0x8048830; i=i+10 )
    {
        /*
            E4 83 F0 55 57 E5 53 81  56 89 --> 
            83 E4 F0 55 57 89 E5 53  56 81
            4 10 6 5 9 7 2 1 3 8
        */
        b0 = Byte(i+0);
        b1 = Byte(i+1);
        b2 = Byte(i+2);
        b3 = Byte(i+3);
        b4 = Byte(i+4);
        b5 = Byte(i+5);
        b6 = Byte(i+6);
        b7 = Byte(i+7);
        b8 = Byte(i+8);
        b9 = Byte(i+9);
        
        PatchByte(i+0, b3);
        PatchByte(i+1, b9);
        PatchByte(i+2, b5);
        PatchByte(i+3, b4);
        PatchByte(i+4, b8);
        PatchByte(i+5, b6);
        PatchByte(i+6, b1);
        PatchByte(i+7, b0);
        PatchByte(i+8, b2);
        PatchByte(i+9, b7);
                
//      fprintf( fp, "%2X %2X %2X %2X %2X %2X 00 00 00 00 00 00 00 00 00 00\n", 
//      , Byte(i+10-1), Byte(i+6-1), Byte(i+2-1), Byte(i+1-1), Byte(i+3-1) );
    }
    
    // fclose( fp );
    
}
// ------------------------------------------------------------------------------------------------
