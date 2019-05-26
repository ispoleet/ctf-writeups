// ------------------------------------------------------------------------------------------------
#include <idc.idc>

static main()
{
	auto rand, n, map;

	Message( "Script started...\n" );

	for( rand=1; rand<256; rand++ )			// for each value
	{

		// .text:080486DB    call    gen_array
		RunTo( 0x080486DB ); GetDebuggerEvent(WFNE_SUSP, -1);
		map = GetRegValue("eax");			// get address of map

		// .text:080485A7    call    _rand
		// .text:080485AC    and     eax, 0FFh
		// .text:080485B1    mov     [ebp+rand_C], eax
		RunTo( 0x080485B1 ); GetDebuggerEvent(WFNE_SUSP, -1);
		SetRegValue(rand, "eax");			// set the "random" value

		/*
		**	Let the program generate the map
		*/

		// .text:080486DB    call    gen_array
		// .text:080486E0    mov     dword ptr [esp+18h], 0
		RunTo( 0x080486E0 ); GetDebuggerEvent(WFNE_SUSP, -1); 
		SetRegValue(0x080486D4 , "eip");	// rewind back


		
		Message( "map_%02x = [", rand  );	// print sbox, as python list
		for( n=0; n<256; n++ ) Message( "%d,", Byte(map+n) );
		Message( "0]\n" );
	}


	/* print a superior map */
	Message( "map = [");
	for( rand=1; rand<255; rand++ ) Message( "map_%02x,", rand  );
	Message( "map_255]\n" );
}
// ------------------------------------------------------------------------------------------------
