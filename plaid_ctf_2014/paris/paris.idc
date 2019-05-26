// ------------------------------------------------------------------------------------------------
/*
**  Plaid CTF 2014 - RE300 - paris -> VM crackme
**  This script executes the program and traces the emulated instructions.
**  April 2014 - ispo
**
**  NOTICE: Don't forget to tell IDA to pass exceptions to the program.
*/
// ------------------------------------------------------------------------------------------------
#include <idc.idc>

static main()
{
    auto i, j, addr, c, opcode, bx, cx, matched, handle;
    auto reg_bx, reg_cx, ZF, pc, prev_eip;
    
    
    Message( "Plaid CTF 2014 - RE300 - paris. ispo\n" ); 
    Message( "Emulator tracer started...\n" );
    
    
    // AddBpt(0x401043);        // breakpoint after password read   
    AddBpt(0x40247C);       // breakpoint for function 1
    AddBpt(0x402323);       // breakpoint for function 2
    AddBpt(0x40211E);       // breakpoint for function 3
    AddBpt(0x4020A1);       // breakpoint for function 4
    AddBpt(0x40241C);       // breakpoint for function 5
    AddBpt(0x4022F2);       // breakpoint for function 6
    AddBpt(0x4022C1);       // breakpoint for function 7
    AddBpt(0x402290);       // breakpoint for function 8
    AddBpt(0x40225F);       // breakpoint for function 9
    AddBpt(0x40239D);       // breakpoint for function 10
    AddBpt(0x4023FF);       // breakpoint for function 11
    AddBpt(0x4023E2);       // breakpoint for function 12
    AddBpt(0x4020E4);       // breakpoint for function 13
    AddBpt(0x402450);       // breakpoint for function 14
    AddBpt(0x4023C0);       // breakpoint for function 15
    AddBpt(0x402196);       // breakpoint for function 16
    AddBpt(0x40215B);       // breakpoint for function 17
    AddBpt(0x40234F);       // breakpoint for function 18
    AddBpt(0x4021D4);       // breakpoint for function 19  
    AddBpt(0x402439);       // breakpoint for function 20
    /*
    .text:00401FCA RESTORE_COPY_401FCA:                    ; CODE XREF: .text:004020DFj
    .text:00401FCA                                         ; .text:00402119j ...
    .text:00401FCA mov     edx, [esp+0Ch]                  ; edx = CONTEXT
    .text:00401FCE cmp     al, 1
    */
    AddBpt(0x401FCE);       // breakpoint for possible matched instruction
    
    
    handle  = fopen( "em_trace.txt", "w" );     // open file 
    matched = 0;                                // initialize variables
    pc      = 0;
    c       = 1;
    
    while( 1 )                                  // while there are commands to emulate
    for( i=0; i<20; i++ )                       // for each possible function
    {               
        /*
        **  .text:0040106A cmp     esi, 0DEADBEEFh
        **  0x40106A is an address after the execution of VM. If we reach this point
        **  then 
        */
        RunTo( 0x40106A );                      // run to the next BP (the next function)
        GetDebuggerEvent(WFNE_SUSP, -1);        // allow execution to continue
        addr     = GetEventEa();                // get address of function
        pc       = Dword(0x4024A7);             // update  eip
        
        if( addr == 0x40106A ) {                // Do we reach the end ?
            Message( "Emulation finish...\n" );
            return 0;                           // exit script
        }
        
        StepOver();                             // step over to get the command
        GetDebuggerEvent(WFNE_SUSP, -1);        // allow execution to continue

        // if( matched == 91 || matched == 94 )
        //      PatchWord(0x4024AC, 1); 
        
        opcode = GetRegValue( "eax" );          // get opcode
        bx     = GetRegValue( "ebx" ) & 0xffff; // get 1st operand
        cx     = GetRegValue( "ecx" ) & 0xffff; // get 2nd operand              
        reg_bx = Word(0x28FC98 + 0x9C + bx);    // get register value of 1st operand
        reg_cx = Word(0x28FC98 + 0x9C + cx);    // get register value of 2nd operand
        
        
        RunTo(0x40106A);                        // run to RESTORE_COPY (0x401FCA)
        GetDebuggerEvent(WFNE_SUSP, -1);        // allow execution to continue
        if( addr == 0x40106A ) {                // Do we reach the end ?
            Message( "Emulation finish...\n" );
            return 0;                           // exit script
        }
                
        // Message( "f:0x%x\teax:0x%x\tal:%d\tc:%d\n",addr, opcode, isValid, c );
        // Message("address of RESTORE_COPY: 0x%x\n", GetEventEa() );       
        
        if((GetRegValue("eax") & 0xff) == 1)    // if al is 1 then the opcode matched
        {               
            matched  = matched + 1;             // increase number of matched instructions
            ZF       = Word(0x4024AC);          // get value of Zero flag           
            
            fprintf( handle, "#%3d\tcmd:%2d\taddr:0x%x\teip:%d\t", matched, c, addr, pc );
            
            // resolve instruction
                 if( c == 1  ) fprintf(handle,"nop"                                           );
            else if( c == 2  ) fprintf(handle,"mov  $%x[%x], $%x[%x]",  cx, reg_cx, bx, reg_bx);
            else if( c == 3  ) fprintf(handle,"psw[$%x[%x]] = $%x[%x]", cx, reg_cx, bx, reg_bx);
            else if( c == 4  ) fprintf(handle,"$%x[%x] = psw[$%x[%x]]", cx, reg_cx, bx, reg_bx);
            else if( c == 5  ) fprintf(handle,"mov  $%x[%x], 0x%x",         bx, reg_bx, cx    );
            else if( c == 6  ) fprintf(handle,"add  $%x[%x], $%x[%x]",  cx, reg_cx, bx, reg_bx);
            else if( c == 7  ) fprintf(handle,"sub  $%x[%x], $%x[%x]",  cx, reg_cx, bx, reg_bx);
            else if( c == 8  ) fprintf(handle,"xor  $%x[%x], $%x[%x]",  cx, reg_cx, bx, reg_bx);
            else if( c == 9  ) fprintf(handle,"and  $%x[%x], $%x[%x]",  cx, reg_cx, bx, reg_bx);
            else if( c == 10 ) fprintf(handle,"shr  $%x[%x], 8",                    bx, reg_bx);
            else if( c == 11 ) fprintf(handle,"not  $%x[%x]",                       bx, reg_bx);
            else if( c == 12 ) fprintf(handle,"inc  $%x[%x]",                       bx, reg_bx);
            else if( c == 13 ) fprintf(handle,"cmp  $%x[%x], $%x[%x] -> %d", bx,reg_bx,cx,reg_cx,ZF);
            else if( c == 14 ) fprintf(handle,"jmp  $%d",               cx                    );
            else if( c == 15 ) fprintf(handle,"jz   $%d -> %d",         cx, ZF                );
            else if( c == 16 ) fprintf(handle,"push $%x[%x]",                       bx, reg_bx);
            else if( c == 17 ) fprintf(handle,"pop  $%x[%x]",                       bx, reg_bx);
            else if( c == 18 ) fprintf(handle,"xchg $%x[%x]",                       bx, reg_bx);         
            else if( c == 19 )
            { 
                fprintf(handle,"decr $%x[%x]\t", bx, reg_bx);
            
                for( j=0; j<16; j++ )       // print the first 16 bytes of hash table               
                    fprintf( handle, " %2X", Byte(0x401690 + j) );              
            }
            else if( c == 20 ) fprintf(handle,"halt"                                          );

            fprintf(handle,  "\n"); 

            if( matched % 10 == 0 ) Message( "%d instructions traced\n", matched );
        }
        
        
        c = c + 1;              // increase function counter
        if( c > 20 ) c = 1;     // cyclic increment
    }
    
    fclose( handle );           // close file handle

    // get_func_name( 0x7701b499, i, 100);
}
// ------------------------------------------------------------------------------------------------
