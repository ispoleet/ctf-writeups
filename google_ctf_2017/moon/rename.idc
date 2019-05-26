// ------------------------------------------------------------------------------------------------
#include <idc.idc>

// ------------------------------------------------------------------------------------------------
static main() 
{
	auto func, end, target, inst, name, flags, xref, hidname, var, str;
	
	flags = SEARCH_DOWN | SEARCH_NEXT;


	/* rename functions in the 1st indirection */
	func = 0x04032C0;
	name = Name(func);
	
	Message( "Function %s\n", name );
	
	end = GetFunctionAttr(func, FUNCATTR_END);
	hidname = "none";
	
	for( inst=func; inst<end; inst=FindCode(inst, flags) )
	{
		Message("Instruction: 0x%x...\n", inst);
			
		for( target=Dfirst(inst); target!=BADADDR; target=Dnext(inst, target) ) 
		{
			xref = XrefType();
			
			if( xref == dr_O ) { 					// xref type: offset
				hidname =  GetString(target, -1, ASCSTR_C);
				
				Message("Read function name %s at %x\n", hidname, target);
			}
			
			if( xref == dr_W ) {					// xref type: write
				Message("Writing function name to %s\n", Name(target));
				
				str = sprintf("%s_%X", hidname, target );
				MakeNameEx(target, str, SN_NOCHECK);
			}
		}
	}
	
	
	/* rename functions in the 2nd indirection */
	for( var=0x004AB140; var<=0x004AB3E0; var=FindData(var, flags) )
	{
		name = Name(var);

		Message("Next DXREF at %x (%s)\n", var, name);
		
		for( target=Dfirst(var); target!=BADADDR; target=Dnext(var, target) ) 
		{
			xref = XrefType();
			
			if( xref == dr_O ) { 					// xref type: offset
				hidname = Name(target);				
				hidname = substr(hidname, 0, strstr(hidname, "_"));
				
				str = sprintf("%s_%X", hidname, var );
				Message("Variable %s becomes: %s\n",  Name(var), str);
				MakeNameEx(var, str, SN_NOCHECK);				
			}
		}
	}
}
// ------------------------------------------------------------------------------------------------
/*
Sample output:

...
Next DXREF at 4ab140 (glApplyFramebufferAttachmentCMAAINTEL_4AB140)
Variable off_4AB140 becomes: glApplyFramebufferAttachmentCMAAINTEL_4AB140
Next DXREF at 4ab150 (glBeginConditionalRender_4AB150)
Variable off_4AB150 becomes: glBeginConditionalRender_4AB150
Next DXREF at 4ab160 (glBindBufferBase_4AB160)
Variable off_4AB160 becomes: glBindBufferBase_4AB160
...
Instruction: 0x4032df...
Instruction: 0x4032e1...
Read function name glActiveTexture at 49f3c9
Instruction: 0x4032e8...
Writing function name to glActiveTexture_4CC7C8
Instruction: 0x4032ef...
Instruction: 0x4032f1...
Read function name glApplyFramebufferAttachmentCMAAINTEL at 49f3e0
Instruction: 0x4032f8...
Writing function name to qword_4CC7C0
Instruction: 0x4032ff...
Instruction: 0x403301...
Read function name glAttachShader at 49f406
...
*/
// ------------------------------------------------------------------------------------------------
