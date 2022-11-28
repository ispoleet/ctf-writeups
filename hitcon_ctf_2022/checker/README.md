## HITCON CTF 2022 - checker (RE 274)
##### 24-26/11/2022 (48hr)
___

### Description
 
*just a deep and normal checker*

```
checker-042580c29f20a5c861ac4c21fe006e5fb1d08bb1.zip
```

*Author: zeze*
___

### Solution

The *checker.exe* binary simply opens the `hitcon_checker` *Physical Device*
and sends the control code `222080h`:
```c
int __cdecl main(int argc, const char **argv, const char **envp) {
  HANDLE FileW; // rax
  char *v4; // rcx
  char OutBuffer[4]; // [rsp+40h] [rbp-18h] BYREF
  DWORD BytesReturned; // [rsp+44h] [rbp-14h] BYREF

  FileW = CreateFileW(L"\\\\.\\hitcon_checker", 0xC0000000, 0, 0i64, 3u, 4u, 0i64);
  glo_file_hdl = (__int64)FileW;
  if ( FileW == (HANDLE)-1i64 )
  {
    u_vfprintf("driver not found\n");
    exit(0);
  }
  OutBuffer[0] = 0;
  DeviceIoControl(FileW, 0x222080u, 0i64, 0, OutBuffer, 1u, &BytesReturned, 0i64);
  v4 = "correct\n";
  if ( !OutBuffer[0] )
    v4 = "wrong\n";
  u_vfprintf(v4);
  system("pause");
  return 0;
}
```

Let's move on the *chcecker_drv.sys* driver. We start from `DriverEntry`:
```c
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
  _security_init_cookie();
  return u_driver_main(DriverObject);
}
```

```c
__int64 __fastcall u_driver_main(struct _DRIVER_OBJECT *a1) {
  /* ... */
  a1->DriverUnload = (PDRIVER_UNLOAD)u_driver_unload;
  v2 = sub_140001110(a1);
  a1->MajorFunction[0] = (PDRIVER_DISPATCH)u_driver_major_func;
  a1->MajorFunction[2] = (PDRIVER_DISPATCH)u_driver_major_func;
  a1->MajorFunction[3] = (PDRIVER_DISPATCH)u_driver_major_func;
  a1->MajorFunction[4] = (PDRIVER_DISPATCH)u_driver_major_func;
  DriverSection = a1->DriverSection;
  a1->MajorFunction[14] = (PDRIVER_DISPATCH)u_driver_major_func;
  DriverSection[104] |= 0x20u;
  sub_140001040();
  encryptedBuf = MmGetPhysicalAddress((char *)u_disable_write_protect + 0x1B70);// glo_encr_buf
  glo_encr_buf_ptr = (char *)MmMapIoSpace(encryptedBuf, 0x1000ui64, MmNonCached);
  glo_encr_buf_2_ptr = glo_encr_buf_ptr + 0x30;
  PhysicalAddress = MmGetPhysicalAddress((char *)u_disable_write_protect - 96);// 0x140001430
  glo_xor_buf_ptr = (char *)MmMapIoSpace(PhysicalAddress, 0x1000ui64, MmNonCached);
  glo_decr_func_off = glo_xor_buf_ptr + 0x700;  // u_decr_func
  v6 = u_disable_write_protect();

  *glo_decr_func_off ^= *glo_xor_buf_ptr;
  glo_decr_func_off[1] ^= glo_xor_buf_ptr[1];
  glo_decr_func_off[2] ^= glo_xor_buf_ptr[2];
  glo_decr_func_off[3] ^= glo_xor_buf_ptr[3];
  glo_decr_func_off[4] ^= glo_xor_buf_ptr[4];
  glo_decr_func_off[5] ^= glo_xor_buf_ptr[5];
  glo_decr_func_off[6] ^= glo_xor_buf_ptr[6];
  glo_decr_func_off[7] ^= glo_xor_buf_ptr[7];
  glo_decr_func_off[8] ^= glo_xor_buf_ptr[8];
  glo_decr_func_off[9] ^= glo_xor_buf_ptr[9];
  glo_decr_func_off[10] ^= glo_xor_buf_ptr[10];
  glo_decr_func_off[11] ^= glo_xor_buf_ptr[11];
  glo_decr_func_off[12] ^= glo_xor_buf_ptr[12];
  glo_decr_func_off[13] ^= glo_xor_buf_ptr[13];
  glo_decr_func_off[14] ^= glo_xor_buf_ptr[14];
  glo_decr_func_off[15] ^= glo_xor_buf_ptr[15];

  *glo_decr_func_off ^= glo_xor_buf_ptr[16];
  glo_decr_func_off[1] ^= glo_xor_buf_ptr[17];
  glo_decr_func_off[2] ^= glo_xor_buf_ptr[18];
  glo_decr_func_off[3] ^= glo_xor_buf_ptr[19];
  glo_decr_func_off[4] ^= glo_xor_buf_ptr[20];
  glo_decr_func_off[5] ^= glo_xor_buf_ptr[21];
  glo_decr_func_off[6] ^= glo_xor_buf_ptr[22];
  glo_decr_func_off[7] ^= glo_xor_buf_ptr[23];
  glo_decr_func_off[8] ^= glo_xor_buf_ptr[24];
  glo_decr_func_off[9] ^= glo_xor_buf_ptr[25];
  glo_decr_func_off[10] ^= glo_xor_buf_ptr[26];
  glo_decr_func_off[11] ^= glo_xor_buf_ptr[27];
  glo_decr_func_off[12] ^= glo_xor_buf_ptr[28];
  glo_decr_func_off[13] ^= glo_xor_buf_ptr[29];
  glo_decr_func_off[14] ^= glo_xor_buf_ptr[30];
  glo_decr_func_off[15] ^= glo_xor_buf_ptr[31];

  u_enable_write_protect(v6);
  return v2;
}
```

There are a few things going on here. First driver sets the `u_driver_major_func` to
handle the I/O. Then it maps some parts of the code into memory so it can modify them
(yes it's a self-modifying driver). The function that modifies is `u_decr_func` at
`140001B30h`:
```c
char __fastcall u_decr_func(char a1) {
  return 0x9E - 0x11 * ((a1 - 0x22) ^ 0xAD);
}
```

Program also uses the following buffers (we will use them later):
```assembly
.data:0000000140003000 glo_encr_buf db 63h, 60h, 0A5h, 0B9h, 0FFh, 0FCh, 30h, 0Ah, 48h, 0BBh, 2 dup(0FEh)
.data:0000000140003000                                         ; DATA XREF: u_driver_major_func+15B↑r
.data:0000000140003000                                         ; u_driver_major_func+16D↑r
.....

.text:0000000140001430 glo_xor_buf db 40h, 53h, 48h, 83h, 0ECh, 20h, 48h, 8Bh, 5, 3Bh, 0Ch, 2 dup(0)
.text:0000000140001430                                         ; DATA XREF: sub_140001040+83↑o
.text:0000000140001430                                         ; .rdata:00000001400020A0↓o ...
.text:0000000140001430         db 48h, 8Bh, 0DAh, 48h, 8Bh, 4Ah, 10h, 48h, 39h, 8, 75h, 37h, 48h
.....
```

Flag decryption takes place at `u_driver_major_func` at `1400011Bh`:
```c
__int64 __fastcall u_driver_major_func(PDEVICE_OBJECT VolumeDeviceObject, PIRP Irp) {
  /* ... */
  Length = 0;
  CurrentIrpStackLocation = IoGetCurrentIrpStackLocation(Irp);
  if ( VolumeDeviceObject != DeviceObject )
    return 0xC0000001i64;
  if ( CurrentIrpStackLocation->MajorFunction )
  {
    if ( CurrentIrpStackLocation->MajorFunction == 14 )
    {
      Length = CurrentIrpStackLocation->Parameters.Read.Length;
      switch ( CurrentIrpStackLocation->Parameters.Read.ByteOffset.LowPart )
      {
        case 0x222000u:
          u_do_decrypt(0);
          glo_check_bitmap[0] = 1;
          break;
        case 0x222010u:
          u_do_decrypt(0x20u);
          glo_check_bitmap[1] = 1;
          break;
        case 0x222020u:
          u_do_decrypt(0x40u);
          glo_check_bitmap[2] = 1;
          break;
        case 0x222030u:
          u_do_decrypt(0x60u);
          glo_check_bitmap[3] = 1;
          break;
        case 0x222040u:
          u_do_decrypt(0x80u);
          glo_check_bitmap[4] = 1;
          break;
        case 0x222050u:
          u_do_decrypt(0xA0u);
          glo_check_bitmap[5] = 1;
          break;
        case 0x222060u:
          u_do_decrypt(0xC0u);
          glo_check_bitmap[6] = 1;
          break;
        case 0x222070u:
          u_do_decrypt(0xE0u);
          glo_check_bitmap[7] = 1;
          break;
        case 0x222080u:
          if ( !Length )
            goto LABEL_15;
          guard = 1;
          chk_cnt = 0i64;
          while ( glo_check_bitmap[chk_cnt] )
          {
            if ( ++chk_cnt >= 8 )
              goto CHECK_PASSED;
          }
          guard = 0;
CHECK_PASSED:
          if ( guard )
          {
            v9 = *(_DWORD *)glo_encr_buf - 'ctih';
            if ( *(_DWORD *)glo_encr_buf == 'ctih' )
              v9 = *(unsigned __int16 *)&glo_encr_buf[4] - 'no';
            LOBYTE(Irp->AssociatedIrp.MasterIrp->Type) = v9 == 0;
          }
          else
          {
LABEL_15:
            LOBYTE(Irp->AssociatedIrp.MasterIrp->Type) = 0;
          }
          break;
        default:
          break;
      }
    }
  }
  else
  {
    byte_140003170[(_QWORD)PsGetCurrentProcessId()] = 1;
  }
  Irp->IoStatus.Information = Length;
  Irp->IoStatus.Status = 0;
  IofCompleteRequest(Irp, 0);
  return 0i64;
}
```

Based on the I/O control code, function invokes `u_do_decrypt` with a different offset
as an argument. If you notice offsets span from **0** to **0xE0** with intervals of **0x20**.
If all the codes are invoked then all entries in `glo_check_bitmap` are set, so driver returns
the flag. That is, `gloc_encr_buf` contains the encrypted flag:
```assembly
.data:0000000140003000 glo_encr_buf db 63h, 60h, 0A5h, 0B9h, 0FFh, 0FCh, 30h, 0Ah, 48h, 0BBh, 2 dup(0FEh)
.data:0000000140003000                                         ; DATA XREF: u_driver_major_func+15B↑r
.data:0000000140003000                                         ; u_driver_major_func+16D↑r
.data:0000000140003000         db 32h, 2Ch, 0Ah, 0D6h, 0E6h, 2 dup(0FEh), 32h, 2Ch, 0Ah, 0D6h
.data:0000000140003000         db 0BBh, 2 dup(4Ah), 32h, 2Ch, 0FCh, 0FFh, 0Ah, 0FDh, 0BBh, 0FEh
.data:0000000140003000         db 2Ch, 0B9h, 63h, 0D6h, 0B9h, 62h, 0D6h, 0Ah, 4Fh, 5 dup(0)
.data:0000000140003030 glo_opcodes_xor_buf db 19h, 0BCh, 8Fh, 82h, 0D0h, 2Ch, 61h, 34h, 0C0h, 9Fh, 0F6h, 50h
.data:0000000140003030         db 0D5h, 0FBh, 0Ch, 6Eh, 0D0h, 0EBh, 0E5h, 0E3h, 0CEh, 0B5h, 4Ch
.data:0000000140003030         db 0CAh, 45h, 0AAh, 11h, 0B2h, 3Eh, 62h, 6Fh, 7Dh, 0D0h, 0EBh
.data:0000000140003030         db 0A9h, 0E3h, 0B2h, 2Fh, 6, 47h, 7Ch, 28h, 0C5h, 2 dup(0DEh)
.data:0000000140003030         db 1Ah, 4Eh, 0D6h, 0D8h, 2Dh, 93h, 4Fh, 82h, 65h, 64h, 0FDh, 8
....
```

Finally we have `u_do_decrypt` at `1400014D0h`:
```c
void __fastcall u_do_decrypt(unsigned int a1_off) {
  /* ... */
  *(_QWORD *)&off = a1_off;
  *glo_decr_func_off ^= glo_opcodes_xor_buf_ptr[*(_QWORD *)&off];
  glo_decr_func_off[1] ^= glo_opcodes_xor_buf_ptr[off + 1];
  glo_decr_func_off[2] ^= glo_opcodes_xor_buf_ptr[off + 2];
  glo_decr_func_off[3] ^= glo_opcodes_xor_buf_ptr[off + 3];
  glo_decr_func_off[4] ^= glo_opcodes_xor_buf_ptr[off + 4];
  glo_decr_func_off[5] ^= glo_opcodes_xor_buf_ptr[off + 5];
  glo_decr_func_off[6] ^= glo_opcodes_xor_buf_ptr[off + 6];
  glo_decr_func_off[7] ^= glo_opcodes_xor_buf_ptr[off + 7];
  glo_decr_func_off[8] ^= glo_opcodes_xor_buf_ptr[off + 8];
  glo_decr_func_off[9] ^= glo_opcodes_xor_buf_ptr[off + 9];
  glo_decr_func_off[10] ^= glo_opcodes_xor_buf_ptr[off + 10];
  glo_decr_func_off[11] ^= glo_opcodes_xor_buf_ptr[off + 11];
  glo_decr_func_off[12] ^= glo_opcodes_xor_buf_ptr[off + 12];
  glo_decr_func_off[13] ^= glo_opcodes_xor_buf_ptr[off + 13];
  glo_decr_func_off[14] ^= glo_opcodes_xor_buf_ptr[off + 14];
  glo_decr_func_off[15] ^= glo_opcodes_xor_buf_ptr[off + 15];

  v3 = glo_encr_buf_ptr;
  *v3 = u_decr_func(*glo_encr_buf_ptr);
  v4 = glo_encr_buf_ptr;
  v4[1] = u_decr_func(glo_encr_buf_ptr[1]);
  v5 = glo_encr_buf_ptr;
  v5[2] = u_decr_func(glo_encr_buf_ptr[2]);
  v6 = glo_encr_buf_ptr;
  v6[3] = u_decr_func(glo_encr_buf_ptr[3]);
  v7 = glo_encr_buf_ptr;
  v7[4] = u_decr_func(glo_encr_buf_ptr[4]);
  /**
   *  Do the same for the next bytes ....
   */
  v43 = glo_encr_buf_ptr;
  v43[40] = u_decr_func(glo_encr_buf_ptr[40]);
  v44 = glo_encr_buf_ptr;
  v44[41] = u_decr_func(glo_encr_buf_ptr[41]);
  v45 = glo_encr_buf_ptr;
  v45[42] = u_decr_func(glo_encr_buf_ptr[42]);

  *glo_decr_func_off ^= glo_opcodes_xor_buf_ptr[off + 16];
  glo_decr_func_off[1] ^= glo_opcodes_xor_buf_ptr[off + 17];
  glo_decr_func_off[2] ^= glo_opcodes_xor_buf_ptr[off + 18];
  glo_decr_func_off[3] ^= glo_opcodes_xor_buf_ptr[off + 19];
  glo_decr_func_off[4] ^= glo_opcodes_xor_buf_ptr[off + 20];
  glo_decr_func_off[5] ^= glo_opcodes_xor_buf_ptr[off + 21];
  glo_decr_func_off[6] ^= glo_opcodes_xor_buf_ptr[off + 22];
  glo_decr_func_off[7] ^= glo_opcodes_xor_buf_ptr[off + 23];
  glo_decr_func_off[8] ^= glo_opcodes_xor_buf_ptr[off + 24];
  glo_decr_func_off[9] ^= glo_opcodes_xor_buf_ptr[off + 25];
  glo_decr_func_off[10] ^= glo_opcodes_xor_buf_ptr[off + 26];
  glo_decr_func_off[11] ^= glo_opcodes_xor_buf_ptr[off + 27];
  glo_decr_func_off[12] ^= glo_opcodes_xor_buf_ptr[off + 28];
  glo_decr_func_off[13] ^= glo_opcodes_xor_buf_ptr[off + 29];
  glo_decr_func_off[14] ^= glo_opcodes_xor_buf_ptr[off + 30];
  glo_decr_func_off[15] ^= glo_opcodes_xor_buf_ptr[off + 31];
  u_enable_write_protect(v2);
}
```

Function uses the parameter as an offset to `glo_opcodes_xor_buf_ptr` (which is
actually `glo_opcodes_xor_buf`) to select some bytes and XOR them with the
`glo_decr_func_off` which points to `u_decr_func` at `140001B30h`. That is
function "decrypts" `u_decr_func`.

After XOR, function decrypts the flag (`glo_encr_buf_ptr`) byte-by-byte. Then
it uses the next **16** bytes from the `glo_opcodes_xor_buf` to "encrypt" again
`u_decr_func`, before passing it to the next decryption.


### Cracking the Code

To get the flag, we have to invoke the driver with all I/O control codes and
invoke `u_do_decrypt` with all **8** possible offsets to decrypt `glo_encr_buf`
**8** times.

The problem is that **we do not know the order** of the decryptions. That is,
the `u_decr_func` is changed every time we call `u_do_decrypt` which affects
the final result (flag).

At first, we have **8** possible offset candidates (`0, 20h, 40h, 60h, 80h A0h, C0h, E0h`).
We try all of them and we check which decryption for `u_decr_func` "makes sense"
(i.e., yields to meaningful disassembly):
```assembly
Trying candidate #0 (Offset: 0x0) ...
Opcodes: 91-8D-AF-91-85-98-2E-7C-33-87-B9-0B-65-D2-92-A9
.text:140001B30 	xchg	eax, ecx
.text:140001B31 	lea	ebp, [rdi + 0x2e988591]
.text:140001B37 	jl	0x140001b6c
.text:140001B39 	xchg	dword ptr [rcx - 0x6d2d9af5], edi

Trying candidate #1 (Offset: 0x20) ...
Opcodes: 58-DA-89-F0-E7-9B-49-0F-8F-30-8A-85-6E-33-D0-11
.text:140001B30 	pop	rax
.text:140001B31 	fimul	dword ptr [rcx + 0x499be7f0]
.text:140001B37 	jg	0x1ae85a56d
.text:140001B3D 	xor	edx, eax

Trying candidate #2 (Offset: 0x40) ...
Opcodes: 3F-8B-F0-2A-3D-E7-1F-E3-D3-CD-85-DF-96-58-F1-56

Trying candidate #3 (Offset: 0x60) ...
Opcodes: 51-3E-1D-90-A6-48-9E-5B-E9-7A-5D-1B-1A-C3-53-0C
.text:140001B30 	push	rcx
.text:140001B31 	sbb	eax, 0x9e48a690
.text:140001B37 	pop	rbx
.text:140001B38 	jmp	0x15a1b78b7
.text:140001B3D 	ret	
.text:140001B3E 	push	rbx

Trying candidate #4 (Offset: 0x80) ...
Opcodes: D2-EB-19-14-A5-9A-7D-68-AA-4E-03-EF-3F-17-99-A6
.text:140001B30 	shr	bl, cl
.text:140001B32 	sbb	dword ptr [0xffffffffaa687d9a], edx
.text:140001B39 	add	r13, rdi

Trying candidate #5 (Offset: 0xA0) ...
Opcodes: 69-F7-38-70-CF-2F-C5-C2-8C-10-8C-B3-51-C5-95-48
.text:140001B30 	imul	esi, edi, 0x2fcf7038

Trying candidate #6 (Offset: 0xC0) ...
Opcodes: 1C-40-91-86-84-44-20-FF-2A-25-4A-C5-71-7A-AD-B1
.text:140001B30 	sbb	al, 0x40
.text:140001B32 	xchg	eax, ecx
.text:140001B33 	xchg	byte ptr [rsp + rax*2 + 0x252aff20], al

Trying candidate #7 (Offset: 0xE0) ...
Opcodes: 0F-B6-D1-8B-C2-C0-E2-03-C1-E8-05-0A-C2-C3-97-30
.text:140001B30 	movzx	edx, cl
.text:140001B33 	mov	eax, edx
.text:140001B35 	shl	dl, 3
.text:140001B38 	shr	eax, 5
.text:140001B3B 	or	al, dl
.text:140001B3D 	ret	
.text:140001B3E 	xchg	eax, edi
```

From the above disassembly listings, only the last one is good, which
gives us the following decryption function:
```c
unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
  return (8 * a1) | (a1 >> 5);
}
```

After we apply decryption we move on. This time we have **7** candidates:
```assembly
Opcodes: 37-4B-F6-36-DE-92-93-40-54-74-1F-8C-30-03-6E-C8
Trying candidate #0 (Offset: 0x0) ...

Opcodes: 2E-F7-79-B4-0E-BE-F2-74-94-EB-E9-DC-E5-F8-62-A6
.text:140001B30 	idiv	dword ptr cs:[rcx - 0x4c]

Trying candidate #1 (Offset: 0x20) ...
Opcodes: E7-A0-5F-D5-6C-BD-95-07-28-5C-DA-52-EE-19-20-1E
.text:140001B30 	out	0xa0, eax
.text:140001B32 	pop	rdi

Trying candidate #2 (Offset: 0x40) ...
Opcodes: 80-F1-26-0F-B6-C1-C3-EB-74-A1-D5-08-16-72-01-59
.text:140001B30 	xor	cl, 0x26
.text:140001B33 	movzx	eax, cl
.text:140001B36 	ret	
.text:140001B37 	jmp	0x140001bad

Trying candidate #3 (Offset: 0x60) ...
Opcodes: EE-44-CB-B5-2D-6E-42-53-4E-16-0D-CC-9A-E9-A3-03
.text:140001B30 	out	dx, al
.text:140001B31 	retf	
.text:140001B33 	mov	ch, 0x2d
.text:140001B35 	outsb	dx, byte ptr [rsi]
.text:140001B36 	push	rbx

Trying candidate #4 (Offset: 0x80) ...
Opcodes: 6D-91-CF-31-2E-BC-A1-60-0D-22-53-38-BF-3D-69-A9
.text:140001B30 	insd	dword ptr [rdi], dx
.text:140001B31 	xchg	eax, ecx
.text:140001B32 	iretd	
.text:140001B33 	xor	dword ptr [rsi], ebp
.text:140001B35 	mov	esp, 0x220d60a1
.text:140001B3A 	push	rbx

Trying candidate #5 (Offset: 0xA0) ...
Opcodes: D6-8D-EE-55-44-09-19-CA-2B-7C-DC-64-D1-EF-65-47

Trying candidate #6 (Offset: 0xC0) ...
Opcodes: A3-3A-47-A3-0F-62-FC-F7-8D-49-1A-12-F1-50-5D-BE
.text:140001B30 	movabs	dword ptr [0x8df7fc620fa3473a], eax
.text:140001B39 	sbb	dl, byte ptr [r10]
.text:140001B3C 	int1	
.text:140001B3D 	push	rax
.text:140001B3E 	pop	rbp
```

From these candidates the correct one is the **third** one:
```c
unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
      return a1 ^ 0x26u;
}
```

We continue this process until we find the correct order of the decryption:
```
 Decryption Order:
       0xE0 ~> 0F B6 D1 8B C2 C0 E2 03 C1 E8 05 0A C2 C3 97 30
       0x40 ~> 80 F1 26 0F B6 C1 C3 EB 74 A1 D5 08 16 72 01 59
       0xC0 ~> 0F B6 D1 8B C2 C0 E2 04 C1 E8 04 0A C2 C3 1A FA
       0x0 ~>  8D 41 37 C3 CC 11 FE 57 B9 5E D9 9D D2 BC 3A 45
       0x20 ~> 8D 41 7B C3 B0 8B B4 DA 80 DC 0D F1 32 C4 1B EE
       0x80 ~> 0F B6 D1 8B C2 C0 E2 07 D1 E8 0A C2 C3 A8 5B BF
       0x60 ~> 0F B6 C1 69 C0 AD 00 00 00 C3 70 7C 76 96 1C 8A
       0xA0 ~> 0F B6 D1 8B C2 C0 E2 02 C1 E8 06 0A C2 C3 F5 78


Decryption Routines:
        # 0F B6 D1 8B C2 C0 E2 03 C1 E8 05 0A C2 C3 97 30
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
          return (8 * a1) | (a1 >> 5);
        }

        # 80 F1 26 0F B6 C1 C3 EB 74 A1 D5 08 16 72 01 59
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
          return a1 ^ 0x26u;
        }

        # 0F B6 D1 8B C2 C0 E2 04 C1 E8 04 0A C2 C3 1A FA
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
            return (16 * a1) | (a1 >> 4);
        }

        # 8D 41 37 C3 CC 11 FE 57 B9 5E D9 9D D2 BC 3A 45
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
          return a1 + 55;
        }

        # 8D 41 7B C3 B0 8B B4 DA 80 DC 0D F1 32 C4 1B EE
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
            return a1 + 123;
        }
        
        # 0F B6 D1 8B C2 C0 E2 07 D1 E8 0A C2 C3 A8 5B BF
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
            return (a1 << 7) | (a1 >> 1);
        }    

        # 0F B6 C1 69 C0 AD 00 00 00 C3 70 7C 76 96 1C 8A
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
            return 0xAD * a1;
        }    

        # 0F B6 D1 8B C2 C0 E2 02 C1 E8 06 0A C2 C3 F5 78
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
            return (4 * a1) | (a1 >> 6);
        }    
```

Once we know the decryption order and all the versions of the `u_decr_func`,
we can easily decrypt the `glo_encr_buf` and get the flag.

**NOTE:** We can automate this process by recursively trying all possible decryptions.
Incorrect decryptions will yield to invalid opcodes (e.g., have not `retn` instruction),
so recursion will backtrack and try another path. A path that reaches a depth of **8**
will be the correct (hopefully) solution. However, with some scripting we can quickly
select the correct function at each step and get the solution a lot simpler.

For more details, please refer to the [checker_crack.py](./checker_crack.py) file.

So the flag is: `hitcon{r3ally_re4lly_rea11y_normal_checker}`

___

