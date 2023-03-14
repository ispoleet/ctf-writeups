#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HXP 2022 - required (RE 385)
# ----------------------------------------------------------------------------------------
import re
import os
import textwrap


# All flag operations.
flag_ops = textwrap.dedent("""
    f[17]+=f[5]
    f[29]=~f[29]&0xff
    f[3]^=f[11]
    f[6]=f[6]<<7&0xff|f[6]>>1
    f[2]=~f[2]&0xff
    f[20]=f[20]<<7&0xff|f[20]>>1
    f[23]=f[23]^(f[23]>>1)
    f[15]=f[15]^(f[15]>>1)
    f[9]^=f[1]
    f[9]^=f[4]
    f[16]=f[16]^(f[16]>>1)
    f[11]=f[11]<<1&0xff|f[11]>>7
    f[28]=~f[28]&0xff
    f[0]=~f[0]&0xff
    f[16]+=f[13]
    f[14]+=f[29]
    f[13]=~f[13]&0xff
    f[26]-=f[7]
    f[26]-=f[0]
    f[18]-=f[29]
    f[8]=f[8]<<1&0xff|f[8]>>7
    f[4]=f[4]^(f[4]>>1)
    f[5]-=f[7]
    f[10]^=f[29]
    f[15]^=f[20]
    f[22]=f[22]<<7&0xff|f[22]>>1
    f[4]^=f[15]
    f[13]-=f[3]
    f[5]=f[5]<<1&0xff|f[5]>>7
    f[26]=f[26]<<7&0xff|f[26]>>1
    f[14]^=f[21]
    f[29]=f[29]<<7&0xff|f[29]>>1
    f[1]-=f[4]
    f[4]=~f[4]&0xff
    f[13]-=f[18]
    f[16]=f[16]<<1&0xff|f[16]>>7
    f[11]=f[11]<<7&0xff|f[11]>>1
    f[7]-=f[6]
    f[11]-=f[20]
    f[23]=~f[23]&0xff
    f[4]+=f[3]
    f[26]+=f[22]
    f[16]=f[16]<<1&0xff|f[16]>>7
    f[11]+=f[8]
    f[8]^=f[9]
    f[24]+=f[14]
    f[29]-=f[24]
    f[4]-=f[18]
    f[1]=f[1]<<7&0xff|f[1]>>1
    f[20]=f[20]<<7&0xff|f[20]>>1
    f[20]=f[20]<<7&0xff|f[20]>>1
    f[20]=~f[20]&0xff
    f[11]^=f[2]
    f[20]-=f[24]
    f[2]+=f[6]
    f[10]+=f[24]
    f[25]=f[25]^(f[25]>>1)
    f[12]^=f[14]
    f[25]=f[25]<<7&0xff|f[25]>>1
    f[15]=f[15]<<1&0xff|f[15]>>7
    f[25]+=f[12]
    f[2]+=f[5]
    f[0]-=f[11]
    f[6]-=f[1]
    f[6]+=f[17]
    f[29]-=f[9]
    f[7]=~f[7]&0xff
    f[2]+=f[5]
    f[22]-=f[2]
    f[24]=f[24]<<1&0xff|f[24]>>7
    f[20]=f[20]^(f[20]>>1)
    f[28]=f[28]^(f[28]>>1)
    f[15]^=f[20]
    f[3]=f[3]<<1&0xff|f[3]>>7
    f[17]=f[17]<<7&0xff|f[17]>>1
    f[11]=f[11]<<7&0xff|f[11]>>1
    f[18]=~f[18]&0xff
    f[13]=f[13]^(f[13]>>1)
    f[15]-=f[2]
    f[9]+=f[20]
    f[6]^=f[1]
    f[1]-=f[13]
    f[0]-=f[4]
    f[14]=~f[14]&0xff
    f[17]=f[17]<<1&0xff|f[17]>>7
    f[17]=f[17]<<7&0xff|f[17]>>1
    f[14]=f[14]^(f[14]>>1)
    f[24]-=f[7]
    f[16]^=f[6]
    f[13]+=f[9]
    f[1]-=f[10]
    f[28]=f[28]<<1&0xff|f[28]>>7
    f[25]-=f[22]
    f[14]=f[14]^(f[14]>>1)
    f[2]=f[2]<<7&0xff|f[2]>>1
    f[2]^=f[15]
    f[17]=f[17]<<7&0xff|f[17]>>1
    f[3]-=f[22]
    f[23]=f[23]<<7&0xff|f[23]>>1
    f[11]=f[11]<<7&0xff|f[11]>>1
    f[9]+=f[16]
    f[7]=f[7]<<7&0xff|f[7]>>1
    f[6]=~f[6]&0xff
    f[5]+=f[15]
    f[6]-=f[17]
    f[7]-=f[6]
    f[3]+=f[28]
    f[1]^=f[18]
    f[22]-=f[5]
    f[14]-=f[2]
    f[21]^=f[22]
    f[4]-=f[29]
    f[26]=(((f[26]*0x0802&0x22110)|(f[26]*0x8020&0x88440))*0x10101>>>16)&0xff
    f[17]-=f[18]
    f[17]=f[17]<<1&0xff|f[17]>>7
    f[16]-=f[3]
    f[25]^=f[21]
    f[14]+=f[9]
    f[1]+=f[13]
    f[0]^=f[1]
    f[1]^=f[28]
    f[14]=~f[14]&0xff
    f[27]=(((f[27]*0x0802&0x22110)|(f[27]*0x8020&0x88440))*0x10101>>>16)&0xff
    f[9]^=f[2]
    f[17]=f[17]<<7&0xff|f[17]>>1
    f[13]^=f[1]
    f[5]^=f[13]
    f[10]^=f[0]
    f[12]^=f[1]
    f[2]=~f[2]&0xff
    f[1]=f[1]<<7&0xff|f[1]>>1
    f[11]=f[11]<<1&0xff|f[11]>>7
    f[9]^=f[28]
    f[3]=(((f[3]*0x0802&0x22110)|(f[3]*0x8020&0x88440))*0x10101>>>16)&0xff
    f[19]=f[19]<<1&0xff|f[19]>>7
    f[16]-=f[9]
    f[8]=f[8]<<1&0xff|f[8]>>7
    f[28]=f[28]<<1&0xff|f[28]>>7
    f[12]-=f[3]
    f[25]=(((f[25]*0x0802&0x22110)|(f[25]*0x8020&0x88440))*0x10101>>>16)&0xff
    f[14]=(((f[14]*0x0802&0x22110)|(f[14]*0x8020&0x88440))*0x10101>>>16)&0xff
    f[11]=f[11]<<7&0xff|f[11]>>1
    f[6]+=f[28]
    f[6]^=f[5]
    f[28]^=f[0]
    f[10]-=f[22]
    f[8]=f[8]^(f[8]>>1)
    f[19]=f[19]<<7&0xff|f[19]>>1
    f[26]-=f[14]
    f[25]^=f[28]
    f[15]-=f[17]
    f[12]^=f[4]
    f[25]+=f[4]
    f[11]=~f[11]&0xff
    f[1]=f[1]<<7&0xff|f[1]>>1
    f[9]+=f[28]
    f[4]^=f[18]
    f[15]=~f[15]&0xff
    f[12]=f[12]<<1&0xff|f[12]>>7
    f[12]=f[12]<<7&0xff|f[12]>>1
    f[2]=f[2]^(f[2]>>1)
    f[6]=~f[6]&0xff
    f[10]=f[10]<<7&0xff|f[10]>>1
    f[20]=f[20]^(f[20]>>1)
    f[20]+=f[24]
    f[4]=f[4]<<1&0xff|f[4]>>7
    f[16]^=f[11]
    f[8]=~f[8]&0xff
    f[1]=(((f[1]*0x0802&0x22110)|(f[1]*0x8020&0x88440))*0x10101>>>16)&0xff
    f[4]+=f[18]
    f[5]=f[5]^(f[5]>>1)
    f[25]-=f[4]
    f[9]^=f[26]
    f[5]^=f[3]
    f[4]^=f[2]
    f[29]-=f[21]
    f[20]=f[20]<<1&0xff|f[20]>>7
    f[24]^=f[27]
    f[8]+=f[16]
    f[22]=f[22]<<7&0xff|f[22]>>1
    f[3]=f[3]<<7&0xff|f[3]>>1
    f[10]-=f[9]
    f[9]=f[9]^(f[9]>>1)
    f[24]^=f[25]
    f[9]=~f[9]&0xff
    f[1]=f[1]^(f[1]>>1)
    f[19]=f[19]<<1&0xff|f[19]>>7
    f[7]=f[7]<<7&0xff|f[7]>>1
    f[21]+=f[25]
    f[28]-=f[0]
    f[18]=f[18]<<7&0xff|f[18]>>1
    f[20]^=f[5]
    f[17]^=f[12]
    f[22]-=f[23]
    f[18]+=f[25]
    f[4]=f[4]<<1&0xff|f[4]>>7
    f[0]=f[0]<<1&0xff|f[0]>>7
    f[29]=f[29]<<1&0xff|f[29]>>7
    f[17]=f[17]<<1&0xff|f[17]>>7
    f[7]^=f[21]
    f[8]-=f[17]
    f[10]+=f[22]
    f[8]-=f[18]
    f[21]+=f[0]
    f[15]^=f[20]
    f[1]=f[1]<<1&0xff|f[1]>>7
    f[14]=f[14]<<7&0xff|f[14]>>1
    f[13]^=f[2]
    f[9]^=f[6]
    f[15]-=f[8]
    f[8]^=f[1]
    f[6]=f[6]^(f[6]>>1)
    f[21]^=f[5]
    f[17]^=f[13]
    f[12]-=f[8]
    f[19]^=f[12]
    f[2]^=f[1]
    f[25]=f[25]<<1&0xff|f[25]>>7
    f[19]=f[19]^(f[19]>>1)
    f[0]=f[0]^(f[0]>>1)
    f[17]+=f[27]
    f[20]=f[20]<<7&0xff|f[20]>>1
    f[28]-=f[13]
    f[22]=~f[22]&0xff
    f[26]^=f[17]
    f[10]=f[10]<<1&0xff|f[10]>>7
    f[24]=~f[24]&0xff
    f[4]-=f[22]
    f[4]-=f[20]
    f[24]+=f[12]
    f[13]=f[13]<<1&0xff|f[13]>>7
    f[2]=f[2]<<7&0xff|f[2]>>1
    f[1]-=f[24]
    f[11]^=f[27]
    f[14]=f[14]^(f[14]>>1)
    f[17]=f[17]^(f[17]>>1)
    f[21]=f[21]^(f[21]>>1)
    f[24]=(((f[24]*0x0802&0x22110)|(f[24]*0x8020&0x88440))*0x10101>>>16)&0xff
    f[12]=f[12]^(f[12]>>1)
    f[3]=f[3]<<1&0xff|f[3]>>7
    f[8]+=f[1]
    f[21]+=f[18]
    f[0]+=f[22]
    f[4]=f[4]<<7&0xff|f[4]>>1
    f[25]=f[25]<<1&0xff|f[25]>>7
    f[10]=f[10]<<7&0xff|f[10]>>1
    f[13]=f[13]^(f[13]>>1)
    f[1]-=f[27]
    f[13]=(((f[13]*0x0802&0x22110)|(f[13]*0x8020&0x88440))*0x10101>>>16)&0xff
    f[11]=(((f[11]*0x0802&0x22110)|(f[11]*0x8020&0x88440))*0x10101>>>16)&0xff
    f[2]+=f[17]
    f[6]=f[6]<<7&0xff|f[6]>>1
    f[10]=f[10]^(f[10]>>1)
    f[4]-=f[8]
    f[1]-=f[2]
    f[0]-=f[14]
    f[11]=f[11]^(f[11]>>1)
    f[7]-=f[17]
    f[18]=~f[18]&0xff
    f[0]^=f[16]
    f[12]+=f[13]
    f[23]=~f[23]&0xff
    f[10]-=f[7]
    f[29]=f[29]^(f[29]>>1)
    f[3]=f[3]<<7&0xff|f[3]>>1
    f[20]^=f[3]
    f[8]=f[8]<<1&0xff|f[8]>>7
    f[25]-=f[24]
    f[26]=f[26]<<1&0xff|f[26]>>7
    f[10]=f[10]^(f[10]>>1)
    f[26]=f[26]^(f[26]>>1)
    f[16]-=f[7]
    f[8]=~f[8]&0xff
    f[14]^=f[13]
    f[3]+=f[24]
    f[15]=(((f[15]*0x0802&0x22110)|(f[15]*0x8020&0x88440))*0x10101>>>16)&0xff
    f[15]-=f[28]
    f[10]=f[10]^(f[10]>>1)
    f[17]+=f[15]
    f[22]-=f[2]
    f[27]=~f[27]&0xff
    f[5]=f[5]^(f[5]>>1)
    f[20]=~f[20]&0xff
    f[13]^=f[24]
    f[23]^=f[21]
    f[2]-=f[23]
    f[5]+=f[20]
    f[24]^=f[12]
    f[9]-=f[8]
    f[11]=f[11]^(f[11]>>1)
    f[27]-=f[14]
    f[18]+=f[25]
    f[6]+=f[26]
    f[7]=f[7]^(f[7]>>1)
    f[28]=f[28]^(f[28]>>1)
    f[10]-=f[1]
    f[18]-=f[14]
    f[20]+=f[14]
    f[15]-=f[17]
    f[0]=~f[0]&0xff
""")


# ----------------------------------------------------------------------------------------
def patch_js_files(root_dir):
    """Patches all js files to append a console.log() statement."""
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if not file.endswith(".js"):
                continue

            # Blacklisted files.
            if file in ['289.js', '37.js', '314.js', '556.js', '28.js', '157.js',
                        '299.js', '394.js', '555.js', '736.js', 'required.js']:
                continue

            # Read file
            with open(os.path.join(root_dir, file)) as fp:
                content = fp.read().strip()


            # Verify that all files start the same.        
            prolog = 'module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],'
            if not content.startswith(prolog):
                raise Exception(f'Invalid file content: {content}')

            line = content[len(prolog):]        # Drop the prolog            
            line = line[:-1]                    # Drop the last ')'
            stmt = line.split(',')[0]           # Get the 1st operation on f
                                                # (we can have an extra f[i]&=0xff too)
            stmt = stmt.replace('i', '${i}')    # Substitute parameters with formatted strings
            stmt = stmt.replace('j', '${j}')
            stmt = stmt.replace('t', '${t}')

            # Put operation into a console.log() statement with i,j,t being substituted
            line = prolog + line + f",console.log(`{stmt}`))"
 
            print(f'[+] Patching {file}: {line}')

            # Write patched file back.
            with open(os.path.join(root_dir, file), 'w') as fp:
                fp.write(line)




# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] required crack started.')

    # # Work on a copy of the .js files.
    # patch_js_files('./files/y')
    # exit()

    inverted_ops = ''        
    for line in reversed(flag_ops.splitlines()):
        if not line: continue

        # Add becomes sub.
        if match := re.fullmatch(r"^f\[(\d+)\]\+=f\[(\d+)\]$", line):
            a, b = int(match.group(1)), int(match.group(2))
            inv = f'f[{a}] -= f[{b}]; f[{a}] &= 0xff'
            
        # NOT remains as it is.
        elif match := re.fullmatch(r"^f\[(\d+)\]=~f\[(\d+)\]&0xff$", line):
            inv = line

        # Sub becomes add.
        elif match := re.fullmatch(r"^f\[(\d+)\]\-=f\[(\d+)\]$", line):
            a, b = int(match.group(1)), int(match.group(2))
            inv = f'f[{a}] += f[{b}]; f[{a}] &= 0xff'

        # XOR with shift. Not sure how to invert this. Just brute force it.
        elif match := re.fullmatch(r"^f\[(\d+)\]=f\[(\d+)\]\^\(f\[(\d+)\]>>1\)", line):
            a, b, d = int(match.group(1)), int(match.group(2)), int(match.group(3))            
            assert a == b == d
            inv = f'f[{a}] = [i for i in range(256) if i ^ (i >> 1) == f[{a}]][0]'
            
        # XOR remains as it is. 
        elif match := re.fullmatch(r"^f\[(\d+)\]\^=f\[(\d+)\]$", line):
            inv = line

        # ROL becomes ROR.
        elif match := re.fullmatch(r"^f\[(\d+)\]=f\[(\d+)\]<<(\d)&0xff\|f\[(\d+)\]>>\d$", line):
            a, b = int(match.group(1)), int(match.group(2))
            n = int(match.group(3))
            assert a == b
            inv = f'f[{a}] = ((f[{a}] >> {n}) | (f[{a}] << (8-{n}))) & 0xff'

        # Not sure how to inverse this thing. Brute force it too.
        # 
        # Ex: f[26]=(((f[26]*0x0802&0x22110)|(f[26]*0x8020&0x88440))*0x10101>>>16)&0xff
        elif match := re.fullmatch(r"^f\[(\d+)\]=\(\(\(f\[(\d+)\]\*0x0802&0x22110\)\|"
                                   r"\(f\[(\d+)\]\*0x8020&0x88440\)\)\*0x10101....*$", line):
            a, b, d = int(match.group(1)), int(match.group(2)), int(match.group(3))            
            assert a == b == d

            inv = (f'f[{a}] = [i for i in range(256) '
                   f'if (((i*0x0802&0x22110)|(i*0x8020&0x88440))*0x10101>>16)&0xff == f[{a}]][0]')

        else:
            raise Exception('Unknown operation:', line)

        inverted_ops += inv + '\n'

        print(f'[+] Inverting {line!r} ~> {inv!r}')


    # Generate program
    f = list(bytes.fromhex('0xd19ee193b461fd8d1452e7659acb1f47dc3ed445c8eb4ff191b1abfa7969'[2:]))
    gen_python_prog  = '#!/usr/bin/env python3' + '\n'
    gen_python_prog += '# Program is automatically generated.' + '\n'
    gen_python_prog += f'f = {f}' + '\n'
    gen_python_prog += inverted_ops
    gen_python_prog += 'print("Initial Flag:", f)' + '\n'
    gen_python_prog += 'print("".join(chr(x) for x in f))' + '\n'
    gen_python_prog += '\n'
    
    open('solve.py', 'w').write(gen_python_prog)

    print('[+] Program finished. Bye bye :)')


# ----------------------------------------------------------------------------------------
"""
ispo@ispo-glaptop2:~/ctf/hxp_2022/required$ ./required_crack.py 
[+] required crack started.
[+] Inverting 'f[0]=~f[0]&0xff' ~> 'f[0]=~f[0]&0xff'
[+] Inverting 'f[15]-=f[17]' ~> 'f[15] += f[17]; f[15] &= 0xff'
[+] Inverting 'f[20]+=f[14]' ~> 'f[20] -= f[14]; f[20] &= 0xff'
[+] Inverting 'f[18]-=f[14]' ~> 'f[18] += f[14]; f[18] &= 0xff'
[+] Inverting 'f[10]-=f[1]' ~> 'f[10] += f[1]; f[10] &= 0xff'
[+] Inverting 'f[28]=f[28]^(f[28]>>1)' ~> 'f[28] = [i for i in range(256) if i ^ (i >> 1) == f[28]][0]'
[+] Inverting 'f[7]=f[7]^(f[7]>>1)' ~> 'f[7] = [i for i in range(256) if i ^ (i >> 1) == f[7]][0]'
[+] Inverting 'f[6]+=f[26]' ~> 'f[6] -= f[26]; f[6] &= 0xff'
[+] Inverting 'f[18]+=f[25]' ~> 'f[18] -= f[25]; f[18] &= 0xff'
[+] Inverting 'f[27]-=f[14]' ~> 'f[27] += f[14]; f[27] &= 0xff'
[+] Inverting 'f[11]=f[11]^(f[11]>>1)' ~> 'f[11] = [i for i in range(256) if i ^ (i >> 1) == f[11]][0]'
....
[+] Inverting 'f[16]=f[16]^(f[16]>>1)' ~> 'f[16] = [i for i in range(256) if i ^ (i >> 1) == f[16]][0]'
[+] Inverting 'f[9]^=f[4]' ~> 'f[9]^=f[4]'
[+] Inverting 'f[9]^=f[1]' ~> 'f[9]^=f[1]'
[+] Inverting 'f[15]=f[15]^(f[15]>>1)' ~> 'f[15] = [i for i in range(256) if i ^ (i >> 1) == f[15]][0]'
[+] Inverting 'f[23]=f[23]^(f[23]>>1)' ~> 'f[23] = [i for i in range(256) if i ^ (i >> 1) == f[23]][0]'
[+] Inverting 'f[20]=f[20]<<7&0xff|f[20]>>1' ~> 'f[20] = ((f[20] >> 7) | (f[20] << (8-7))) & 0xff'
[+] Inverting 'f[2]=~f[2]&0xff' ~> 'f[2]=~f[2]&0xff'
[+] Inverting 'f[6]=f[6]<<7&0xff|f[6]>>1' ~> 'f[6] = ((f[6] >> 7) | (f[6] << (8-7))) & 0xff'
[+] Inverting 'f[3]^=f[11]' ~> 'f[3]^=f[11]'
[+] Inverting 'f[29]=~f[29]&0xff' ~> 'f[29]=~f[29]&0xff'
[+] Inverting 'f[17]+=f[5]' ~> 'f[17] -= f[5]; f[17] &= 0xff'
[+] Program finished. Bye bye :)

ispo@ispo-glaptop2:~/ctf/hxp_2022/required$ cat solve.py 
#!/usr/bin/env python3
# Program is automatically generated.
f = [209, 158, 225, 147, 180, 97, 253, 141, 20, 82, 231, 101, 154, 203, 31, 71, 220, 62, 212, 69, 200, 235, 79, 241, 145, 177, 171, 250, 121, 105]
f[0]=~f[0]&0xff
f[15] += f[17]; f[15] &= 0xff
f[20] -= f[14]; f[20] &= 0xff
f[18] += f[14]; f[18] &= 0xff
f[10] += f[1]; f[10] &= 0xff
f[28] = [i for i in range(256) if i ^ (i >> 1) == f[28]][0]
f[7] = [i for i in range(256) if i ^ (i >> 1) == f[7]][0]
f[6] -= f[26]; f[6] &= 0xff
f[18] -= f[25]; f[18] &= 0xff
f[27] += f[14]; f[27] &= 0xff
....
f[28]=~f[28]&0xff
f[11] = ((f[11] >> 1) | (f[11] << (8-1))) & 0xff
f[16] = [i for i in range(256) if i ^ (i >> 1) == f[16]][0]
f[9]^=f[4]
f[9]^=f[1]
f[15] = [i for i in range(256) if i ^ (i >> 1) == f[15]][0]
f[23] = [i for i in range(256) if i ^ (i >> 1) == f[23]][0]
f[20] = ((f[20] >> 7) | (f[20] << (8-7))) & 0xff
f[2]=~f[2]&0xff
f[6] = ((f[6] >> 7) | (f[6] << (8-7))) & 0xff
f[3]^=f[11]
f[29]=~f[29]&0xff
f[17] -= f[5]; f[17] &= 0xff
print("Initial Flag:", f)
print("".join(chr(x) for x in f))

ispo@ispo-glaptop2:~/ctf/hxp_2022/required$ ./solve.py 
Initial Flag: [104, 120, 112, 123, 67, 97, 110, 110, 48, 116, 95, 102, 49, 110, 100, 95, 109, 48, 100, 117, 108, 101, 95, 39, 102, 108, 52, 103, 39, 125]
hxp{Cann0t_f1nd_m0dule_'fl4g'}
"""
# ----------------------------------------------------------------------------------------
