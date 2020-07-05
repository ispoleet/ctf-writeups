#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# 0CTF 2020 - Happy Tree (RE 407)
#
# NOTE: Make sure that script runs after program finishes execution of too_big_565554A0
# (tree initialization) function.
# ----------------------------------------------------------------------------------------
import sys
import struct

import idautils
import idaapi
import idc
import ida_ua
import ida_bytes


# Function descriptions.
# The (raw) copy from IDA pro looks like this:
#   emu_insn_56570670    .text 56570670 000000EA 0000000C 00000004 R . . . . . . .
#   array_index_56570760 .text 56570760 00000078 0000000C 00000004 R . . . . . . .
#   mov_565707E0	 .text 565707E0 00000061 00000008 00000004 R . . . . . . .
#   ....
#
# We can quickly convert them into a dictionariy using the following ex command:
#   16,34s/\(.*\)_\([0-9A-F]\{8}\).*$/\t\t0x\2: '\1',/g
func_descr = {
    0x56570370: 'visit children',
    0x565703C0: 'visit 1st child',
    0x565703E0: 'read symbol table',
    0x56570400: 'read symbol table',
    0x56570420: 'get 1st arg',
    0x56570430: 'visit children',
    0x56570480: 'return 0',
    0x56570490: 'loop',
    0x565704F0: 'visit 1st child',
    0x56570510: 'visit 1st child',
    0x56570530: 'return 0',
    0x56570540: 'alloc',
    0x56570570: 'make call',
    0x56570670: 'emulate instruction',
    0x56570760: 'get array index',
    0x565707E0: 'mov',
    0x56570850: 'if else',
}
 
# Symbol table.
sym_tbl = [
  'memset', 'scanf', 'puts', 'buf_1', '"Ah?"', '"%36s"', '0', '0', '"Wow!"', '"Ow!"'
]

tmp = 0
node_info = {}


# ----------------------------------------------------------------------------------------
# Create a temporary variable.
def mk_tmp(var='t'):
    global tmp
    tmp += 1
    return '%c_%d' % (var, tmp)


# ----------------------------------------------------------------------------------------
# Add indentation to a set of lines.
def pad(lines, n=4):
  return [' '*n + line for line in lines]


# ----------------------------------------------------------------------------------------
# Load a node from memory.
def process_node(addr):
    global node_info

    if addr in node_info:
        node_info[addr]['first'] = False
        return node_info[addr]

    arg0  = ida_bytes.get_dword(addr)
    arg1  = ida_bytes.get_dword(addr + 0x4)
    func  = ida_bytes.get_dword(addr + 0x8)
    n_out = ida_bytes.get_dword(addr + 0xC)
    out_ptr = ida_bytes.get_dword(addr + 0x10)
    out = [ida_bytes.get_dword(out_ptr + 4*i) for i in range(n_out)]

    info = {
        'arg0'   : arg0, 
        'arg1'   : arg1,
        'func'   : func,
        'n_out'  : n_out,
        'out'    : out,
    }

    node_info[addr] = info

    return info


# ----------------------------------------------------------------------------------------
# Disassemble a node. This function is recursive.
def disasm_node(addr, depth=0): 
    info = process_node(addr)
  
    retval = ''
    code = []

    # print('[+] %2d Visit %s %X (%-20s): (%x, %x) --> {%s}' % (    
    #        depth, 'node' if info['n_out'] else 'leaf', addr, func_descr[info['func']],
    #        info['arg0'], info['arg1'], ', '.join('%X' % c for c in info['out'])))

    # --------------------------------------------------------------------------
    # Process leaves first.
    # --------------------------------------------------------------------------
    # Load a variable from symbol table.
    if info['func'] == 0x565703E0 or info['func'] == 0x56570400:
        retval = sym_tbl[info['arg1']]

    # Allocate memory and store buffer into symbol table.
    elif info['func'] == 0x56570540:
        sym_tbl[info['arg1']] = 'buf_#%d_%d' % (info['arg1'], info['arg0'])

        code.append('%s = malloc(%d)' % (sym_tbl[info['arg1']], info['arg0']))
        retval = sym_tbl[info['arg1']]

    # Load a constant value from the node.
    elif info['func'] == 0x56570420:
        retval = '%d' % info['arg0']

    # Simply return zero.
    elif info['func'] == 0x56570480 or info['func'] == 0x56570530:
        code.append('return 0')
        retval = '0'

    # --------------------------------------------------------------------------
    # Process nodes.
    # --------------------------------------------------------------------------
    # Visit all outgoing nodes in order.
    elif info['func'] == 0x56570370 or info['func'] == 0x56570430:
        for out in info['out']:
            sub_code, retval = disasm_node(out, depth + 1)
            code += sub_code
        # Use the retval from the last child.

    # Visit first child only and return 0.
    elif info['func'] == 0x565703C0:
        code, _ = disasm_node(info['out'][0], depth + 1)
        retval = '0'

    # Visit first child only and propagate its return value
    elif info['func'] == 0x565704F0 or info['func'] == 0x56570510:
        code, retval = disasm_node(info['out'][0], depth + 1)

    # Get array index.
    elif info['func'] == 0x56570760:
        sub_code1, retval1 = disasm_node(info['out'][0], depth + 1)
        sub_code2, retval2 = disasm_node(info['out'][1], depth + 1)

        code += sub_code1 + sub_code2

        retval  = '(char)' if info['arg0'] == 1 else '(int)'
        retval += '%s[%s] ' % (retval1, retval2)

    # Move.
    elif info['func'] == 0x565707E0:
        code, retval1 = disasm_node(info['out'][0], depth + 1)        

        if info['arg0'] == 1:
            retval += '*(char*)' if info['arg1'] == 1 else '*(int*)'
            retval += '%s ' % (retval1)
        else:            
            retval  = '%s' % (retval1)

    # Make a library call.
    elif info['func'] == 0x56570570:
        _, retval1 = disasm_node(info['out'][0], depth + 1)
        argz = []
   
        for arg in info['out'][1:]:
            sub_code, retval = disasm_node(arg, depth + 1)
            
            code += sub_code 
            argz.append(retval)

        code.append('call %s(%s)' % (retval1, ', '.join(argz)))

    # Loop.
    elif info['func'] == 0x56570490:
        sub_code0, retval0 = disasm_node(info['out'][0], depth + 1)
        sub_code1, _ = disasm_node(info['out'][4], depth + 1)
        sub_code2, _ = disasm_node(info['out'][3], depth + 1)
        sub_code3, retval3 = disasm_node(info['out'][2], depth + 1)

        code += sub_code0
        code += sub_code3
        code.append('while (%s) {' % retval3)
        code += pad(sub_code1)
        code += pad(sub_code2)
        code += pad(sub_code3)
        code.append('}')

    # If else statement.
    elif info['func'] == 0x56570850:
        sub_code0, retval1 = disasm_node(info['out'][0], depth + 1)
        sub_code1, _ = disasm_node(info['out'][1], depth + 1)
        sub_code2, _ = disasm_node(info['out'][2], depth + 1)

        code += sub_code0
        code.append('if (%s) {' % retval1)
        code += pad(sub_code1)
        code.append('} else {')
        code += pad(sub_code2)
        code.append('}')

    # Emulate a single instruction.
    elif info['func'] == 0x56570670:
        sub_code0, retval1 = disasm_node(info['out'][0], depth + 1)
        sub_code1, retval2 = disasm_node(info['out'][1], depth + 1)

        insn = {
            0: '%s == %s',
            1: '%s << %s',
            2: '%s >> %s',
            3: '%s ^ %s',
            4: '%s + %s',
            5: '%s - %s',
            6: '%s * %s',
            7: '%s && %s',
            8: '%s < %s',
            9: '*%s = %s'
        }[info['arg0']] % (retval1, retval2)

        if info['arg0'] == 9:
            code += sub_code0
            code += sub_code1
            code.append(insn)
            retval = retval1
        else:        
            retval = mk_tmp()
            code += sub_code0
            code += sub_code1
            code.append('%s = %s' % (retval, insn))
    else:
        raise Exception('Unknown node!')

    return code, retval


# ----------------------------------------------------------------------------------------
# Create graphviz file of the tree.
def make_dot(nodes, adj_matrix):
  with open('tree.dot', 'w') as fp:
    fp.write('digraph G {\n')

    # Write nodes.
    for idx, node in nodes.items():
      fp.write('\t"%X" [shape=box label="%s" fillcolor=greenyellow style=filled];\n' % (
               idx, node.replace('"', '\\"')))

    fp.write('\n\n')

    # Write edges.
    for node, children in adj_matrix.items():
      for child in children:
          fp.write('\t"%X" -> "%X"\n' % (node, child))

    fp.write('\n\n')
    fp.write('}\n')


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
  print('[+] Happy Tree crack Disassembler.')

  start_node = 0x5657C1D0   # first_node_5657C1D0

  code, _ = disasm_node(start_node)
  for line in code:
      print(line)

  print('[+] Visualizing tree (back edges not included)')
  queue = [(start_node, 0)]
  visited = set([start_node])

  adj_matrix = {}
  nodes = {}

  while queue:
    curr, depth = queue.pop()

    arg0    = ida_bytes.get_dword(curr)
    arg1    = ida_bytes.get_dword(curr + 0x4)
    func    = ida_bytes.get_dword(curr + 0x8)
    n_out   = ida_bytes.get_dword(curr + 0xC)
    out_ptr = ida_bytes.get_dword(curr + 0x10)
    out     = [ida_bytes.get_dword(out_ptr + 4*i) for i in range(n_out)]
 
    print('[+] %2d Visit %s %X (%-20s) --> {%s}' % (    
        depth, 'node' if n_out else 'leaf', curr, func_descr[func], ', '.join('%X' % o for o in out)))


    # Dipatch tree function
    if func in [0x56570370, 0x565703C0, 0x56570430, 0x565704F0, 0x56570510]:
       mnem = ' '
    elif func in [0x565703E0, 0x56570400]:
       mnem = sym_tbl[arg1]
    elif func == 0x56570420:
      mnem = '%d' % arg0
    elif func in [0x56570480, 0x56570530]:
      mnem = 'return 0'
    elif func == 0x56570490:
      mnem = 'loop'
    elif func == 0x56570540:
      mnem = 'buf_#%d = malloc(%d)' % (arg1, arg0)
    elif func == 0x56570570:
      mnem = 'call'
    elif func == 0x56570670: 
      mnem = {0: '==', 1: '<<', 2: '>>', 3: '^', 4: '+', 5: '-', 6: '*', 7: '&&',
              8: '<', 9: '='}[arg0]
    elif func == 0x56570760:
      mnem = 'array %s' % ('BYTE' if arg0 == 1 else 'DWORD')
    elif func == 0x565707E0:
      mnem = 'mov'
    elif func == 0x56570850:
      mnem = 'if else'
 
    nodes[curr] = mnem
    for child in out:
      if child not in visited:
        visited.add(child)
        queue.insert(0, (child, depth + 1))

        adj_matrix.setdefault(curr, set()).add(child)

  make_dot(nodes, adj_matrix) 

# ----------------------------------------------------------------------------------------

