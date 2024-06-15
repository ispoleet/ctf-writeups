#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# DefCon Quals 2021 - Rick (RE 200)
# ----------------------------------------------------------------------------------------
import socket
import struct
import sys
import networkx
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import graphviz_layout
 

# ----------------------------------------------------------------------------------------
def recv_until(string):
    """Keep receiving data from `sock`, until you encounter a given `string`."""
    recv = b''
    while string not in recv:
        recv += sock.recv(16384)
    return recv


# ----------------------------------------------------------------------------------------
def array_to_tree(arr):
    """Convert a pre-order tree array onto a networkx tree."""
    tree = networkx.DiGraph()
    array_to_tree_recursive(arr, tree, parent=None, i=0, depth=0)
    return tree


def array_to_tree_recursive(arr, tree, parent, i=0, depth=0):
    """Convert a pre-order tree array onto a networkx tree (recursively)."""
    operation  = arr[i + 0] % 10
    n_children = arr[i + 1] & 0xFF if arr[i] % 10 else -1

    # Add node attributes (operation and number of children).
    tree.add_node(f'{arr[i]:08X}', op=operation, n=n_children)

    if parent:
        tree.add_edge(parent, f'{arr[i]:08X}')  # Link to the parent (if exists).

    if arr[i] % 10 == 0:
        return 1  # Leaf node.

    eat = 2  # We already consumed 2 elements.
    for j in range(n_children):
        eat += array_to_tree_recursive(arr, tree, f'{arr[i]:08X}', i + eat, depth + 1)

    return eat
    

# ----------------------------------------------------------------------------------------
def gen_correct_value(op, expected_result, idx=0):
    """Generate a correct value for a subtree given the `op` and `expected_result`."""
    # There can be many solutions. Just generate a valid one.
    return {
        0: None,
        # NOT
        #   If expected result is 1, then return 0. Otherwise return 1
        #   (NOTE: NOT nodes always have 1 child).
        1: 0 if expected_result == 1 else 1,
        # AND
        #   If expected result is 1, then make everything 1. Otherwise make everything 0.
        2: 1 if expected_result == 1 else 0,
        # OR
        #   If expected result is 1, then make everything 1. Otherwise make everything 0.
        3: 1 if expected_result == 1 else 0,
        # XOR
        #   If expected result is 1 set the first to 1 and everything else to 0. That
        #   way the XOR will always be 1 no matter how many nodes we have.
        #   If expected result is 0, simply set everything to 0.
        4: (1 if idx == 0 else 0) if expected_result == 1 else 0,
        # NAND
        #   If expected result is 1, then make everything 0. Otherwise make everything 1.
        5: 0 if expected_result == 1 else 1,
        # NOR
        #   If expected result is 1, then make everything 0. Otherwise make everything 1.
        6: 0 if expected_result == 1 else 1,
        # Alternate 1 and 0
        #   If expected result is 1, then set to 1 for even indices and 0 for odd.
        #   Otherwise, set everything to 0.
        7: (1 if idx % 2 == 0 else 0) if expected_result == 1 else 0,
        # First and last are 0
        #   If expected result is 1, then set everything to 0.
        #   Otherwise set everything to 1 (we keep things simple).
        8: 0 if expected_result == 1 else 1,
        # First and last are 1
        #   If expected result is 1, then set everything to 1.
        #   Otherwise set everything to 0.
        9: 1 if expected_result == 1 else 0
    }[op]


# ----------------------------------------------------------------------------------------
def find_tree_sol(tree, curr_node, expected_result=1, depth=1, dbg=False):
    """Find a leaf assignment that makes a subtree return `expected_result`."""
    operation  = networkx.get_node_attributes(tree, 'op')[curr_node]
    n_children = networkx.get_node_attributes(tree, 'n' )[curr_node]
    ops = ['None', 'NOT', 'AND', 'OR', 'XOR', 'NAND', 'NOR', 'ALT', 'FL0', 'FL1']

    if dbg:
        print('{0}Curr node: {1}, op:{2}, #{3}, exp:{4}'.format(
                ' '*depth*4, curr_node, ops[operation], n_children, expected_result))

    sol = ''
    for i, n in enumerate(tree[curr_node]):
        nxt_op = networkx.get_node_attributes(tree, 'op')[n]

        if dbg:
            print('{0}  {1}: i:{2} Next:{3}'.format(' '*depth*4, ops[nxt_op], i, nxt_op))
        
        val = gen_correct_value(operation, expected_result, i)

        if nxt_op == 0:
            # We have a leaf. Make correct value a string.
            sol += f'{val}'          
        else:
            # Recursively make the subtree return the expected value.
            sol += find_tree_sol(tree, n, val, depth + 1, dbg)  

    return sol


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Rick crack started.')

    # Sample arrays for testing.
    arr1 = [
        0x99C9A710, 0x44E2AC02, 0xF00C81D9, 0xC1217502, 0x2C7C9F44, 0xFD499FE6,
        0xB09214AB, 0xF0608702, 0x34C8AE04, 0xA5D62A18
    ]

    arr2 = [
        0x78CFFA13, 0xE56C1B01, 0x90052A8C, 0x14291803, 0x0CFCCBC6, 0xE3A85DD4,
        0xEDA2BE38
    ]

    arr3 = [
        0x9FFE254A, 0xECA5F004, 0x5934A94B, 0x89B46302, 0x39038475, 0x77E6AE02,
        0xE2DADEFE, 0xEC47C0E2, 0x1E89B1C2, 0x4A485203, 0xCAF1A156, 0x38A85588,
        0x8D4DA3F4, 0xAD4BF835, 0x7E8F2504, 0x53435D7E, 0x88134703, 0x8DC75492,
        0x49C37140, 0xE1901050, 0xD77D838A, 0x9DACB003, 0x0ED56B06, 0x20C21DB4,
        0x7AC5CDF6, 0xE4B0CD23, 0x01710304, 0xAC6E2470, 0xAC009AC2, 0x5104E182,
        0xD0E6A034, 0x84CE1C95, 0xEDA59C04, 0x2D2543BA, 0x907A267E, 0x23969948,
        0xC395C9FA, 0xEA81F063, 0x91AE3D04, 0x9179B2B7, 0x3BADAE03, 0xB758E852,
        0x061EB576, 0x8500FA16, 0x18A62F70, 0x7B8EF403, 0xCFD05EBA, 0x4D67EAEC,
        0x6FC91426, 0xF32D3E1F, 0x536D0101, 0x8B3AA350, 0xA3D47BE9, 0xACD07B01, 
        0x989FD006, 0x03E9719F, 0x6D121704, 0x171AAFA5, 0x185DCB04, 0xF8CF529E,
        0xF01FD0BA, 0x9B58E30A, 0x33FA31FA, 0x230D2AA2, 0xE9697102, 0xD85284AA,
        0xEC698042, 0x1ACCD8DB, 0x70A59704, 0xC8E88C12, 0x570C6654, 0x8A034226,
        0x5AC3208A, 0xE5B8DFDB, 0x0896FE04, 0x66098F1A, 0xCE19E9B0, 0xF9A30436, 
        0x32FE1FA0
    ]    

    tree = array_to_tree(arr1)
    # Run as:  dot -Tpng test.dot >test.png
    networkx.nx_agraph.write_dot(tree, 'test.dot')

    for node in networkx.dfs_tree(tree).nodes():
        op = networkx.get_node_attributes(tree, 'op')[node]
        n  = networkx.get_node_attributes(tree, 'n')[node]
        print(f'{node}, op:{op}, #{n}') 

    # Find the root node.
    root = [n for (n, d) in tree.in_degree() if d == 0]
    assert len(root) == 1
    print(f'[+] Root node: {root}')

    sol = find_tree_sol(tree, root[0], dbg=True)
    print('[+] Tree solution: {sol}')

    print('[+] Starting real work .....')
    print('[!] WARNING: YOU MAY HAVE TO RUN ME MULTIPLE TIMES TO GET THE FLAG!')
    
    #sock = socket.create_connection(('192.168.9.2', 4343)) # local
    sock = socket.create_connection(('rick.challenges.ooo', 4343)) # remote

    assert sock.recv(4) == b'RICK'

    dwords = sock.recv(4)
    for rnd in range(1, 128):
        print(f'[+] ============================== Round #{rnd} ==============================')
        buflen = struct.unpack('<L', dwords)[0]

        #buf    = sock.recv(buflen * 4)
        buf = b''  
        while len(buf) < buflen*4:  # A single recv, may not retrieve everything.
          buf += sock.recv(4096)
        
        arr = [struct.unpack('<L', buf[4*z:4*z+4])[0] for z in range(buflen)]

        tree = array_to_tree(arr)

        root = [n for (n, d) in tree.in_degree() if d == 0]
        assert len(root) == 1
        print(f'[+] Array size: {len(arr)}. Tree nodes: {len(tree.nodes())}. Root node: {root}')

        if len(tree.nodes()) > 7000:
            print('[!] WARNING. Tree is tooooooo big :\\')
            print('[!] It will probably timeout on server. Press Ctl+C and retry.')

        # TODO: This is too slow for tree w/ >7000 nodes.
        # Need to optimize it, or run it multiple times until you hit a relatively
        # small tree.
        sol = find_tree_sol(tree, root[0], dbg=rnd < 15)
        print(f'[+] Valid solution (len: #{len(sol)}): {sol}')

        # Send solution back to the server.
        sol = sol.encode('utf-8')
        enc_sol = bytes([a ^ b for a, b in zip(sol, b'RICK'*len(sol))])
        sock.send(enc_sol + b"\n")

        # Check response to verify if solution was correct.
        dwords = sock.recv(4)
        if dwords in [b'KO', b'KOKO']:
            raise Exception(f'[+] Incorrect solution (or timeout) :(')
        elif dwords == b'RICK':
            print(f'[+] FLAG FOUND!')
            flaglen = sock.recv(4)
            flaglen = struct.unpack('<L', flaglen)[0]
            print(f'[+] Flag len: {flaglen}')
            flag = sock.recv(flaglen)
            flag = bytes([a ^ b for a, b in zip(flag, b'RICK'*flaglen)])
            print(f'[+] Flag: {flag}')
            break

    sock.close()

# ----------------------------------------------------------------------------------------
r"""
$ time ./rick_crack.py 
[+] Rick crack started.
99C9A710, op:2, #2
F00C81D9, op:3, #2
2C7C9F44, op:0, #-1
FD499FE6, op:0, #-1
B09214AB, op:3, #2
34C8AE04, op:0, #-1
A5D62A18, op:0, #-1
[+] Root node: ['99C9A710']
    Curr node: 99C9A710, op:AND, #2, exp:1
      OR: i:0 Next:3
        Curr node: F00C81D9, op:OR, #2, exp:1
          None: i:0 Next:0
          None: i:1 Next:0
      OR: i:1 Next:3
        Curr node: B09214AB, op:OR, #2, exp:1
          None: i:0 Next:0
          None: i:1 Next:0
[+] Tree solution: {sol}
[+] Starting real work .....
[!] WARNING: YOU MAY HAVE TO RUN ME MULTIPLE TIMES TO GET THE FLAG!
[+] ============================== Round #1 ==============================
[+] Array size: 3. Tree nodes: 2. Root node: ['25925DCE']
    Curr node: 25925DCE, op:AND, #1, exp:1
      None: i:0 Next:0
[+] Valid solution (len: #1): 1
[+] ============================== Round #2 ==============================
[+] Array size: 4. Tree nodes: 3. Root node: ['BCD36BD9']
    Curr node: BCD36BD9, op:OR, #2, exp:1
      None: i:0 Next:0
      None: i:1 Next:0
[+] Valid solution (len: #2): 11
[+] ============================== Round #3 ==============================
[+] Array size: 4. Tree nodes: 3. Root node: ['586CA862']
    Curr node: 586CA862, op:AND, #2, exp:1
      None: i:0 Next:0
      None: i:1 Next:0
[+] Valid solution (len: #2): 11
[+] ============================== Round #4 ==============================
[+] Array size: 6. Tree nodes: 5. Root node: ['627B09F3']
    Curr node: 627B09F3, op:OR, #4, exp:1
      None: i:0 Next:0
      None: i:1 Next:0
      None: i:2 Next:0
      None: i:3 Next:0
[+] Valid solution (len: #4): 1111
[+] ============================== Round #5 ==============================
[+] Array size: 6. Tree nodes: 5. Root node: ['BDF48CC2']
    Curr node: BDF48CC2, op:AND, #4, exp:1
      None: i:0 Next:0
      None: i:1 Next:0
      None: i:2 Next:0
      None: i:3 Next:0
[+] Valid solution (len: #4): 1111
[+] ============================== Round #6 ==============================
[+] Array size: 8. Tree nodes: 5. Root node: ['85F75E13']
    Curr node: 85F75E13, op:OR, #2, exp:1
      OR: i:0 Next:3
        Curr node: 40C8CB97, op:OR, #1, exp:1
          None: i:0 Next:0
      OR: i:1 Next:3
        Curr node: 9E47176F, op:OR, #1, exp:1
          None: i:0 Next:0
[+] Valid solution (len: #2): 11
[+] ============================== Round #7 ==============================
[+] Array size: 8. Tree nodes: 5. Root node: ['F78694EE']
    Curr node: F78694EE, op:AND, #2, exp:1
      AND: i:0 Next:2
        Curr node: E228C9A0, op:AND, #1, exp:1
          None: i:0 Next:0
      OR: i:1 Next:3
        Curr node: C268B9D7, op:OR, #1, exp:1
          None: i:0 Next:0
[+] Valid solution (len: #2): 11
[+] ============================== Round #8 ==============================
[+] Array size: 8. Tree nodes: 5. Root node: ['35823756']
    Curr node: 35823756, op:XOR, #2, exp:1
      NOT: i:0 Next:1
        Curr node: 0699950D, op:NOT, #1, exp:1
          None: i:0 Next:0
      NOT: i:1 Next:1
        Curr node: C7C9AE1B, op:NOT, #1, exp:0
          None: i:0 Next:0
[+] Valid solution (len: #2): 01
[+] ============================== Round #9 ==============================
[+] Array size: 10. Tree nodes: 7. Root node: ['BDCADA94']
    Curr node: BDCADA94, op:AND, #2, exp:1
      OR: i:0 Next:3
        Curr node: 0F2B6DF1, op:OR, #2, exp:1
          None: i:0 Next:0
          None: i:1 Next:0
      OR: i:1 Next:3
        Curr node: 0AF00779, op:OR, #2, exp:1
          None: i:0 Next:0
          None: i:1 Next:0
[+] Valid solution (len: #4): 1111
[+] ============================== Round #10 ==============================
[+] Array size: 10. Tree nodes: 7. Root node: ['77CEF264']
    Curr node: 77CEF264, op:AND, #2, exp:1
      XOR: i:0 Next:4
        Curr node: DCFCFE4E, op:XOR, #2, exp:1
          None: i:0 Next:0
          None: i:1 Next:0
      XOR: i:1 Next:4
        Curr node: F1CF9B38, op:XOR, #2, exp:1
          None: i:0 Next:0
          None: i:1 Next:0
[+] Valid solution (len: #4): 1010
[+] ============================== Round #11 ==============================
[+] Array size: 14. Tree nodes: 11. Root node: ['4F78950E']
    Curr node: 4F78950E, op:AND, #2, exp:1
      FL0: i:0 Next:8
        Curr node: 46EC796A, op:FL0, #4, exp:1
          None: i:0 Next:0
          None: i:1 Next:0
          None: i:2 Next:0
          None: i:3 Next:0
      ALT: i:1 Next:7
        Curr node: C5AAD183, op:ALT, #4, exp:1
          None: i:0 Next:0
          None: i:1 Next:0
          None: i:2 Next:0
          None: i:3 Next:0
[+] Valid solution (len: #8): 00001010
[+] ============================== Round #12 ==============================
[+] Array size: 36. Tree nodes: 27. Root node: ['8A41B29F']
    Curr node: 8A41B29F, op:NAND, #2, exp:1
      NAND: i:0 Next:5
        Curr node: 15F7DF95, op:NAND, #4, exp:0
          OR: i:0 Next:3
            Curr node: E7B0E061, op:OR, #2, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
          NAND: i:1 Next:5
            Curr node: 265151C3, op:NAND, #2, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
          NAND: i:2 Next:5
            Curr node: D0917A91, op:NAND, #4, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
              None: i:3 Next:0
          NOR: i:3 Next:6
            Curr node: 6DDAD86C, op:NOR, #2, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
      NAND: i:1 Next:5
        Curr node: E7F5FFA9, op:NAND, #2, exp:0
          NAND: i:0 Next:5
            Curr node: 1C73A0CF, op:NAND, #4, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
              None: i:3 Next:0
          FL1: i:1 Next:9
            Curr node: 2FD7D8B5, op:FL1, #4, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
              None: i:3 Next:0
[+] Valid solution (len: #18): 110000000000001111
[+] ============================== Round #13 ==============================
[+] Array size: 69. Tree nodes: 51. Root node: ['75AAF1F8']
    Curr node: 75AAF1F8, op:NOR, #4, exp:1
      AND: i:0 Next:2
        Curr node: 690BCD38, op:AND, #3, exp:0
          AND: i:0 Next:2
            Curr node: 559B2AF0, op:AND, #3, exp:0
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
          NOR: i:1 Next:6
            Curr node: AD1A569C, op:NOR, #3, exp:0
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
          NAND: i:2 Next:5
            Curr node: DFA9BB6F, op:NAND, #4, exp:0
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
              None: i:3 Next:0
      FL0: i:1 Next:8
        Curr node: A75CEEB0, op:FL0, #2, exp:0
          NOR: i:0 Next:6
            Curr node: 720821A6, op:NOR, #2, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
          XOR: i:1 Next:4
            Curr node: 77CAA3FA, op:XOR, #4, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
              None: i:3 Next:0
      NOR: i:2 Next:6
        Curr node: EC0DB31C, op:NOR, #4, exp:0
          NOT: i:0 Next:1
            Curr node: 6E276A8D, op:NOT, #1, exp:1
              None: i:0 Next:0
          NOT: i:1 Next:1
            Curr node: 6690D633, op:NOT, #1, exp:1
              None: i:0 Next:0
          OR: i:2 Next:3
            Curr node: 553F3A4D, op:OR, #2, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
          FL1: i:3 Next:9
            Curr node: 58122E61, op:FL1, #2, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
      NAND: i:3 Next:5
        Curr node: 47DC8015, op:NAND, #4, exp:0
          NAND: i:0 Next:5
            Curr node: FB6003A5, op:NAND, #2, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
          AND: i:1 Next:2
            Curr node: F63CDE5E, op:AND, #4, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
              None: i:3 Next:0
          FL1: i:2 Next:9
            Curr node: 244EAF23, op:FL1, #3, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
          AND: i:3 Next:2
            Curr node: EE7ED5D2, op:AND, #2, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
[+] Valid solution (len: #33): 000111111100100000111100111111111
[+] ============================== Round #14 ==============================
[+] Array size: 63. Tree nodes: 47. Root node: ['250868AC']
    Curr node: 250868AC, op:NOR, #4, exp:1
      FL0: i:0 Next:8
        Curr node: F1E822D8, op:FL0, #2, exp:0
          FL1: i:0 Next:9
            Curr node: 90C3F3BB, op:FL1, #3, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
          OR: i:1 Next:3
            Curr node: 6673CC75, op:OR, #2, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
      NOT: i:1 Next:1
        Curr node: DCE57203, op:NOT, #1, exp:0
          ALT: i:0 Next:7
            Curr node: DE6410E5, op:ALT, #4, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
              None: i:3 Next:0
      FL0: i:2 Next:8
        Curr node: 4C7C0B20, op:FL0, #4, exp:0
          NOT: i:0 Next:1
            Curr node: A9F6FBE1, op:NOT, #1, exp:1
              None: i:0 Next:0
          NOR: i:1 Next:6
            Curr node: 4C7E80A6, op:NOR, #4, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
              None: i:3 Next:0
          AND: i:2 Next:2
            Curr node: 3CCAD624, op:AND, #2, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
          OR: i:3 Next:3
            Curr node: 5ECDB689, op:OR, #2, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
      FL0: i:3 Next:8
        Curr node: 5DA5B3F6, op:FL0, #4, exp:0
          NOT: i:0 Next:1
            Curr node: 205C10C9, op:NOT, #1, exp:1
              None: i:0 Next:0
          AND: i:1 Next:2
            Curr node: 7EC194E6, op:AND, #4, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
              None: i:3 Next:0
          NAND: i:2 Next:5
            Curr node: B641F283, op:NAND, #4, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
              None: i:3 Next:0
          OR: i:3 Next:3
            Curr node: 73DFE6C3, op:OR, #4, exp:1
              None: i:0 Next:0
              None: i:1 Next:0
              None: i:2 Next:0
              None: i:3 Next:0
[+] Valid solution (len: #31): 1111110100000011110111100001111
[+] ============================== Round #15 ==============================
[+] Array size: 24. Tree nodes: 17. Root node: ['4F244E1F']
[+] Valid solution (len: #10): 1111100011
[+] ============================== Round #16 ==============================
[+] Array size: 61. Tree nodes: 45. Root node: ['623C9510']
[+] Valid solution (len: #29): 11000111111111000011111110000
[+] ============================== Round #17 ==============================
[+] Array size: 28. Tree nodes: 20. Root node: ['7399FA1E']
[+] Valid solution (len: #12): 001111110010
[+] ============================== Round #18 ==============================
[+] Array size: 50. Tree nodes: 38. Root node: ['7043E05E']
[+] Valid solution (len: #26): 11111100000000000001110000
[+] ============================== Round #19 ==============================
[+] Array size: 30. Tree nodes: 22. Root node: ['EF13ECB7']
[+] Valid solution (len: #14): 11110001111111
[+] ============================== Round #20 ==============================
[+] Array size: 43. Tree nodes: 31. Root node: ['49DDC8A3']
[+] Valid solution (len: #19): 0000011101001011000
[+] ============================== Round #21 ==============================
[+] Array size: 80. Tree nodes: 57. Root node: ['E0C11B6C']
[+] Valid solution (len: #34): 1111110011100000000011101100011100
[+] ============================== Round #22 ==============================
[+] Array size: 39. Tree nodes: 28. Root node: ['647580EC']
[+] Valid solution (len: #17): 00010001100000000
[+] ============================== Round #23 ==============================
[+] Array size: 29. Tree nodes: 21. Root node: ['A6CEF520']
[+] Valid solution (len: #13): 1100000000000
[+] ============================== Round #24 ==============================
[+] Array size: 69. Tree nodes: 49. Root node: ['B8652D62']
[+] Valid solution (len: #29): 00000110001100000001110001000
[+] ============================== Round #25 ==============================
[+] Array size: 33. Tree nodes: 23. Root node: ['103277B5']
[+] Valid solution (len: #13): 1011110110011
[+] ============================== Round #26 ==============================
[+] Array size: 46. Tree nodes: 30. Root node: ['7DCA4AE9']
[+] Valid solution (len: #14): 01110000001110
[+] ============================== Round #27 ==============================
[+] Array size: 37. Tree nodes: 26. Root node: ['572EB4F0']
[+] Valid solution (len: #15): 000001110111100
[+] ============================== Round #28 ==============================
[+] Array size: 36. Tree nodes: 24. Root node: ['75CDE605']
[+] Valid solution (len: #12): 110000000000
[+] ============================== Round #29 ==============================
[+] Array size: 40. Tree nodes: 28. Root node: ['0F2BFE39']
[+] Valid solution (len: #16): 0000011111110000
[+] ============================== Round #30 ==============================
[+] Array size: 113. Tree nodes: 82. Root node: ['F1D487BA']
[+] Valid solution (len: #51): 000000100000001010111111000010111100111110000000000
[+] ============================== Round #31 ==============================
[+] Array size: 434. Tree nodes: 323. Root node: ['E3BAAB34']
[+] Valid solution (len: #212): 00011000000010100011111100000001110010000000000000100000001000101011100000000000000000111111111110000111100000000000000001111100111111111111000111101011111111111000000111110101010000111110001110001111110000111111
[+] ============================== Round #32 ==============================
[+] Array size: 174. Tree nodes: 128. Root node: ['54BB44D6']
[+] Valid solution (len: #82): 1100001111111100001111100000000001000011000010010000000000011110011111111111111111
[+] ============================== Round #33 ==============================
[+] Array size: 288. Tree nodes: 212. Root node: ['09F8CC24']
[+] Valid solution (len: #136): 0000011111111000000000111100111100111110000111111111111111111000100000001111001011110000000001111000011111111111111111001111000011100001
[+] ============================== Round #34 ==============================
[+] Array size: 31. Tree nodes: 22. Root node: ['94E86267']
[+] Valid solution (len: #13): 0011100011111
[+] ============================== Round #35 ==============================
[+] Array size: 21. Tree nodes: 15. Root node: ['021BB885']
[+] Valid solution (len: #9): 110001000

[..... TRUNCATED FOR BREVITY .....]

[+] ============================== Round #95 ==============================
[+] Array size: 1963. Tree nodes: 1497. Root node: ['C680C36C']
[+] Valid solution (len: #1031): 00011100000001111000111000111111110001000111111110001001110001111010000011110001000000000011111111111100000000111111111111111000000111100010101000111110100000000000000000000000011100000000111100011100000001111000001000000000001000111111110001111111100000000000000000111000000011111100000011110000000000111100000000000000000001010010000000000000000001111111111110001111000000000011000111111111110000001111000011100011111110001111000000000001110111101000011100000000000000000001111111111000000011111111100000001110000111000011111101010111000000001111111111000111111100000011110001110001111000011100000001000000111110000001111000000111100000000000111000000010001010000000000000000001111000010000111111100000011110000111111111111111000011111100000001110000000111100000001111111111111000000000000000000000011110000111000010001010100000000111111111111111000111000000000001110000000000000011111110001111110000000100000000001111000000000000001111000000000011110001111101011111111111111111000000010000000000000000111000000000011110001111000
[+] ============================== Round #96 ==============================
[+] Array size: 242. Tree nodes: 182. Root node: ['82EDE717']
[+] Valid solution (len: #122): 11111110000100001111111111111111100000000111000101010001111000000111100001111000011111111111100000000000010011111110000000
[+] ============================== Round #97 ==============================
[+] Array size: 2670. Tree nodes: 2044. Root node: ['3BF0B17B']
[+] Valid solution (len: #1418): 11100000000000111110000100010000000000000111111100000000000000111101000000000000111111000000001110000000000000111111100000000000000000000111100000000111111110001010000000001111110000111100000000000000000000001000011100000000000000000011111111111111111110000000000000000000100000000000000111110101111101100000001000000010001111010100000000000100000000000000000001111111110000000000011111111111111101001110000111111101000000000111100000001000000000001110111100010000001111111111111100000001010001000101111100010111110000000000000011111111000100000000000000111100001010111111110000000000000001111010000111100000000000011111110000000000011100000000111000111000010101111111010100001111111101100011111110000001111101000000001111111100001110000000011110001111111100011100000011100000000001110000001110000111111111111111000010000000011110000000111111100000000001111111101111000000000001111111100001111100000000000000100011110000001110001000000000001001000111111110000100001111000010001111000000111000011100000000011100010111110000111111110000000000000100000101010100000000111000000100111111111100000011110000011100000000001110001111111111111110001111000000000000001010100000011101111010000111000100111111111000111000010000111110001110000000000111111111111100011111100000000000111111000000000001110000011100000011100000001110001010111111111010100111000000000001010000111110111110000000111000000000011111111110100000001111000111
[+] ============================== Round #98 ==============================
[+] Array size: 2446. Tree nodes: 1868. Root node: ['C03AE495']
[+] Valid solution (len: #1290): 111000011111110000101000000011110000000111111111100000000011111111000111100001111000000011100000000001111100000000000000011100000000011110000000100011100011110000000000000000011111110000000111111100000000000000111000100000000111000000111111111000000111000100001110001111111111000000011111110000000111111111110000000000000011110000000000000111000000001111111100011000000000011110000111100000001110001111111111111100000000111111111100000000000011111111000111111111111111111100000000111100011111011111011111111111000011111000000000000111110000000100000000000001111000000000000111111101011101001110000000000010001000001011111111011100010101010000111000000111000000000000000000000011110000000000111111111111111000010110000000011111110000000000011110100000001111111111000011110000001011111111111100000001111011110000000000000011100000001010000010001010001111110000000000000000000000000011111111000100010100000000100011110111000111000011110000000000011111110001111101100001110111100010000000010011110100011111111111000011111111101111111111110000001111100100101000100000001111111000000000000000000000000000000001111000011111111111110100000000000000000011111111111111111111100000000000001111111111110000100010111110000000011111111000000000000000000000001110000000000000000001111111000111111111111010
[+] ============================== Round #99 ==============================
[+] Array size: 2059. Tree nodes: 1563. Root node: ['AAA61222']
[+] Valid solution (len: #1067): 00010000000111000100000001110001111000100011111100001000011111000000000000000001111000001111111111000000001111110000000000011111101111100001000000000000000001111100000011111111000010000001000000000000000110000010111111111110000000111000111111111111000011110000001110000000000101000000000000111111100011110011111111111000111111111111100000000001111000000000000001111000011100000000000111000000001111000111111110001111000111111111110111110000111100000000111000000011111100001110000000000000000011111111111100011100010100000011110001111100000000000101011100000011110001101001011111111110000001111111111111111111000001110000111111000000000010000001111111101111111000000111100000001110001110000000000000000000001110001110000111000111111111100000000100000000111111100000001111111100000001111111000011110000111111111110010000111100000000001000000000010000001110000010000011111000010001111000100010001000000111000000000000000000111111100000000001111110000000000011111110000011000000011111111000000000111100011111111100010111111111000111100010000000000111110001111101100000101
[+] ============================== Round #100 ==============================
[+] Array size: 3366. Tree nodes: 2645. Root node: ['FE7A7189']
[+] Valid solution (len: #1924): 0000000000000000000001111111111110000111100000000000011111111111100001111000000001111100000000000000000000100001111111100000000111100001111111100001000000011110000011111111100000000100011111111000010101010000011110111100001111000000000000000000001111101010000000000000001111100000000000000000000000011111100001111000010000000001111000010100000111111110000000011111000000011111111000000001111111110000111111110000111100000000111100000000111100000000000000001000111110001111000010101000101010101111000000001111111111111111000010001111000000000000111111111000000001111000000001111111100001111000010001010111100001111000000000000111110000111100000000000010100011110000000000001111111110000000000000000111000000000111111111010000000001111111111111111111100001000111110001000111111110000000010000111111111101000000000000011110000000011111111000011111111000001111111100001111111100000000111100000000000000001111110001111100010101000000001111011111000000000000000001111111111111111100001000010000000000000000000111111110000100011111010000000000000000011111111111111111000010000000011111111111111010111100001000111111110000000011111111000000001111000010100000000000000000111100001111010100100011111111000011000000001000000000000000000001111111110000000000000000111100000000100000000000011110000100001111111111000011111010000010101111000000001000000011110000111111111111000000000000000000000000000000000000000000000000000011111111111110000111111110000100011111111111110000111100001111000011110000111111110000000000001000000001111111110000111100000000111110000000000001111000011110000101010001111111101111100001111100000001000000000001111000010101111111111111000000000000111110000000011110000000011110000000000000000111111000011110000111111110000000001010100000000111100001111111111111111111100001111111100000000011000011111111000011111000011110000000010000110100000111100000000000011111111100000000000010100000000000000000000011110000
[+] FLAG FOUND!
[+] Flag len: 69
[+] Flag: b'OOO{never_gooonna_give_yooou_up_but_Im_gooonna_give_yooou_this_flag}\n'

real  0m59.281s
user  0m33.770s
sys 0m1.514s
"""
# ----------------------------------------------------------------------------------------

