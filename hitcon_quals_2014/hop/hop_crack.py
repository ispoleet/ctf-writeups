#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# HITCON CTF 2014 - hop (RE 350)
# --------------------------------------------------------------------------------------------------
import string
import networkx


flag_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}!@$_ \x00'
# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    Message("HITCON CTF 2014 - hop crack started.\n")


    # -------------------------------------------------------------------------
    # Build the hop graph
    # -------------------------------------------------------------------------
    G = networkx.DiGraph()

    visited = set()                                 # visited nodes
    stack   = [0x44F491]                            # entry point on the stack

    while stack:                                    # do an old-school DFS
        curr = stack.pop()

        if curr == 0x4015B9:                        # halt on success node
            Message("Flag node found!\n")
            continue

        elif curr == 0x04015BF:                     # halt on failure node
            continue


        if curr in visited:                         # if node is visited, skip it
            continue

        visited.add(curr)                           # mark node
        G.add_node(curr)                            # and add it in the graph


        # -------------------------------------------------------------------------------
        # Every hop contains the same code: The only difference is the constant numbers
        # in imul and mov instructions. We can easily extract those numbers (as they're 
        # in constant offsets) and calculate the address of the next hop:
        # -------------------------------------------------------------------------------
        # .text:00000000004735F4 58                           pop     rax
        # .text:00000000004735F5 48 69 C0 3F 3B 00 00         imul    rax, 3B3Fh
        # .text:00000000004735FC 8B 84 02 8B 00 00 00         mov     eax, [rdx+rax+8Bh]
        # .text:0000000000473603 48 98                        cdqe
        # .text:0000000000473605 48 01 C2                     add     rdx, rax
        # .text:0000000000473608 FF E2                        jmp     rdx
        # -------------------------------------------------------------------------------
        A = Dword(curr + 4)
        B = Dword(curr + 11)

        for key in [ord(x) for x in flag_charset]:  # for each possible character of the key
            addr = Dword(curr + key * A + B)

            if addr & 0x80000000:
                addr = 0xffffffff00000000 | addr


            # calculate address of the next 'hop'
            next = (curr + addr) & 0xffffffffffffffff
            stack.append(next)                      # add it on the stack

            if not G.has_edge(curr, next):          # add edge on the graph
                G.add_edge(curr, next, key=key)     # edge weight == key


            # ok there might be >1 keys for the same transition. Here we discard them,
            # because we know that there's a unique flag of length 40.

    Message("Graph completed. |V| = %d, |E| = %d\n" % (len(G.nodes()), len(G.edges())))


    # -------------------------------------------------------------------------
    # Find a s path from entry to the success hop
    # -------------------------------------------------------------------------
    Message("Searching for a path...\n")
 
    # calculate all paths (starting from the shortest) from entry to the success hop
    for path in networkx.shortest_simple_paths(G, 0x44F491, 0x4015B9):

        # cast path: [a,b,c,d] to edges: [(a,b),(b,c),(c,d)] and construct flag
        u = path[0]

        flag = ''
        for v in path[1:]:
            flag += chr(G.get_edge_data(u, v)['key'])
            u = v

        Message("Flag of lenght %d found: %s" % (len(flag), flag))
        Message("\n")

        # there are many flags that endup at 0x4015B9, but only one has length 40
        if len(flag) >= 41:                         # is flag final? (40 + NULL byte)
            Message("* * * FLAG FOUND: %s\n" % flag)    
            break

# --------------------------------------------------------------------------------------------------
'''
Output (Code takes about 12hr to finish and produces 32174 flags):


HITCON CTF 2014 - hop crack started.
Flag node found!
Graph completed. |V| = 222, |E| = 12044
Searching for a path...
Flag of lenght 12 found: HI  5hr1n3}
Flag of lenght 12 found: HITL5hr1n3}
Flag of lenght 12 found: HIpA5hr1n3}
Flag of lenght 12 found: HITCO_r1n3}
...
Flag of lenght 20 found: HITCON{Cap7Uq8r1n3}
Flag of lenght 20 found: HITCON{Cap1H5hr1n3}
...
Flag of lenght 36 found:  HITCON{Capipjz7bJ2Ql1Ayi2Q@ 5hr1n3}
Flag of lenght 36 found:  HITCON{CapiOEDYbJ2Ql1h} Us@ 5hr1n3}
...
Flag of lenght 39 found:  HITCON{Cap7UD$LQl1JrWtA 0f Us@ 5hr1n3}
Flag of lenght 39 found:  HITCON{CappZD$LQl1JrWtA 0f Us@ 5hr1n3}
Flag of lenght 39 found:  HITCON{CapipD$LQl1JrWtA 0f Us@ 5hr1n3}
...
Flag of lenght 40 found:  Hl3 F1aKnABA 0f Us@ 5hr1LyQY7bJ2Ql1Jr_}
Flag of lenght 40 found:  Hl3 F1aKnABA 0f Us@ 5hr1LyQY7bJ2Ql1Y _}
Flag of lenght 41 found:  HITCON{Cap7ur3 Wh1t3 F1ag 0f Us@ 5hr1n3}
* * * FLAG FOUND: HITCON{Cap7ur3 Wh1t3 F1ag 0f Us@ 5hr1n3}
'''
# --------------------------------------------------------------------------------------------------
