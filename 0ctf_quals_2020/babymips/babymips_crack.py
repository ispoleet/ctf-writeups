#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# 0CTF 2020 - Baby MIPS (RE 297)
# ----------------------------------------------------------------------------------------
import copy

perm_matrix = [
    ' ', ' ', 'w', ' ', ' ', ' ', 's', ' ', ' ', 
    ' ', ' ', ' ', 'd', ' ', ' ', 'w', ' ', ' ', 
    'd', ' ', ' ', ' ', ' ', ' ', 'a', ' ', ' ', 
    ' ', 'e', ' ', 'w', ' ', 'q', ' ', 'a', ' ', 
    'e', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 
    'a', ' ', ' ', 'z', 'd', ' ', ' ', 's', 'w', 
    'q', ' ', ' ', ' ', ' ', 'w', ' ', ' ', 's', 
    'x', ' ', 'd', ' ', ' ', ' ', ' ', ' ', 'z', 
    'w', ' ', ' ', ' ', ' ', ' ', ' ', 'd', 'x'
]

perm_matrix_orig = copy.deepcopy(perm_matrix)

tbl_B = [
    0x00, 0x01, 0x02, 0x03, 0x0a, 0x0c, 0x0d, 0x0e, 0x13, 
    0x04, 0x05, 0x06, 0x0f, 0x18, 0x19, 0x21, 0x2a, 0x33,
    0x07, 0x08, 0x10, 0x11, 0x1a, 0x22, 0x23, 0x2b, 0x34,
    0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x37, 0x3f, 0x48,
    0x0b, 0x14, 0x15, 0x1c, 0x1d, 0x1e, 0x25, 0x2e, 0x27,
    0x16, 0x17, 0x1f, 0x20, 0x28, 0x31, 0x3a, 0x42, 0x43,
    0x26, 0x2f, 0x30, 0x38, 0x39, 0x40, 0x41, 0x49, 0x4a,
    0x29, 0x32, 0x3b, 0x3c, 0x3d, 0x44, 0x4b, 0x4c, 0x4d,
    0x2c, 0x35, 0x3e, 0x45, 0x46, 0x47, 0x4e, 0x4f, 0x50
]


# ----------------------------------------------------------------------------------------
def print_matrix():
    for i in range(9):
        print('\t', end='')

        for j in range(9):          
            print("%c, " % perm_matrix[9*i + j], end='')
        print()


# ----------------------------------------------------------------------------------------
def check(i, ch, iter_func):
    cnt_map = {ch: 0 for ch in 'zxcasdqwe'}

    # Mark the character you want to add once.
    cnt_map[ch] = 1

    for j in range(9):
        ch = perm_matrix[iter_func(i, j)]

        if ch != ' ':
           cnt_map[ch] += 1

    # Check if all characters appear exactly once.
    return max(cnt_map.values()) == 1


# ----------------------------------------------------------------------------------------
def solve_matrix(start=0, depth=0):
    if depth == 56:
        print('[+] Solution found!!!')
        print_matrix()

        # Extract flag using the original matrix
        flag = ''
        for i in range(9*9):
            if perm_matrix_orig[i] == ' ':
                flag += perm_matrix[i]
    
        print('[+] Flag: flag{%s}' % flag)
        return


    # For each position in the matrix
    for curr in range(start, 0x51):
        if perm_matrix[curr] != ' ':
            # Slot is already filled. Skip it.
            continue

        row, col = curr // 9, curr % 9

        for ch in 'zxcasdqwe':            
            if (not check(row, ch, lambda i, j: 9*i + j) or
                not check(col, ch, lambda j, i: 9*i + j) or
                not check(tbl_B_idx[curr], ch, lambda k, j: tbl_B[9*k + j])):
                    continue

            # All checks are passed. Move on.
            perm_matrix[9*row + col] = ch
            solve_matrix(curr+1, depth+1)
            perm_matrix[9*row + col] = ' '

        # We can't find any valid character. Backtrack.
        break

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Baby MIPS crack started.')

    print('[+] Initial permutation matrix:')
    print_matrix()

    # Associate each position with the row in tbl_B (for efficiency).
    tbl_B_idx = {}
    for i in range(9):
        for j in range(9):
            tbl_B_idx[tbl_B[9*i + j]] = i


    print('[+] Solving ...')
    solve_matrix()


# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/0ctf/babymips$ time ./babymips_crack.py
[+] Baby MIPS crack started.
[+] Initial permutation matrix:
	 ,  , w,  ,  ,  , s,  ,  ,
	 ,  ,  , d,  ,  , w,  ,  ,
	d,  ,  ,  ,  ,  , a,  ,  ,
	 , e,  , w,  , q,  , a,  ,
	e,  ,  ,  ,  ,  ,  ,  ,  ,
	a,  ,  , z, d,  ,  , s, w,
	q,  ,  ,  ,  , w,  ,  , s,
	x,  , d,  ,  ,  ,  ,  , z,
	w,  ,  ,  ,  ,  ,  , d, x,
[+] Solving ...
[+] Solution found!!!
	z, a, w, c, e, d, s, x, q,
	s, x, a, d, q, e, w, z, c,
	d, s, c, x, w, z, a, q, e,
	c, e, z, w, s, q, x, a, d,
	e, d, q, s, x, c, z, w, a,
	a, q, e, z, d, x, c, s, w,
	q, z, x, a, c, w, d, e, s,
	x, w, d, e, a, s, q, c, z,
	w, c, s, q, z, a, e, d, x,
[+] Flag: flag{zacedxqsxaqezcscxwzqeczsxddqsxczwaqexczxacdeweasqccsqzae}

real	0m2.572s
user	0m2.551s
sys	0m0.027s
'''
# ----------------------------------------------------------------------------------------


