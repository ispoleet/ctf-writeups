#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HITCON QUALS 2024 - Revisual (RE 255)
# ----------------------------------------------------------------------------------------
import re


equations = '''
   Math.abs(0.3837876686390533  - canvasCalcObj.gtfo(i_11_01_21, i_14_01_09, i_17_09_21, 16, 21));
   Math.abs(0.21054889940828397 - canvasCalcObj.gtfo(i_11_03_01, i_11_01_21, i_08_11_01, 8,  2 ));
   Math.abs(0.475323349112426   - canvasCalcObj.gtfo(i_11_01_21, i_18_11_17, i_05_06_10, 0,  20));
   Math.abs(0.6338370887573964  - canvasCalcObj.gtfo(i_05_17_02, i_07_20_18, i_05_06_10, 8,  4 ));
   Math.abs(0.4111607928994082  - canvasCalcObj.gtfo(i_11_22_18, i_11_03_01, i_12_03_10, 23, 1 ));
   Math.abs(0.7707577751479291  - canvasCalcObj.gtfo(i_18_11_17, i_05_17_02, i_16_14_13, 20, 6 ));
   Math.abs(0.7743081420118344  - canvasCalcObj.gtfo(i_23_09_20, i_02_11_05, i_05_17_02, 9,  10));
   Math.abs(0.36471487573964495 - canvasCalcObj.gtfo(i_17_09_21, i_19_03_05, i_20_13_05, 18, 8 ));
   Math.abs(0.312678449704142   - canvasCalcObj.gtfo(i_12_03_10, i_23_09_20, i_18_11_17, 0,  17));
   Math.abs(0.9502808165680473  - canvasCalcObj.gtfo(i_12_15_02, i_23_09_20, i_05_17_02, 22, 10));
   Math.abs(0.5869052899408282  - canvasCalcObj.gtfo(i_05_06_10, i_09_05_04, i_11_22_18, 14, 10));
   Math.abs(0.9323389467455623  - canvasCalcObj.gtfo(i_18_11_17, i_11_22_18, i_05_06_10, 12, 7 ));
   Math.abs(0.4587118106508875  - canvasCalcObj.gtfo(i_08_11_01, i_02_11_05, i_11_22_18, 4,  21));
   Math.abs(0.14484472189349107 - canvasCalcObj.gtfo(i_12_03_10, i_23_09_20, i_11_03_01, 7,  15));
   Math.abs(0.7255550059171598  - canvasCalcObj.gtfo(i_11_01_21, i_18_11_17, i_12_15_02, 9,  23));
   Math.abs(0.5031261301775147  - canvasCalcObj.gtfo(i_05_17_02, i_11_22_18, i_11_03_01, 7,  1 ));
   Math.abs(0.1417352189349112  - canvasCalcObj.gtfo(i_08_11_01, i_11_03_01, i_17_09_21, 16, 14));
   Math.abs(0.5579334437869822  - canvasCalcObj.gtfo(i_11_03_01, i_11_22_18, i_12_15_02, 19, 11));
   Math.abs(0.48502262721893485 - canvasCalcObj.gtfo(i_16_05_04, i_20_13_05, i_09_05_04, 23, 18));
   Math.abs(0.5920916568047336  - canvasCalcObj.gtfo(i_09_05_04, i_17_09_21, i_07_20_18, 19, 6 ));
   Math.abs(0.7222713017751479  - canvasCalcObj.gtfo(i_14_01_09, i_11_22_18, i_20_13_05, 8,  16));
   Math.abs(0.12367382248520711 - canvasCalcObj.gtfo(i_16_05_04, i_12_03_10, i_05_06_10, 9,  5 ));
   Math.abs(0.4558028402366864  - canvasCalcObj.gtfo(i_16_14_13, i_16_05_04, i_11_22_18, 10, 2 ));
   Math.abs(0.8537692426035504  - canvasCalcObj.gtfo(i_18_11_17, i_23_09_20, i_02_11_05, 4,  11));
   Math.abs(0.9618170650887574  - canvasCalcObj.gtfo(i_05_06_10, i_12_15_02, i_18_11_17, 15, 2 ));
   Math.abs(0.22088933727810647 - canvasCalcObj.gtfo(i_19_03_05, i_09_05_04, i_14_01_09, 10, 5 ));
   Math.abs(0.4302783550295858  - canvasCalcObj.gtfo(i_14_01_09, i_16_14_13, i_11_01_21, 14, 2 ));
   Math.abs(0.6262803313609467  - canvasCalcObj.gtfo(i_22_00_19, i_11_03_01, i_11_22_18, 17, 22));
'''

# ----------------------------------------------------------------------------------------
def find_equation(knownz=set(), num_unknowz=4):
    """Finds the equation with `num_unknowz` unknown points excluding a `knownz` set."""
    best_points = set()
    best_equation = ''

    print(f'[+] Finding an equation using the known set: {knownz}')

    for i, line in enumerate(equations.splitlines()):
        if not line: continue   # Skip emply lines.

        # Extract all 9 points from the `gtfo` function.
        #
        # Example: canvasCalcObj.gtfo(i_11_01_21, i_14_01_09, i_17_09_21, 16, 21)).
        match = re.match(r'.*' + 
                         r'i_([0-9]{2})_([0-9]{2})_([0-9]{2}), ' +
                         r'i_([0-9]{2})_([0-9]{2})_([0-9]{2}), ' +
                         r'i_([0-9]{2})_([0-9]{2})_([0-9]{2})' +
                         r'.*', line)
        if match is None:
            continue

        points = set(int(p) for p in match.groups())
        unknown_points = points.difference(knownz)  # Exclude known points.
        count = len(unknown_points)

        print(f'[+]    Equation #{i:2d} has {count} unknown points: {unknown_points}')

        if count == 0:
            continue  # If we know all points in an equation. ingore it.

        if num_unknowz == count:
            print(f'[+] Found equation with {count} unknown points: {unknown_points} ' +
              f'~> {line.strip()!r}')

            return unknown_points, line


    raise Exception(f'Cannot find an equation with {num_unknowz} unknown points')


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Revisual `find equation` script started.')

    # Nothing with 4, try with 5.
    s1, eq1 = find_equation(num_unknowz=5) 
    s2, eq2 = find_equation(s1, num_unknowz=3)  # Try 3, it's faster.
    s3, eq3 = find_equation(s2.union(s1), num_unknowz=4)
    s4, eq4 = find_equation(s3.union(s2).union(s1), num_unknowz=4)
    s5, eq5 = find_equation(s4.union(s3).union(s2).union(s1), num_unknowz=4)
    # Nothing with 4 and 3. Try 2.
    s6, eq6 = find_equation(s5.union(s4).union(s3).union(s2).union(s1), num_unknowz=2)
    # Nothing with 2. Try 1.
    s7, eq7 = find_equation(s6.union(s5).union(s4).union(s3).union(s2).union(s1), num_unknowz=1)
    s8, eq8 = find_equation(s7.union(s6).union(s5).union(s4).union(s3).union(s2).union(s1), num_unknowz=1)
    # Nothing with 1 => We have solved all points!

    print('[+] EQUATION LIST:')
    print(f'[+]    {eq1} ~> {s1}')
    print(f'[+]    {eq2} ~> {s2}')
    print(f'[+]    {eq3} ~> {s3}')
    print(f'[+]    {eq4} ~> {s4}')
    print(f'[+]    {eq5} ~> {s5}')
    print(f'[+]    {eq6} ~> {s6}')
    print(f'[+]    {eq7} ~> {s7}')
    print(f'[+]    {eq8} ~> {s8}')

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
"""
[+] Revisual `find equation` script started.
[+] Finding an equation using the known set: set()
[+]    Equation # 1 has 6 unknown points: {1, 17, 21, 9, 11, 14}
[+]    Equation # 2 has 5 unknown points: {1, 3, 21, 8, 11}
[+] Found equation with 5 unknown points: {1, 3, 21, 8, 11} ~> 'Math.abs(0.21054889940828397 - canvasCalcObj.gtfo(i_11_03_01, i_11_01_21, i_08_11_01, 8,  2 ));'
[+] Finding an equation using the known set: {1, 3, 21, 8, 11}
[+]    Equation # 1 has 3 unknown points: {9, 14, 17}
[+] Found equation with 3 unknown points: {9, 14, 17} ~> 'Math.abs(0.3837876686390533  - canvasCalcObj.gtfo(i_11_01_21, i_14_01_09, i_17_09_21, 16, 21));'
[+] Finding an equation using the known set: {1, 3, 8, 9, 11, 14, 17, 21}
[+]    Equation # 1 has 0 unknown points: set()
[+]    Equation # 2 has 0 unknown points: set()
[+]    Equation # 3 has 4 unknown points: {10, 18, 5, 6}
[+] Found equation with 4 unknown points: {10, 18, 5, 6} ~> 'Math.abs(0.475323349112426   - canvasCalcObj.gtfo(i_11_01_21, i_18_11_17, i_05_06_10, 0,  20));'
[+] Finding an equation using the known set: {1, 3, 5, 6, 8, 9, 10, 11, 14, 17, 18, 21}
[+]    Equation # 1 has 0 unknown points: set()
[+]    Equation # 2 has 0 unknown points: set()
[+]    Equation # 3 has 0 unknown points: set()
[+]    Equation # 4 has 3 unknown points: {2, 20, 7}
[+]    Equation # 5 has 2 unknown points: {12, 22}
[+]    Equation # 6 has 3 unknown points: {16, 2, 13}
[+]    Equation # 7 has 3 unknown points: {2, 20, 23}
[+]    Equation # 8 has 3 unknown points: {19, 20, 13}
[+]    Equation # 9 has 3 unknown points: {12, 20, 23}
[+]    Equation #10 has 5 unknown points: {2, 12, 15, 20, 23}
[+]    Equation #11 has 2 unknown points: {4, 22}
[+]    Equation #12 has 1 unknown points: {22}
[+]    Equation #13 has 2 unknown points: {2, 22}
[+]    Equation #14 has 3 unknown points: {12, 20, 23}
[+]    Equation #15 has 3 unknown points: {2, 12, 15}
[+]    Equation #16 has 2 unknown points: {2, 22}
[+]    Equation #17 has 0 unknown points: set()
[+]    Equation #18 has 4 unknown points: {2, 12, 22, 15}
[+] Found equation with 4 unknown points: {2, 12, 22, 15} ~> 'Math.abs(0.5579334437869822  - canvasCalcObj.gtfo(i_11_03_01, i_11_22_18, i_12_15_02, 19, 11));'
[+] Finding an equation using the known set: {1, 2, 3, 5, 6, 8, 9, 10, 11, 12, 14, 15, 17, 18, 21, 22}
[+]    Equation # 1 has 0 unknown points: set()
[+]    Equation # 2 has 0 unknown points: set()
[+]    Equation # 3 has 0 unknown points: set()
[+]    Equation # 4 has 2 unknown points: {20, 7}
[+]    Equation # 5 has 0 unknown points: set()
[+]    Equation # 6 has 2 unknown points: {16, 13}
[+]    Equation # 7 has 2 unknown points: {20, 23}
[+]    Equation # 8 has 3 unknown points: {19, 20, 13}
[+]    Equation # 9 has 2 unknown points: {20, 23}
[+]    Equation #10 has 2 unknown points: {20, 23}
[+]    Equation #11 has 1 unknown points: {4}
[+]    Equation #12 has 0 unknown points: set()
[+]    Equation #13 has 0 unknown points: set()
[+]    Equation #14 has 2 unknown points: {20, 23}
[+]    Equation #15 has 0 unknown points: set()
[+]    Equation #16 has 0 unknown points: set()
[+]    Equation #17 has 0 unknown points: set()
[+]    Equation #18 has 0 unknown points: set()
[+]    Equation #19 has 4 unknown points: {16, 20, 4, 13}
[+] Found equation with 4 unknown points: {16, 20, 4, 13} ~> 'Math.abs(0.48502262721893485 - canvasCalcObj.gtfo(i_16_05_04, i_20_13_05, i_09_05_04, 23, 18));'
[+] Finding an equation using the known set: {1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 22}
[+]    Equation # 1 has 0 unknown points: set()
[+]    Equation # 2 has 0 unknown points: set()
[+]    Equation # 3 has 0 unknown points: set()
[+]    Equation # 4 has 1 unknown points: {7}
[+]    Equation # 5 has 0 unknown points: set()
[+]    Equation # 6 has 0 unknown points: set()
[+]    Equation # 7 has 1 unknown points: {23}
[+]    Equation # 8 has 1 unknown points: {19}
[+]    Equation # 9 has 1 unknown points: {23}
[+]    Equation #10 has 1 unknown points: {23}
[+]    Equation #11 has 0 unknown points: set()
[+]    Equation #12 has 0 unknown points: set()
[+]    Equation #13 has 0 unknown points: set()
[+]    Equation #14 has 1 unknown points: {23}
[+]    Equation #15 has 0 unknown points: set()
[+]    Equation #16 has 0 unknown points: set()
[+]    Equation #17 has 0 unknown points: set()
[+]    Equation #18 has 0 unknown points: set()
[+]    Equation #19 has 0 unknown points: set()
[+]    Equation #20 has 1 unknown points: {7}
[+]    Equation #21 has 0 unknown points: set()
[+]    Equation #22 has 0 unknown points: set()
[+]    Equation #23 has 0 unknown points: set()
[+]    Equation #24 has 1 unknown points: {23}
[+]    Equation #25 has 0 unknown points: set()
[+]    Equation #26 has 1 unknown points: {19}
[+]    Equation #27 has 0 unknown points: set()
[+]    Equation #28 has 2 unknown points: {0, 19}
[+] Found equation with 2 unknown points: {0, 19} ~> 'Math.abs(0.6262803313609467  - canvasCalcObj.gtfo(i_22_00_19, i_11_03_01, i_11_22_18, 17, 22));'
[+] Finding an equation using the known set: {0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}
[+]    Equation # 1 has 0 unknown points: set()
[+]    Equation # 2 has 0 unknown points: set()
[+]    Equation # 3 has 0 unknown points: set()
[+]    Equation # 4 has 1 unknown points: {7}
[+] Found equation with 1 unknown points: {7} ~> 'Math.abs(0.6338370887573964  - canvasCalcObj.gtfo(i_05_17_02, i_07_20_18, i_05_06_10, 8,  4 ));'
[+] Finding an equation using the known set: {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}
[+]    Equation # 1 has 0 unknown points: set()
[+]    Equation # 2 has 0 unknown points: set()
[+]    Equation # 3 has 0 unknown points: set()
[+]    Equation # 4 has 0 unknown points: set()
[+]    Equation # 5 has 0 unknown points: set()
[+]    Equation # 6 has 0 unknown points: set()
[+]    Equation # 7 has 1 unknown points: {23}
[+] Found equation with 1 unknown points: {23} ~> 'Math.abs(0.7743081420118344  - canvasCalcObj.gtfo(i_23_09_20, i_02_11_05, i_05_17_02, 9,  10));'
[+] EQUATION LIST:
[+]       Math.abs(0.21054889940828397 - canvasCalcObj.gtfo(i_11_03_01, i_11_01_21, i_08_11_01, 8,  2 )); ~> {1, 3, 21, 8, 11}
[+]       Math.abs(0.3837876686390533  - canvasCalcObj.gtfo(i_11_01_21, i_14_01_09, i_17_09_21, 16, 21)); ~> {9, 14, 17}
[+]       Math.abs(0.475323349112426   - canvasCalcObj.gtfo(i_11_01_21, i_18_11_17, i_05_06_10, 0,  20)); ~> {10, 18, 5, 6}
[+]       Math.abs(0.5579334437869822  - canvasCalcObj.gtfo(i_11_03_01, i_11_22_18, i_12_15_02, 19, 11)); ~> {2, 12, 22, 15}
[+]       Math.abs(0.48502262721893485 - canvasCalcObj.gtfo(i_16_05_04, i_20_13_05, i_09_05_04, 23, 18)); ~> {16, 20, 4, 13}
[+]       Math.abs(0.6262803313609467  - canvasCalcObj.gtfo(i_22_00_19, i_11_03_01, i_11_22_18, 17, 22)); ~> {0, 19}
[+]       Math.abs(0.6338370887573964  - canvasCalcObj.gtfo(i_05_17_02, i_07_20_18, i_05_06_10, 8,  4 )); ~> {7}
[+]       Math.abs(0.7743081420118344  - canvasCalcObj.gtfo(i_23_09_20, i_02_11_05, i_05_17_02, 9,  10)); ~> {23}
[+] Program finished. Bye bye :)
"""
# ----------------------------------------------------------------------------------------
