## 9447 Security Society CTF 2014 - polydata (Misc 270)
##### 29-30/11/2014 (36hr)
___

### Description: 

polydata.9447.plumbing:13371

```
Maximum subsequence sum (MSS):
 - Input:
   A list of numbers.
 - Output:
   The maximum subsequence sum of the numbers
 - Input format:
   x_1 x_2 ... x_n
 - Restrictions:
   None

Travelling salesperson problem (TSP):
 - Input:
   A graph represented as a list of edges of the form (to, from, weight). Edges
   are bidirectional.
 - Output:
   The weight of the shortest cycle visiting all nodes exactly once
 - Input format:
   u_1 v_1 w_1
   u_2 v_2 w_2
   ...
   u_n v_n w_n
 - Restrictions
   At most 20 unique nodes

0-1 knapsack (KS):
 - Input:
   The size of the bag, followed by pairs of integers, each representing the
   weight and value respectively of a single item.
 - Output:
   The maximum value that can be obtained through picking a set of the
   items such that the sum of their weights is less than or equal to the size
   of the bag.
 - Input format:
   W
   w_1 v_1
   w_2 v_2
   ...
   w_n v_n
 - Restrictions:
   0 < w_i <= W <= 100000

Input should be a list of whitespace-separated numbers. All numbers should fit
in a 32-bit signed integer. This list should be valid input for all problems.
This list of numbers should be terminated by whitespace then a hash character
'#'.

Provide input that meets all constraints and produces the same result for all
problems
```
___

### Solution
Very tricky challenge. How can we generate such an input? The method here is by trial 
and error. To reduce the possible combinations, we must analyze first the problems:

The MSS is the easiest of all. By setting very large negative values between the numbers, 
we can manipulate the result.

The TSP problem consists of triplets. So the input should be multiple of 3. The points
here are:
	- Negative node indices are allowed
	- If there are many edges from a node to an another, only the edge with the least
		cost will be used, e.g. 1 2 5, and 1 2 9 --> distance from 1 to 2 is 5.

Consider the following input: x y A x z B y z C. No matter what are x,y,z the result here
will be A + B + C. We can also add dummy values, that do not affect the result. So the
input: x y A x z B y z C x y D, won't affect the result if D <= A.

Let's go to the knapsack. We need a big value as a first number. Then we need pairs of
numbers. So the input should be an odd number. If an item has an negative value, it
will definetely won't participate on answer (it's better to not take it and get a 0 value). 
So the input: W x A y -B z -C, will have an result of A, subject to:
```
	0< x, y, z <= W
	A, B, C >= 0
```

The minimum length of input is 9 numbers. Then next is 15 characters. Let's make a first
try with 9 numbers:

```
Input              : x y C x z B z y A
Knapsack Constrains: > >   >   >   >    (where > denotes a positive value)
Results:
	TSP : A + B + C
	KNAP: A
	MSS : MAX(x+y, x, B, y+A} 

Subject to:
	x > y > 0
	x > B
	x > z
	B > 0
```

TSP has a solution because x,y,z make a circle. To prevent a big result on MSS, we must set
negative values somewer. Here z can be negative. We assume that z<0 and C<0 (only the the 
last pair will participate on knapsack). These results must be equal, so:
```
	TSP : A + B + C           => B = -C
	KNAP: A                   => A
	MSS : MAX(x+y, x, B, y+A} =  y + A => y = 0 => Error! y > 0!
```

We can see that the above assumptions can be hold. Also it's very difficult (if not impossible)
to solve that problem with 9 numbers. So Let's go to 15 numbers. We just extend the previous
idea. Let's try a TSP with 3 nodes, and a Knapsack with 2 values participating in the result:
```
Input     : x y A x z B z x C x z D x z E, with C > D, E.  
Constrains: > >   >   >   >   >   >   >
```
z can be < 0, in order to control the MSS. So we assume that z < 0. Let's try to find a 
first substitution:
```	
    5 1 5 5 -8 5 -8 1 6 1 -8 5 -8 1 5 #
	MSS: 16
	TSP: 15
	KS : 16
```
Not bad! We're quite close. However with different assumptions we can get different
equations. The point here is to try to write the problem in a mathematical format. Let's
assume now that TSP has 4 nodes:
```	
    A -> B -> C -> A
	A -> D -> B
```

We have 5 edges here, so there're no dummy values on TSP. Furthermore the size of knapsack
is too small (5). Let's increase it to 6. But we must decrease the size of the first 
value/item to avoid a very big MSS (because we have 4 positive number at the beginning).

Let's make a first assumption:
```
	x  y  A  x  z   B  z  y  C  x  w  D  w  y  E
	6  1  3  6 -18  6 -18 1  7  6 -6  3 -6  1  6 #
	MSS: 16
	TSP: 22
	KS:  16
```

By setting a very low z value, we can control MSS to 16 (the first 4 values). The knapsack
is ok (we only use the items (y,A), (y,C) and (y,E) -all other items have a negative values.
Let's try to fix the TSP. The solution must pass through node w. So, we must fix the edges
(x,w) and (w,y). Playing around with the edge, finally we can end up with a solution of 16
for the TSP, and solve the problem:
```
	6 1 3 6 -18 2 -18 1 7 6 -6 1 -6 1 6 #
	MSS: 16
	TSP: 16
	KS:  16
```
Congratulations! The flag is **9447{fun_fact_this_data_is_better_than_most_Australian_ACM_data}**

Of course this path to the solution is not unique. Everything here based on assumptions.
We made some assumptions, and then we try to formalize the "solution family".

___
