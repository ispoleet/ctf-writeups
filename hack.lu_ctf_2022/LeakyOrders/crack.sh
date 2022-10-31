#!/bin/bash
# ----------------------------------------------------------------------------------------
# Hack.Lu CTF 2022 - Leaky Orders (RE 277)
# ----------------------------------------------------------------------------------------
./public/main &
#/chal/sigs &
PID=$!

echo "$> pid: $PID"

timestamp=$(date +%s)
for ((i=0; i<15; i++))
do
    NUMS=`./rand $((timestamp + 0))`
    # NUMS=`/tmp/rand $((timestamp + 0))`
    echo "$> Generate Numbers: $NUMS ~> (Iteration #$i)"

    ARR=($NUMS)
    echo "$> Array: ${ARR[0]} ${ARR[1]} ${ARR[2]}"

    # We need to play around with the sleep delay
    sleep 0.90

    timestamp=$(date +%s)

    kill -${ARR[0]} $PID
    kill -${ARR[2]} $PID
    kill -${ARR[1]} $PID

    echo '$> --------------------'
done

echo 'finito!'
sleep 2

# ----------------------------------------------------------------------------------------
# ispo@ispo-glaptop2:~/ctf/hack.lu_ctf_2022/LeakyOrders$ ./crack.sh 
#   $> pid: 292529
#   38 62 53
#   $> Generate Numbers: 38 62 53 ~> (Iteration #0)
#   $> Array: 38 62 53
#   $> --------------------
#   48 53 60
#   $> Generate Numbers: 48 53 60 ~> (Iteration #1)
#   $> Array: 48 53 60
#   $> --------------------
#   52 57 58
#   $> Generate Numbers: 52 57 58 ~> (Iteration #2)
#   $> Array: 52 57 58
#   $> --------------------
#   52 57 58
#   $> Generate Numbers: 52 57 58 ~> (Iteration #3)
#   $> Array: 52 57 58
#   $> --------------------
#   53 50 62
#   $> Generate Numbers: 53 50 62 ~> (Iteration #4)
#   $> Array: 53 50 62
#   $> --------------------
#   38 34 50
#   $> Generate Numbers: 38 34 50 ~> (Iteration #5)
#   $> Array: 38 34 50
#   $> --------------------
#   47 49 58
#   $> Generate Numbers: 47 49 58 ~> (Iteration #6)
#   $> Array: 47 49 58
#   $> --------------------
#   52 59 38
#   $> Generate Numbers: 52 59 38 ~> (Iteration #7)
#   $> Array: 52 59 38
#   $> --------------------
#   60 36 40
#   $> Generate Numbers: 60 36 40 ~> (Iteration #8)
#   $> Array: 60 36 40
#   $> --------------------
#   54 50 41
#   $> Generate Numbers: 54 50 41 ~> (Iteration #9)
#   $> Array: 54 50 41
#   $> --------------------
#   34 60 40
#   $> Generate Numbers: 34 60 40 ~> (Iteration #10)
#   $> Array: 34 60 40
#   $> --------------------
#   56 51 63
#   $> Generate Numbers: 56 51 63 ~> (Iteration #11)
#   $> Array: 56 51 63
#   $> --------------------
#   57 36 62
#   $> Generate Numbers: 57 36 62 ~> (Iteration #12)
#   $> Array: 57 36 62
#   $> --------------------
#   57 51 47
#   $> Generate Numbers: 57 51 47 ~> (Iteration #13)
#   $> Array: 57 51 47
#   $> --------------------
#   57 51 47
#   $> Generate Numbers: 57 51 47 ~> (Iteration #14)
#   $> Array: 57 51 47
#   $> --------------------
#   finito!
# ----------------------------------------------------------------------------------------