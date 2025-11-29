## Lake CTF 2025 - Wordler (Misc 100)
##### 28/11 - 29/11/2025 (24hr)

___

### Description

*yo dawg i heard you like words in your wordle so i put words in your words so words*

```
nc chall.polygl0ts.ch 6052
```
___

### Solution

This challenge is a typical [Wordle](https://en.wikipedia.org/wiki/Wordle) game:
```
┌─[20:22:24]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/lake_ctf_2025/Wordler]
└──> nc chall.polygl0ts.ch 6052
Welcome to Wordle! The solution has 23 letters.
Structure: ■■■■■■■_■■■■■■_■■■■_■■_■■■■
------------------------------
Your guess: aaaaabbbbbcccccdddddeee
AAAAABB_BBBCCC_CCDD_DD_DEEE
Your guess: 
```

Some letters from server output are colored (yellow or green) according to the rules of Wordle.

The first task is to process the input. First we parse the `■■■■■■■_■■■■■■_■■■■_■■_■■■■` structure
and we extract the word lengths: `7, 6, 4, 2, 4`. Then we make a word guess and we send it back to
the server. The second task is to parse the letter colors to improve the guess.

To make things simpler, we are also given [word_list.txt](./word_list.txt), that contains all 
possible words that can be used, so we can easily iterate over all words of a given length and
find the most "suitable".

Once we have the functionality to process the server's output, we can apply the classic Wordle
algorithm. However, something is fucked up. Take a look at the example:
```
#1 ABOUT_....
   YYY-G 		-> Y = yellow, - = grey, G = green

#2 FIRST_....
   --YYT

#3 GREAT_....
   GGGGG
```    

Here `ABOUT`, gives us **3** yellows, `A`, `B`, `O`. But later on the word `GREAT` gives all greens
(guessed correctly) and does not contain `B`, `O`, or `S`.

I'm not sure what exactly is going on, but it is possible to solve the challenge by using only
the green letters (we have to make many tries though).

For more details, please refer to the [wordler_crack.py](./wordler_crack.py) script.

So the flag is: `EPFL{5CR1P71NG_15_CH34T1NG}`

___
