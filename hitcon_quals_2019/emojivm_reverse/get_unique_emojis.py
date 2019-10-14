#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# HITCON CTF quals 2019 - EmojiVM (RE 300)
# --------------------------------------------------------------------------------------------------
import sys
import struct
import codecs

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    with codecs.open('chal.evm', encoding='utf-8') as fp:
        emojis = fp.readline()

    unique_emojis = set(emoji for emoji in emojis)

    for emoji in sorted(unique_emojis):
        print u"{0}\t0x{1:05x}    --->".format(emoji, struct.unpack("<L", emoji.encode('utf-32le'))[0])
    
# --------------------------------------------------------------------------------------------------
