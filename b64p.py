#!/usr/bin/env python
#Takes a string as an argument and returns 3 base64 encoded string partials.
#One of these strings is guaranteed to be present in the base64 content if
#the original plain-text code contained the (case-sensitive) input string.

#Due to the 8 bit to 6 bit encoding conversion involved in base64 encoding,
#the edges don't always align nicely, so trimming is required as the first
#and last characters may be different depending on the immediate context.

from base64 import b64encode
import sys

def main(input):
        L_offset = 0
        R_offset = 3 - ((len(input) + L_offset) % 3)
        if (R_offset == 3):
                R_offset = 0

        e1, e2, e3 = encode(input)

        e1 = trim(e1, L_offset, R_offset)

        L_offset += 1
        R_offset = 3 - ((len(input) + L_offset) % 3)
        if (R_offset == 3):
                R_offset = 0

        e2 = trim(e2, L_offset, R_offset)

        L_offset += 1
        R_offset = 3 - ((len(input) + L_offset) % 3)
        if (R_offset == 3):
                R_offset = 0

        e3 = trim(e3, L_offset, R_offset)

        print(e1)
        print(e2)
        print(e3)

def offset_2_chars(offset):
        if (offset == 0):
                return 0
        elif (offset == 1):
                return 2
        else:
                return 3

def trim(input, L_offset, R_offset):
        input = trimL(input, L_offset)
        input = trimR(input, R_offset)
        return input

def trimL(input, offset):
        left_cut = offset_2_chars(offset)
        return input[left_cut:]

def trimR(input, offset):
        if (offset == 0):
                return input
        right_cut = offset_2_chars(offset)
        return input[:-right_cut]

def encode(input):
        e1 = b64encode(input)
        e2 = b64encode('0' + input)
        e3 = b64encode('00' + input)
        return e1, e2, e3

if __name__ == '__main__':
        main(sys.argv[1])
