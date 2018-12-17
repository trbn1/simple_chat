# -*- coding: utf-8 -*-

"""
This is a script used for encrypting/decrypting given text.
"""
import unicodedata

from itertools import cycle


def xor(text, secret_key):
    """Encrypt given string using single-byte XOR cipher."""

    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(text, cycle(str(secret_key % 256))))


def caesar(text, secret_key, mode=''):
    """Encrypt given string using Caesar cipher."""
    # Initialize empty string.
    enc_text = ''
    # Reverse the key, if mode is set to decryption.
    if mode == 'decrypt':
        secret_key *= (-1)

    # Normalize the text to take care of non-ASCII letters .
    else:
        text = unicodedata.normalize('NFD', text)

    for i in range(len(text)):
        char = text[i]
        # Don't touch 'ł' - normalization doesn't work for 'ł'.
        if char == 'ł' or char == 'Ł':
            enc_text += char

        # Encrypt upper-case letters.
        elif (char.isupper()):
            enc_text += chr((ord(char) + secret_key - 65) % 26 + 65)

        # Encrypt lower-case letters.
        elif (char.islower()):
            enc_text += chr((ord(char) + secret_key - 97) % 26 + 97)

        # Don't touch any other characters.
        else:
            enc_text += char
  
    return enc_text 