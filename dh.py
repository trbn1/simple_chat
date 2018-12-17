# -*- coding: utf-8 -*-

"""
This script is used for calculating public and secret key 
which is later used in the encryption process.
"""
import json_actions as ja
import random


def get_public_key(prime, base):
    """Calculate public key using given prime number and primitive root."""
    # Initialize secure random pool.
    rng = random.SystemRandom()
    # Get random number between X and Y used as a secret.
    secret = rng.randint(10000, 50000)
    # Calculate public key.
    public_key = base ** secret % prime
    return public_key, secret


def get_secret_key(prime, secret, recv_key):
    """Calculate secret key using given prime number, pre-generated secret
    and public key received from the other side."""
    # Calculate secret key.
    secret_key = recv_key ** secret % prime
    return secret_key