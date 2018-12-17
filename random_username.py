# -*- coding: utf-8 -*-

"""
This is a script used for generating random usernames.
"""
import random


def get_random_username():
    """Generate a random username."""
    # Generate a random number and append it to 'User' string.
    rng = random.SystemRandom()
    random_number = rng.randint(1000, 9999)
    return 'User' + str(random_number)