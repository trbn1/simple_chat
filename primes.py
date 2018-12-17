# -*- coding: utf-8 -*-

"""
This is a script used for getting random prime number.
"""
import random


def find_primes(max_number):
    """Find all prime numbers that are smaller than a given number."""
    # Source: https://hackernoon.com/prime-numbers-using-python-824ff4b3ea19
    primes = []
    for possible_prime in range(2, max_number + 1):
        # Assume number is prime until shown it is not. 
        is_prime = True
        for num in range(2, int(possible_prime ** 0.5) + 1):
            if possible_prime % num == 0:
                is_prime = False
                break
        # Append prime to the list, if it passed the test.
        if is_prime:
            primes.append(possible_prime)
    return primes


def get_random_prime(max_number):
    """Get random prime number from pre-generated list of primes."""
    primes = find_primes(max_number)
    # Don't allow prime numbers smaller than 100
    prime = 0
    while prime < 100:
        prime =random.randrange(0, len(primes))
    return prime