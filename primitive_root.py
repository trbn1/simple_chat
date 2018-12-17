# -*- coding: utf-8 -*-

"""
This is a script used for finding smallest primitive root of a given prime number.

"""
from math import gcd


def prim_roots(prime):
    """Find all primitive roots of a given prime number."""
    # Source: https://stackoverflow.com/a/40199092
    required_set = {num for num in range(1, prime) if gcd(num, prime) }
    return [g for g in range(1, prime) if required_set == {pow(g, powers, prime) for powers in range(1, prime)}]


def get_smallest_prim_root(prime):
    """Get smallest result from primitive roots list."""
    prim_roots_list = prim_roots(prime)
    return min(prim_roots_list)