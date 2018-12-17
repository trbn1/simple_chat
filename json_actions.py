# -*- coding: utf-8 -*-

"""
This script is used when working with JSON format,
in particular when encoding/decoding.
"""
import base64
import json


def initial_message():
    """Set proper format of initial message for verification purposes
    and encode it into JSON format."""
    msg = { 
        'request': 'keys',
    }
    return json.dumps(msg)


def recv_message(msg_recv):
    """Decode received message from JSON format."""
    return json.loads(msg_recv)


def verify_request(recv_req):
    """Verify received request message by comparing it with the proper
    initial message set earlier."""
    # Get values for both initial messages.
    recv_req = recv_req['request']
    proper_req = json.loads(initial_message())['request']

    # Return false if received request is not proper.
    if recv_req != proper_req:
        return False


def encode_text(text, username):
    """Encode given text to Base64 and, with username, encode it to
    JSON format."""
    # Create text string.
    text = base64.b64encode(text.encode('utf-8')).decode('utf-8')
    msg = { 
        'msg': text,
        'from': username,
    }
    return json.dumps(msg)


def decode_text(msg_recv):
    """Decode received message from JSON format and decide if it's
    an encryption request or a message with text."""
    msg = json.loads(msg_recv)

    # Is true if the received message is an encryption request.
    if 'encryption' in msg:
        return msg['encryption'], 'encryption_request'

    # Is true if the received message is a message with text.
    if 'msg' in msg:
        return base64.b64decode(msg['msg']).decode(), msg['from']

def encode_variables(prime, base):
    """Encode given prime number and primitive root to valid 
    JSON format."""
    msg = { 
        'p': prime,
        'g': base,
    }
    return json.dumps(msg)


def get_primes(msg):
    """Get prime number and primitive root from given JSON."""
    primes = {}
    primes[0] = msg['p']
    primes[1] = msg['g']
    return primes


def send_client_key(secret):
    """Send public client key in proper JSON format."""
    msg = { 
        'a': str(secret),
    }
    return json.dumps(msg)


def send_server_key(secret):
    """Send public server key in proper JSON format."""
    msg = { 
        'b': str(secret),
    }
    return json.dumps(msg)


def recv_public_key(msg_recv, queue_out=''):
    """Get public key from received message."""
    msg_recv = recv_message(msg_recv)
    # If message is from a client, put the key in queue output.
    if 'a' in msg_recv:
        queue_out.put(msg_recv['a'])
    # If message is from a server, return key.
    else:
        return msg_recv['b']


def request_encryption(mode):
    """Encode encryption mode request in proper JSON format."""
    msg = { 
        'encryption': mode,
    }
    return json.dumps(msg)