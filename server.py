# -*- coding: utf-8 -*-

"""
This is a server for client-server chat system.
"""
import argparse
import dh
import encrypt
import json_actions as ja
import primes as p
import primitive_root as pr
import queue

from socket import AF_INET, SOCK_STREAM, socket
from threading import Thread


# Define server username globally.
SERVERNAME = 'Server'
# Maxiumum allowed number, while calculating primes (more than 1000 is not recommended).
MAX_PRIME = 1000


def accept_incoming_connection():
    """Accept incoming connection and create client thread."""
    while True:
        (client, client_address) = SERVER.accept()
        addresses[client] = client_address
        verboseprint('\n%s:%s has connected.' % addresses[client])
        Thread(target=handle_client, args=(client, )).start()


def handle_client(client):
    """Handle single client from accepted incoming connection."""
    # Receive and decode initial message.
    recv_init_msg = ja.recv_message(client.recv(BUFSIZ).decode())
    verboseprint('Received initial message:', recv_init_msg)
    # Verify, if client properly requests keys.
    if ja.verify_request(recv_init_msg):
        # End client connection, if initial request is invalid.
        client.close()
        verboseprint('Received initial message is incorrect.')
        return
    # Continue, if keys request is valid.
    else:
        # Initialize client parameters.
        init_client(client)
        client_name_set = False
        set_encrypt = True

        # Receive messages from client, as long as the connection exists.
        while True:
            retry_count = 0
            while retry_count < 10:
                try:
                    verboseprint('Waiting for message...')
                    retry_count += 1
                    # Receive message.
                    text, username = ja.decode_text(client.recv(BUFSIZ).decode())
                    verboseprint('\nReceived message:', text,
                                'Username:', username)
                    break
                except:
                    pass
            if retry_count == 10:
                close_connection(client, clients[client])
                break
            # Set encryption to 'none', if client didn't request any.
            if set_encrypt and username != 'encryption_request':
                encryptions[client] = 'none'
            # Accept change encryption request.
            if not set_encrypt and username == 'encryption_request':
                set_encrypt = True
            # Try to set selected encryption mode.
            if set_encrypt and username == 'encryption_request':
                set_encryption(client, text)
                set_encrypt = False
            else:
                # Save client username.
                if not client_name_set:
                    # Broadcast message, that somebody has joined the chat.
                    send_message_to_all('%s has joined the chat.' % username)
                    clients[client] = username
                    client_name_set = True
                # Ignore empty messages.
                if text == '':
                    continue
                # Decrypt encrypted message.
                elif encryptions[client] != 'none':
                    # Decrypt with xor.
                    if encryptions[client] == 'xor':
                        text = encrypt.xor(text, secret_keys[client])
                    # Decrypt with cezar.
                    if encryptions[client] == 'cezar':
                        text = encrypt.caesar(text, secret_keys[client], mode='decrypt')
                    verboseprint('Used decryption mode:', encryptions[client],
                                'Decrypted message:', text)
                    # Broadcast message to all clients.
                    if text != '/exit':
                        send_message_to_all(text, username)
                    # End connection, if client requests so.
                    else:
                        close_connection(client, username)
                        break
                else:
                    # Broadcast message to all clients.
                    if text != '/exit':
                        send_message_to_all(text, username)
                    # End connection, if client requests so.
                    else:
                        close_connection(client, username)
                        break


def init_client(client):
    """Initialize single clients parameters."""
    # Generate prime number and its primitive root.
    bases[client] = []
    # Don't allow primes without generators.
    while bases[client] == []:
        try:
            primes[client] = p.get_random_prime(MAX_PRIME)
            bases[client] = pr.get_smallest_prim_root(primes[client])
        except:
            pass
    # Send prime number and primitive root to client.
    client.send(ja.encode_variables(primes[client], bases[client]).encode('utf-8'))
    # Get secret and calculated public key.
    (public_key, secret) = dh.get_public_key(primes[client], bases[client])

    # Create queue later used for holding received public key value.
    thread_queue = queue.Queue()
    # Create threads used for sending and received public keys, so they can occur in any order.
    send_key_thread = Thread(target=client.send, args=(ja.send_server_key(public_key).encode('utf-8'), ))
    recv_key_thread = Thread(target=ja.recv_public_key, args=(client.recv(BUFSIZ).decode(), thread_queue))
    # Start threads.
    send_key_thread.start()
    recv_key_thread.start()
    # Receive client public key from queue.
    recv_client_key = thread_queue.get()
    # End threads and queue
    send_key_thread.join()
    recv_key_thread.join()
    thread_queue.task_done()

    # Get calculated secret key.
    secret_keys[client] = dh.get_secret_key(primes[client], secret, int(recv_client_key))

    verboseprint('DH parameters:', 
                'Prime number:', primes[client],
                'Primitive root:', bases[client],
                'Secret:', secret,
                'Server public key:', public_key,
                'Client public key:', recv_client_key,
                'Secret key:',  secret_keys[client])


def set_encryption(client, text):
    """Set requested encryption mode."""
    for encryption in ENCRYPTION_MODES:
        # True, if requested encryption mode is allowed.
        if bytes(text, 'utf-8') == bytes(encryption, 'utf-8'):
            encryptions[client] = text


def send_message(client, text, username=SERVERNAME):
    """Send message to a single client, username defaults to SERVERNAME, if not given."""
    try:
        verboseprint('\nSending message...')
        # Check, if client requires encryption.
        if encryptions[client] != 'none':
            # Encrypt with xor.
            if encryptions[client] == 'xor':
                enc_text = encrypt.xor(text, secret_keys[client])
            # Encrypt with cezar.
            if encryptions[client] == 'cezar':
                enc_text = encrypt.caesar(text, secret_keys[client])
            verboseprint('Used encryption mode:', encryptions[client],
                        'Encrypted message sent to %s:' % clients[client], text)
            # Send encrypted message.
            client.send(ja.encode_text(enc_text, username).encode('utf-8'))
        else:
            verboseprint('Message sent to %s:' % clients[client], text)
            # Send plain-text message.
            client.send(ja.encode_text(text, username).encode('utf-8'))
    except:
        print('ERROR: Couldnt send the message, dropping client connection.')
        close_connection(client)


def send_message_to_all(text, username=SERVERNAME):
    """Broadcast message to all clients."""
    if clients != {}:
        for client in clients:
            send_message(client, text, username)


def close_connection(client, username='unknown'):
    """Default behavior on client closing connection with server."""
    verboseprint('Ending connection with %s:%s.' % addresses[client])
    # Close client connection.
    client.close()
    # Delete information about client, if it exists.
    if client in clients:
        del clients[client]
    if client in addresses:
        del addresses[client]
    if client in primes:
        del primes[client]
    if client in bases:
        del bases[client]
    if client in encryptions:
        del encryptions[client]
    if client in secret_keys:
        del secret_keys[client]
    # Broadcast message, that somebody has left the chat.
    send_message_to_all('%s has left the chat.' % username)


"""Main application"""
# Parse command-line arguments.
parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', help='show additional info during runtime')
parser.add_argument('--ip', metavar='x.x.x.x', dest='HOST', nargs='?', const=1, help='choose ip to listen on', default='0.0.0.0')
parser.add_argument('--port', metavar='N', dest='PORT', nargs='?', const=1, help='choose port to listen on', type=int, default=54321)
args = parser.parse_args()

# Check, if verbose mode was requested.
if args.verbose:
    def verboseprint(*args):
        """Print given arguments."""
        for arg in args:
           print(arg)
        print
else:
    # Do nothing
    verboseprint = lambda *a: None

# Initialize required lists.
clients = {}
addresses = {}
primes = {}
bases = {}
encryptions = {}
secret_keys = {}

# Define server parameters.
BUFSIZ = 8192
ENCRYPTION_MODES = ['none', 'xor', 'cezar']
ADDR = (args.HOST, args.PORT)
SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

# Run server.
if __name__ == '__main__':
    SERVER.listen(5)
    verboseprint('Listening on %s:%s' % ADDR)
    verboseprint('Waiting for connections...')
    # Create new thread for each incoming connection.
    ACCEPT_THREAD = Thread(target=accept_incoming_connection)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()