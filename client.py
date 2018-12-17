# -*- coding: utf-8 -*-

"""
This is a client for client-server chat system.
"""
import argparse
import dh
import encrypt
import json_actions as ja
import random_username as ru
import tkinter

from socket import AF_INET, SOCK_STREAM, socket
from threading import Thread


def init_app():
    """Initialize app with required parameters."""
    # Ask user for host ip.
    host = input('Input host (default is 127.0.0.1): ')
    # Defaults to 127.0.0.1, if user didn't input ip.
    if not host:
        host = '127.0.0.1'

    # Ask user for host port
    port = input('Input port (default is 54321): ')
    # Defaults to 54321, if user didn't input port.
    if not port:
        port = 54321
    else:
        port = int(port)

    # Set buffer size.
    buf_size = 8192
    addr = (host, port)

    # Define available encryption modes.
    encryption_modes = ['none', 'xor', 'cezar']
    # Ask user to select encryption mode.
    encryption = input('Choose encryption mode (input number):\n1) none (default) 2) xor 3) cezar\n')
    # Defaults to no encryption, if user didn't choose any.
    if not encryption or encryption is '1':
        encryption = encryption_modes[0]
    else:
        if encryption is '2':
            encryption = encryption_modes[1]

        if encryption is '3':
            encryption = encryption_modes[2]

    # Ask user for username.
    username = input('Choose username (under 16 characters) or press ENTER to get random one:\n')
    while True:
        if len(username) > 16:
            print('ERROR: Username is too long!')
            username = input()
            continue
        else:
            break
    # Generate random username in format UserXXXX, where XXXX is random number,
    # if user didn't choose one.
    if not username:
        username = ru.get_random_username()

    return buf_size, addr, encryption_modes, encryption, username

def init_client(client_socket, buf_size, encryption):
    """Initialize client parameters and get secret key used in encryption"""
    # Receive first message that contains a prime number and a primitive root.
    recv_msg = ja.recv_message(client_socket.recv(buf_size).decode())
    primes = ja.get_primes(recv_msg)
    prime = int(primes[0])
    base = int(primes[1])

    # Get generated public key and secret used in calculations.
    (public_key, secret) = dh.get_public_key(prime, base)

    # Send generated public key to the server.
    client_socket.send(ja.send_client_key(public_key).encode('utf-8'))

    # Receive public key from the server.
    recv_server_key = int(ja.recv_public_key(client_socket.recv(buf_size).decode()))

    # Get generated secret key.
    secret_key = dh.get_secret_key(prime, secret, recv_server_key)

    # Send encryption request to the server.
    client_socket.send(ja.request_encryption(encryption).encode('utf-8'))

    verboseprint('DH parameters:', 
            'Prime number:', prime,
            'Primitive root:', base,
            'Secret:', secret,
            'Client public key:', public_key,
            'Server public key:', recv_server_key,
            'Secret key:',  secret_key)

    return secret_key


def receive_message():
    """Receive, decode, if required - decrypt - and display the message."""
    # Try to receive the message as long as the client exist.
    while True:
        try:
            verboseprint('Waiting for message...')
            # Receive message.
            text, recv_username = ja.decode_text(client_socket.recv(buf_size).decode())
            verboseprint('\nReceived message:', text,
                        'Username:', recv_username)
            # Don't show the message again, if it's from this client.
            if bytes(username, 'utf-8') == bytes(recv_username, 'utf-8'):
                continue
            # Get current encryption mode.
            global encryption
            # Decrypt message, if it's encrypted.
            if encryption != 'none':
                if encryption == 'xor':
                    text = encrypt.xor(text, secret_key)
                if encryption == 'cezar':
                    text = encrypt.caesar(text, secret_key, mode='decrypt')
            verboseprint('Used decryption mode:', encryption,
                        'Decrypted message:', text)
            # Display message in GUI.
            msg_list.insert(tkinter.END, recv_username + ': ' + text)
            # Autoscroll with text.
            msg_list.see('end')
        except OSError:
            # Break loop if unable to continue.
            break


def send_message(event=None):
    """Get message set in input box and send it to server."""
    # Get message from input box.
    text = my_msg.get()
    # Check, if message is longer than max_length.
    text_length = len(text.encode('utf-8'))
    max_length = 100
    if text_length > max_length:
        # Show info, that the encryption mode was successfully changed.
        msg_list.insert(tkinter.END, 'ERROR: Message is too long (over ' + str(max_length) + ' characters).')
        # Autoscroll with text.
        msg_list.see('end')
        return
    # Clear input box.
    my_msg.set('')
    # Call change_encryption(), if user requested changing encryption.
    if text.startswith('/encryption'):
        verboseprint('\nRequested changing encryption mode to:', text)
        change_encryption(text)
    else:
        verboseprint('\nSending message...')
        if text != '' and text != '/exit':
            # Display message in GUI instantly.
            msg_list.insert(tkinter.END, username + ': ' + text)
            # Autoscroll with text.
            msg_list.see('end')
        try:
            # Encrypt text, if encryption is set to other than 'none'.
            if encryption != 'none':
                # Encrypt with xor.
                if encryption == 'xor':
                    enc_text = encrypt.xor(text, secret_key)
                # Encrypt with cezar.
                if encryption == 'cezar':
                    enc_text = encrypt.caesar(text, secret_key)
                verboseprint('Used encryption mode:', encryption,
                            'Encrypted message sent:', text)
                # Send message.
                client_socket.send(ja.encode_text(enc_text, username).encode('utf-8'))
            # Send message, if encryption is 'none'.
            else:
                verboseprint('Message sent:', text)
                client_socket.send(ja.encode_text(text, username).encode('utf-8'))
        except:
            # Don't break the program, if for some reason user wants to quits before
            # completing client initialization.
            print('Complete setup first!')
            return
        # End program, if message is '/exit'.
        if text == '/exit':
            client_socket.close()
            top.quit()


def change_encryption(text):
    """Support changing encryption mode by writing /encryption X, where X is 
    selected new encryption mode."""
    # First verify, if the selected mode is supported.
    mode_doesnt_exist = 0
    for mode in encryption_modes:
        # True, if selected mode is supported.
        if bytes(text[12:], 'utf-8') == bytes(mode, 'utf-8'):
            global encryption
            # Select new mode, send it to server and display information in GUI.
            encryption = text[12:]
            client_socket.send(ja.request_encryption(encryption).encode('utf-8'))
            # Show info, that the encryption mode was successfully changed.
            msg_list.insert(tkinter.END, 'Encryption mode set to ' + encryption)
            # Autoscroll with text.
            msg_list.see('end')
        else:
            mode_doesnt_exist += 1
    # Display error, if selected mode doesn't exist.
    if mode_doesnt_exist is 3:
        msg_list.insert(tkinter.END, 'ERROR: Encryption mode doesnt exist.')
    verboseprint('Encryption mode set to:', encryption)


def on_window_close(event=None):
    """Default behaviour when user closes app window."""
    # Set message to /exit and call send_message().
    print('Closing application.')
    my_msg.set('/exit')
    send_message()


"""Main application"""
# Parse command-line arguments.
parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true')
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

# Set global variables for required items.
buf_size, addr, encryption_modes, encryption, username = init_app()

# Create socket.
client_socket = socket(AF_INET, SOCK_STREAM)
# Connect to given address.
client_socket.connect(addr)
verboseprint('\nConnected to %s:%s' % addr)
# Send initial message.
client_socket.send(ja.initial_message().encode('utf-8'))
verboseprint('Sent initial message:', ja.initial_message())
# Get secret key required for encryption.
secret_key = init_client(client_socket, buf_size, encryption)
# Send empty message (workaround for server requiring usernames)
client_socket.send(ja.encode_text('', username).encode('utf-8'))
# Define and start receiving thread.
receive_thread = Thread(target=receive_message)
receive_thread.start()
print('Initialization complete.')

"""GUI"""
# Initialize top-level widget.
top = tkinter.Tk()
# Make the window non-resizable.
top.resizable(False, False)
# Set window title.
top.title('Chat')
# Set frame for other widgets.
messages_frame = tkinter.Frame(top)
# Set variable that holds input messages and default it to empty.
my_msg = tkinter.StringVar()
my_msg.set('')
# Create scrollbar widget.
scrollbar = tkinter.Scrollbar(messages_frame)
# Create box that displays all messages.
msg_list = tkinter.Listbox(messages_frame, height=25, width=100, yscrollcommand=scrollbar.set, borderwidth=2)
# Pack scrollbar and messages list widgets together.
scrollbar.pack(side='right', fill='y')
msg_list.pack(side='left', expand=True, fill='both')
messages_frame.pack(expand=True, fill='both')
# Create input field.
entry_field = tkinter.Entry(top, textvariable=my_msg, borderwidth=2)
# Bind input field to 'ENTER'.
entry_field.bind('<Return>', send_message)
entry_field.pack(side='left', expand=True, fill='x')
# Create Send button that calls to send_message().
send_button = tkinter.Button(top, text='Send', command=send_message)
send_button.pack(side='left')
# Default behaviour when user closes app window.
top.wm_protocol('WM_DELETE_WINDOW', on_window_close)
# Start GUI.
tkinter.mainloop()