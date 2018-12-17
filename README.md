# Client-server Chat

## Introduction

This is a client-server chat system. It allows for simple, encrypted communication between multiple users at once.

#### Main Features:

* Uses predefined JSON strings format to communicate between client and server
    * Client requests keys from the server
    * Server sends DH parameters to the client
    * Client/server send their public keys to each other
    * *Optionally, client requests encryption mode*
    * Client/server exchange messages
* Supports Diffie-Hellman secure key exchange
* Supports plain text messaging
* Supports XOR cipher
* Supports Caesar cipher

#### Server-only features:

* Supports multiple clients at once
* Dynamic generating of DH parameters for each client
* Supports different encryption modes per client at once
* Support on-the-fly encryption mode changing

#### Client-only features:

* Connect to any server that supports predefined JSON strings format
* Generate random username, if it wasn't chosen by the user

## Requirements

* Python 3.5+ *(required by math.gcd)*
* *PyInstaller (optional, only used for building executable files)*

During development, I tested the software using Python 3.7.1 on Windows 10.

## Instructions

1) Make sure you have python executable in your PATH environment variable.
2) Clone the repository and cd into it.
3) To start the server, execute:
```
python server.py
```
4) To display available server command-line arguments, append -h or --help to the above command.
```
python server.py -h
usage: server.py [-h] [-v] [--ip [x.x.x.x]] [--port [N]]

optional arguments:
  -h, --help      show this help message and exit
  -v, --verbose   show additional info during runtime
  --ip [x.x.x.x]  choose ip to listen on
  --port [N]      choose port to listen on
```
5) To start the client, execute:
```
python client.py
```
6) To display additional information in the console, append -v or --verbose to the above command.

During start-up, client supports:
* custom host IP and port
* choosing encryption mode by entering correct number
* choosing username

Commands available in client GUI:
* /exit
* /encryption X (X is one of the supported encryption modes: none, xor, cezar)

## Building

Building executable files is optional, scripts can be run directly from *.py files.

1) Make sure you have PyInstaller installed.
2) To build executable files, run:
```
build.bat
```
or
```
pyinstaller --onefile client.py
pyinstaller --onefile server.py
```
3) Executables will be located under **dist** folder.