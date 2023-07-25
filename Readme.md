# libretro

Core library of the retro end2end encrypted terminal messenger.


## Install
Installing libretro:
<pre>
$ pip install .
</pre>

Installing libretro in development mode:
<pre>
$ pip install -e .
</pre>

## Uninstall
<pre>
$ pip uninstall libretro
</pre>


## Modules
<pre>
Account.py         User account
Config.py          Client configs
crypto.py          Crypto and hash functions
Friend.py          Friend class
FriendDb.py        Encrypted sqlite3 db to resolve friendId's to names
MsgHandler.py      Create/Decrypt end2end messages
MsgStore.py        Message storage (encrypted sqlite)
net.py             Network functions (TLS)
RegKey.py          Registration key
RetroClient.py     Central client context
</pre>

## Example
<pre>

from libretro.RetroClient import *

# Create client context
retroClient = RetroClient()

# Load client account
retroClient.load(username, password)

# Connect to server
retroClient.connect()

# Send some bytes
retroClient.send(b'Hello World')

# Receive a packet
pckt = retroClient.recv_packet()

print("Packet Type: {}".format(pckt[1]))
if pckt[1]:
    print("Packet Data: " + pckt[1])

# Close connection
retroClient.close()
</pre>
