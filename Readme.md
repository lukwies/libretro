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


## Files
<pre>
Account.py         User account
Config.py          Client configs
crypto.py          Crypto and hash functions
Friend.py          Friend class
FriendDb.py        Encrypted sqlite3 db to resolve friendId's to names
MsgHandler.py      Create/Decrypt end2end messages
MsgStore.py        Message storage (encrypted sqlite)
net.py             Network functions (TLS)
RetroClient.py     Central client context
</pre>

## Example
<pre>

from libretro.RetroClient import *

# Create client context
retroClient = RetroClient()

# Load client account
if not retroClient.load(username, password):
	return

# Connect to server
try:
	retroClient.connect()
except Exception as e:
	print(str(e))
	return

# Send some bytes
retroClient.send(b'Hello World')

# Receive a dictionary
try:
	recv_dict = retroClient.recv_dict(
		keys=['baz','buz'],
		timeout_sec=10)
except Exception as e:
	print(str(e))
	return

# Close connection
retroClient.close()
</pre>
