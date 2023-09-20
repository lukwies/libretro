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
AccountDb.py       User account database
Config.py          Client configs
crypto.py          Crypto and hash functions
Friend.py          Friend class
FriendDb.py        Encrypted sqlite3 db to resolve friendId's to names
MsgHandler.py      Create/Decrypt end2end messages
MsgStore.py        Message storage (encrypted sqlite)
net.py             Network functions (TLS)
RegKey.py          Registration key
RetroBot.py        Baseclass for creating bots
RetroClient.py     Central client context
</pre>

## Bot Example
Writing an own retro bot is really straight forward.
The only thing you need to do is to subclass `libretro.RetroBot`
and overwrite the method `handle_message()`.

<pre>
from libretro.RetroBot import RetroBot

class MyBot(libretro.RetroBot):
        def __init__(self):
                super().__init__()
                ...

        def handle_message(sender:Friend, text:str):
                # Here we do override the method that
                # is called after receiving a chatmsg.
                # In this case simply send the message
                # back to the sender...
                self.send_msg(sender, text)
</pre>

A bot needs an account just like a 'normal' user.
This is how to create one...
<pre>
bot = MyBot()
bot.create_account(regkey_file)
</pre>

To load the bot account call
<pre>
bot.load(username, password)
</pre>

Now, since the bot account is loaded you can either add
a friend (communication partner) ...
<pre>
bot.add_friend(friend_name, friend_id)
</pre>

... or run the bot's mainloop.
<pre>
bot.run()
</pre>


