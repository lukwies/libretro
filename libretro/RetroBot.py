"""\
 ___ ___ ___ ___ ____ ___  ____ ____
 |_/ |_   |  |_/ |  | |_/  |  |  |
 | \ |___ |  | \ |__| |__\ |__|  |

Using this class you can simply create a retro bot.
The only thing you need to do is to create a subclass
of RetroBot and override the method handle_message().

Example:

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

# Create bot account
bot = MyBot()
bot.create_account(regkey_file)

# Load bot account
bot.load(username, password)

# Add friend to bot account
bot.add_friend(friend_name, friend_id)

# Run bot mainloop
bot.run()

"""

import logging

from os      import listdir  as os_listdir
from os.path import join     as path_join

from libretro.protocol import *
from libretro.RetroClient import RetroClient
from libretro.Account import get_all_accounts
from libretro.AccountCreator import AccountCreator
from libretro.Friend import Friend

LOG = logging.getLogger(__name__)

class RetroBot:
	def __init__(self):
		"""\
		Init RetroBot.
		"""
		self.cli        = RetroClient() # RetroClient context
		self.conf       = self.cli.conf	# Config
		self.username   = None		# Username
		self.userid     = None		# User ID
		self.connected  = False		# Are we connected ?
		self.recvThread = None		# Receive thread
		self.done       = True		# Done?


	def create_account(self, regkey_file):
		"""\
		Create bot account.
		Args:
		  regkey_file: Registration keyfile
		Return:
		  True or False
		"""
		return AccountCreator().create_account(
				regkey_file, is_bot=True)


	def load(self, username:str, password:str):
		"""\
		Load the bot's retro account from ~/.retro/accounts/<username>
		and all other required directories and files...
		The follwing pathes are readed:

		  ~/.retro/config.txt
		  ~/.retro/server-cert.pem
		  ~/.retro/accounts/<username>/*

		Return:
		  True:  All files loaded
		  False: Failed to load files
		"""
		try:
			print("Loading bot account {}...".format(username))
			self.cli.load(username, password, is_bot=True)
			self.username = self.cli.account.name
			self.userid   = self.cli.account.id
			return True

		except Exception as e:
			LOG.error(str(e))
			return False


	def add_friend(self, username:str, userid:bytes):
		"""\
		Add friend to bot account.

		Args:
		  username: Name of new friend
		  userid:   Userid of new friend (8 byte)

		Return:
		  True on success, False on error
		"""
		if not self.__connect():
			return False

		self.cli.send_packet(Proto.T_GET_PUBKEY, userid)

		try:
			pckt = self.cli.recv_packet(timeout_sec=10)
		except Exception as e:
			LOG.error("Add Friend: "+str(e))
			return False

		if not pckt:
			LOG.error("Add Friend: timeout")
			return False
		elif pckt[0] == Proto.T_ERROR:
			LOG.error("Add Friend: "+pckt[1].decode())
			return False
		elif pckt[0] != Proto.T_PUBKEY:
			LOG.error("Add Friend: Invalid packet type {}"\
				.format(pckt[0]))
			return False

		userid2 = pckt[1][:8]
		pembuf  = pckt[1][8:]

		if userid != userid2:
			LOG.error("Wanted key of friend {}, but "\
				"got key of friend {}".format(
				userid, userid2))
			return False

		try:
			self.cli.account.add_friend(userid,
					username, pembuf)
		except Exception as e:
			LOG.error("Failed to add friend {}: {}"\
				.format(userid.hex(), e))
			return False
		LOG.info("Added friend {} ({})".format(
			username, userid.hex()))
		self.cli.close()
		return True


	def handle_message(self, sender:Friend, text:str):
		"""\
		Handle incoming chat message.
		This method MUST be implemented by the child class !!!
		"""
		pass


	def run(self):
		"""\
		Runs the main loop ...
		"""
		if not self.__connect():
			return

		while True:

			try:
				pckt = self.cli.recv_packet(
					timeout_sec=10)
			except KeyboardInterrupt:
				break
			except Exception as e:
				LOG.error("recv, " + str(e))
				break

			if pckt == False:
				continue
			elif not pckt:
				break
			elif pckt[0] == Proto.T_CHATMSG:
				self.__forward_chatmsg(pckt)
			else:
				LOG.warning("run: Invalid packet type ({})".format(pckt[0]))

		# Quitting ...
		self.cli.send_packet(Proto.T_GOODBYE)
		self.cli.close()


	def send_msg(self, friend:Friend, text:str):
		"""\
		Send end2end encrypted message to given friend.
		"""
		try:
			_,e2e_buf = self.cli.msgHandler.make_msg(friend, text)
			self.cli.send_packet(Proto.T_CHATMSG, e2e_buf)
		except Exception as e:
			LOG.error("send_msg: "+str(e))



	#-- PRIVATE --------------------------------------------------

	def __connect(self):
		"""\
		Connect to retro server.
		"""
		try:
			# Connect to server
			self.cli.connect()
			self.connected = True
			LOG.info("We are connected :-)")
		except Exception as e:
			LOG.error(str(e))
			self.connected = False
			return False

		# Send all friends to server to keep track of their
		# status (online/offline)
#		friend_ids = list(self.cli.account.friends.keys())
#		if friend_ids:
#			self.cli.send_packet(Proto.T_FRIENDS,
#				b''.join(friend_ids))

		return True


	def __forward_chatmsg(self, pckt):
		"""\
		Forward chat message (Proto.T_CHATMSG).
		This will call the user implemented handle_message()
		function.
		"""
		if not pckt[1]:
			LOG.error("No payload!")
			return False
		try:
			friend,msg = self.cli.msgHandler.decrypt_msg(
					pckt[0], pckt[1])

			# Call the user implemented function
			self.handle_message(friend, msg['msg'])

		except Exception as e:
			LOG.error("Forward chatmsg, "+str(e))
			return False
