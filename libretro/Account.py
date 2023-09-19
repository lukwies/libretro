from os.path import join as path_join
from os.path import exists as path_exists
from os.path import expanduser
from os import listdir as os_listdir
from os import remove as os_remove
from os import mkdir as os_mkdir

import logging
from getpass import getpass

from libretro.Friend import Friend
from libretro.FriendDb import FriendDb
from libretro.crypto import RetroPrivateKey, RetroPublicKey

LOG = logging.getLogger(__name__)

"""\
The Account class holds all information about a (single) retro
user account.

Each account is identified by a unique 8 byte userid, created
while account registration.

Files:

  ~/.retro/accounts/
  |__ <user-1>/                      # User directory
  |    |__ key.pem                   # Private keys
  |    |__ <username>.pem            # Public keys
  |    |__ downloads/
  |    |__ friends/                  # Friends directory
  |        |__ friends.db            # Friends database
  |        |__ msg/	             # Dir with msgdbs
  |            |__ <friend1msgdb>    # Msg database file 1
  |            |__ ...
  |
  |__ <user-2>/
      |__ key.pem
      |__ ...

"""
class Account:

	def __init__(self, config):
		"""\
		Init account.
		Args:
		  config:    Config instance
		"""
		self.conf      = config	# Config context
		self.is_bot    = False	# Is bot account?
		self.id        = None	# User ID (8 byte)
		self.name      = None	# Username
		self.pw        = None	# Password
		self.path      = None	# Account path
		self.key       = RetroPrivateKey()
		self.pubkey    = RetroPublicKey()
		self.frienddir = None	# Friends directory
		self.friendDb  = None	# See FriendDb
		self.friends   = {}	# Key=userID, Value=Friend


	def load(self, username, password, is_bot=False):
		"""\
		Load user account.

		Args:
		  username: Account's username
		  password: Password for private key
		  is_bot:   Account is a bot account

		Return:
		  True if successfully loaded, else False

		Throws:
		  FileNotFoundError, Exception
		"""
		LOG.info("Loading account '" + username +"' ...")

		# If account is a bot-account, it is stored
		# at ~/.retro/bots/ otherwise at ~/.retro/accounts/
		accdir = self.conf.bots_dir if is_bot \
			 else self.conf.accounts_dir
		self.path = path_join(accdir, username)

		if not path_exists(self.path):
			# raise RetroAccountNotFound()
			raise FileNotFoundError(
				"Account.load: No such account '{}' at {}"\
				.format(username, self.path))

		self.is_bot = is_bot
		self.name   = username
		self.pw     = password

		# Load users private and public rsa/ed25519 keys
		self.__load_keys()

		self.frienddir = path_join(self.path, "friends")

		# Create frienddb for resolving userids to usernames
		dbpath  = path_join(self.frienddir, "friends.db")
		self.friendDb = FriendDb(dbpath, password)

		# Load all friends of this account
		self.load_friends()


	def load_friends(self):
		"""\
		Load all friends of this account from the friends
		sqlite database (see FriendDb.py).
		"""
		self.friends = self.friendDb.load_all()


	def add_friend(self, userid, username, pk_pembuf):
		"""\
		Add a new friend to this account.

		Args:
		  userid:    New friends userid (8 byte)
		  username:  Name of new friend (string)
		  pk_pembuf: PEM buffer of friends pubkey (bytes)

		Raises:
		  Exception if:
		  - Invalid pubkey format
		  - failed to add entry to friendDb
		"""
		friend = Friend()
		friend.id = userid
		friend.name = username
		friend.msgdbname = FriendDb.get_random_dbname(
					self.frienddir)

		LOG.debug("LOAD PUBKEY FROM PEM BUF\n{}\n".format(pk_pembuf))
		friend.pubkey.load_string(pk_pembuf.decode())

		self.friendDb.add(friend)
		self.friends[friend.id] = friend


	def delete_friend(self, userid):
		"""\
		Delete friend from account.
		- Delete entry from friendDb
		- Delete all messages
		- Remove friends from self.friends
		"""
		if userid not in self.friends:
			raise Exception("No such friend {}"\
				.format(userid.hex()))

		friend = self.friends[userid]

		self.friendDb.delete_by_id(friend.id)

		dbpath = path_join(
			path_join(self.frienddir, "msg"),
			friend.msgdbname)

		# Msg database might not exist
		try:	os_remove(dbpath)
		except:	pass

		self.friends.pop(userid)


	def get_friend_by_id(self, userid):
		"""\
		Get friend by userid.
		Returns None if friend doesn't exist.
		"""
		return self.friends[userid]\
			if userid in self.friends\
			else None

	def get_friend_by_name(self, username):
		"""\
		Get friend by username.
		Returns None if friend doesn't exist.
		"""
		for friend in self.friends.values():
			if friend.name == username:
				return friend
		return None

	def __load_keys(self):
		# Load users private and public rsa/ed25519 keys
		try:
			kpath = path_join(self.path, "key.pem")
			LOG.debug("Load private key " + kpath)
			self.key.load(kpath, self.pw)

			pk_loaded = False
			# Since we don't know the name of the public keyfile
			# take the first '.pem' file that's not 'key.pem'.
			# The name of that file also is the account id (in hex).
			for f in os_listdir(self.path):
				if f.endswith('.pem') and f != 'key.pem':

					# Set account id
					hexid = f.replace('.pem', '')
					self.id = bytes.fromhex(hexid)

					pkpath = path_join(self.path, f)
					LOG.debug("Load public key " + pkpath)
					self.pubkey.load_file(pkpath)
					pk_loaded = True
			if not pk_loaded:
				raise FileNotFoundError("No pubkey found in "+self.path)

		except FileNotFoundError as e:
			raise FileNotFoundError("Account.load_keys: " + str(e))
		except Exception as e:
			raise Exception("Account.load_keys: " + str(e))

	# TODO
	"""
	def __load_account_config(self):
		try:
			confpath = path_join(self.path, "config.txt")
			conf = configparser.ConfigParser()
			conf.read(confpath)

			self.name = conf.get("Account", "username")
			self.idx  = conf.get("Account", "userid")
			self.id   = bytes.fromhex(self.useridx)
		except configparser.NoOptionError as e:
			raise Exception("Load account config, "+str(e))
		except:
			raise
	"""


def get_all_accounts(accounts_dir=None):
	"""\
	Get list with all account names.
	If no account dirpath is given we use the default
	path: ~/.retro/accounts
	Returns None if failed to open accounts directory.
	"""
	if not accounts_dir:
		accounts_dir = path_join(expanduser('~'),
				'.retro/accounts')
	try:
		accounts = os_listdir(accounts_dir)
		return accounts
	except:	return None



def chose_account_name(is_bot=False):
	"""\
	Let user select (bot)account from list with all existing accounts.

	If there's just a single account, return that account name.
	If there are more than one account, print a list of all accounts
	and let user select one of them.

	Args:
	  is_bot: Account is bot account?
	Return:
	  The username of selected account
	"""

	if is_bot:
		accdir = path_join(expanduser('~'),
				'.retro/bots')
	else:	accdir = path_join(expanduser('~'),
				'.retro/accounts')

	users = os_listdir(accdir)
	if not users:
		print("You don't have any accounts yet!")
		return None

	if len(users) == 1:
		# Just one account? Return it's name!
		return users[0]
	else:
		# More than one account? Select one!
		if is_bot: print("Select bot\n")
		else: print("Select account\n")

		for i,u in enumerate(users):
			print(" [{}] {}".format(i,u))
		try:
			val = input("\nEnter account id: ")
			id  = int(val)
			return users[id]
		except:
			print("Invalid input '{}'".format(val))
			return None

