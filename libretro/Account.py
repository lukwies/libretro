from os.path import join as path_join
from os.path import exists as path_exists
from os.path import expanduser
from os import listdir as os_listdir
from os import remove as os_remove
from os import mkdir as os_mkdir

import logging
from getpass import getpass

from libretro.AccountDb import AccountDb
from libretro.Friend import Friend
from libretro.FriendDb import FriendDb
from libretro.crypto import RetroPrivateKey
from libretro.crypto import derive_key, read_salt_from_file

LOG = logging.getLogger(__name__)

"""\
The Account class holds all information about a (single) retro
user account.

Each account is identified by a unique 8 byte userid, created
while account registration.

Files:

  ~/.retro/accounts/
     |__ <username>/       	# User directory
     |    |__ .salt		# Saltfile
     |    |__ account.db	# Account database
     |    |__ friends.db	# Friends database
     |    |__ msg/	        # Dir with msgdbs
     |        |__ ...
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
		self.mk        = None	# Master key
		self.path      = None	# Account path
		self.key       = RetroPrivateKey() # Private keys
		self.friendDb  = None	# See FriendDb
		self.friends   = {}	# Key=userID, Value=Friend


	def load(self, username, password, is_bot=False):
		"""\
		Load user account.

		Args:
		  username: Account's username
		  password: Account password
		  is_bot:   Account is a bot account?

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
			raise FileNotFoundError("Account.load: "\
				"No such account '{}' at {}"\
				.format(username, self.path))

		self.is_bot = is_bot

		# Load salt from saltfile and derive master key
		salt_file = path_join(self.path, ".salt")
		salt = read_salt_from_file(salt_file)
		self.mk = derive_key(password, salt, 16).hex()

		# Load userid, username and keys from account db
		accDb = AccountDb(self.path)
		self.id,self.name,self.key = accDb.select(self.mk)

		# After loading the account database, the masterkey
		# is updated to avoid holding the real key in memory.
		self.mk = derive_key(self.mk, salt, 16, 200000).hex()

		# Init friends database
		self.friendDb = FriendDb(self)

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
					self.path)
		friend.pubkey.load_pem_string(pk_pembuf.decode())
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
			path_join(self.path, "msg"),
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

