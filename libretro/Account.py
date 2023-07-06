from os.path import join as path_join
from os.path import exists as path_exists
from os.path import expanduser
from os import listdir as os_listdir
from os import mkdir as os_mkdir
from shutil import copyfile as shutil_copyfile
from time import strftime
import logging as LOG
from getpass import getpass

from libretro.Friend import Friend
from libretro.FriendDb import FriendDb
from libretro.crypto import RetroPrivateKey, RetroPublicKey


"""\
The Account class holds all information about a (single) retro
user account.

  ~/.retro/accounts/
  |__ <user-1>/                      # User directory
  |    |__ key.pem                   # Private keys
  |    |__ <username>.pem            # Public keys
  |    |__ downloads/
  |    |__ msgs/
  |    |__ friends/                  # Friends directory
  |        |__ alice.pem             # Pubkeys of friend 1
  |        |__ bob.pem               # Pubkeys of friend 2
  |
  |__ <user-2>/
      |__ key.pem
      |__ ...

"""
class Account:

	def __init__(self, config):
		"""
		Init account.
		Args:
		  config:    Config instance
		  username:  Username of account
		  password:  Account password
		"""
		self.conf    = config
		self.id      = None	# Account user ID
		self.name    = None	# Username
		self.pw      = None	# Password
		self.path    = None	# Account path
		self.key     = RetroPrivateKey()
		self.pubkey  = RetroPublicKey()
		self.friends = {}	# Key=userID, Value=Friend
		self.friendDb = None	# See FriendDb


	def load(self, username, password):
		"""
		Load account.

		Args:
		  username: Account's username
		  password: Password for private key

		Return:
		  True if successfully loaded, else False

		Throws:
		  FileNotFoundError, Exception
		"""
		LOG.info("Loading account '" + username +"' ...")

		self.path = path_join(self.conf.accounts_dir, username)
		if not path_exists(self.path):
			raise FileNotFoundError(
				"Account.load: No such account '{}' at {}"\
				.format(username, self.path))

		self.name = username
		self.pw   = password

		# Load users private and public rsa/ed25519 keys
		self.__load_keys()

		# Create frienddb for resolving userids to usernames
		friendDbPath  = path_join(self.path, "friends/friends.db")
		self.friendDb = FriendDb(friendDbPath, password)

		# Load all friends of this account
		self.load_friends()


	def load_friends(self):
		"""
		Load all friends of this account.
		1) Load userid/username dict from FriendDb
		   at accounts/USER/friends/friends.db
		2) Read all friends public keys from
		   accounts/USER/friends/*.pem
		3) Create dictionary with all friends where
		   the key is the friends userid and the value
		   the Friend object.
		"""

		id2name      = self.friendDb.get_all()
		friends_dir  = path_join(self.path, "friends")
		self.friends = {}

		LOG.debug("Looking for friends at " + friends_dir + " ...")

		for f in os_listdir(friends_dir):
			if not f.lower().endswith('.pem'):
				continue

			userid = f.rstrip('.pem')
			if userid not in id2name:
				LOG.error("No username for " + userid)
				continue

			# Resolve userid to username, load friend
			# and add to self.friends dict.
			username = id2name[userid]
			friend   = Friend()
			friend.load(
				id2name[userid],
				path_join(friends_dir, f))
			self.friends[friend.id] = friend


	def add_friend(self, username, pubkey_path):
		"""
		Add a new friend to this account.
		- Copy given keyfile to accounts/USER/friends/USERID.pem
		- Add entry to accounts/USER/friends/friends.db
		- Add friend to self.friends
		"""
		friend = Friend()
		friend.load(username, pubkey_path)

		dst = path_join(self.path, "friends/"+friend.id+".pem")
		shutil_copyfile(pubkey_path, dst)

		self.friendDb.add(friend.id, friend.name)
		self.friends[friend.id] = friend

		LOG.info("Added new friend name={} id={}".format(
			friend.name, friend.id))


	def get_friend_by_id(self, userid):
		"""
		Get friend by userid.
		Returns None if friend doesn't exist.
		"""
		return self.friends[userid]\
			if userid in self.friends\
			else None

	def get_friend_by_name(self, username):
		"""
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
			LOG.debug("Account.load: Load private key " + kpath)
			self.key.load(kpath, self.pw)

			# Since we don't know the name of the public keyfile
			# take the first '.pem' file that's not 'key.pem'.
			for f in os_listdir(self.path):
				if f.endswith('.pem') and f != 'key.pem':
					pkpath = path_join(self.path, f)
					LOG.debug("Account.load: Load public key " + pkpath)
					self.pubkey.load(pkpath)
					self.id = self.pubkey.get_keyid()

		except FileNotFoundError as e:
			raise FileNotFoundError("Account.load: " + str(e))
		except Exception as e:
			raise e


def validate_username(username):
	"""
	Validates given username.
	Raises:
	  ValueError: On invalid format
	"""
	l = len(username)

	# Length must be from 4 to 16.
	if l < 4 or l > 16:
		raise ValueError("Invalid username length ({}) "\
			"min={} max={}".format(l, 4, 16))

	# Name must start with alphabetic character
	if not username[0].isalpha():
		raise ValueError("Username must start with "\
			"alphabetic character")

	# Name must end with alphanumeric character
	if not username[-1].isalnum():
		raise ValueError("Username must end with "\
			"alphanumeric character")

	# All characters must be alphanumeric, '-' or '_'
	for c in username:
		if not c.isalnum() and c not in ('-', '_'):
			raise ValueError("Invalid character '{}'"\
				" in username '{}'".format(username, c))

def validate_password(password, min_length=8):
	"""
	Validate if given password is secure.

	>= 2 different lowercase charakters
	>= 2 different uppercase charakters
	>= 2 different numeric charakters
	>= 2 different special charakters

	Raises:
	  ValuError if password isn't secure
	"""
	chars = {
		'special'  : [],
		'numeric'  : [],
		'lowercase': [],
		'uppercase': []
	}

	if len(password) < min_length:
		raise ValueError("Password too short (min={})"\
				.format(min_length))
	for c in password:
		if c.isalpha() and c.islower():
			key = 'lowercase'
		elif c.isalpha() and c.isupper():
			key = 'uppercase'
		elif c.isnumeric():
			key = 'numeric'
		else:
			key = 'special'

		if c not in chars[key]:
			chars[key].append(c)

	for k,v in chars.items():
		if len(v) < 2:
			raise ValueError("Password needs at "\
				"least 2 different {} charakters"\
				.format(k))
	return True


def get_all_accounts(accounts_dir=None):
	"""
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


def create_new_account(accounts_dir=None):
	"""
	Create a new retro account (locally).

	1) Read username/password from user (stdin)
	2) Create account directory ~/.retro/accounts/<username>/
	3) Generate private/public keys (RSA, ED25519) and store them
	4) Create some directories (friends, downloads, msg)

	  ~/.retro/accounts/
	     |__ <username>
		  |__ key.pem
		  |__ <userid>.pem
		  |__ friends/
		  |__ msg/

	Args:
	  accounts_dir: Directory where accounts are located
			None? Use default path ~/.retro/accounts
	Return:
	  True on success, False on error

	"""

	# Read name from user and validate it
	try:
		username = input("Enter username: ")
		if not username: return False
		validate_username(username)
	except ValueError as e:
		print(str(e))
		return False
	except:
		return False

	# If no account dir is given, set to default
	# ~/.retro/accounts
	accdir = accounts_dir
	if not accdir:
		accdir = path_join(expanduser('~'),
				'.retro/accounts')
	userdir = path_join(accdir, username)

	# Check if ~/.retro/accounts exists
	if not path_exists(accdir):
		print("! No such directory: " + accdir)
		return False

	# Check if given username already exists (locally)
	if path_exists(userdir):
		print("! Account '{}' already exists".format(username))
		return False

	try:
		# Get account password
		pw = getpass("Enter password: ")
		if not pw: return False

		# Validate password
#TODO		validate_password(pw)

		# Let user repeat password
		pw2 = getpass("Repeat password: ")
		if not pw2 or pw != pw2:
			print("! Passwords mismatch")
			return False
	except Exception as e:
		print(str(e))
		return False

	# Create account dir
	os_mkdir(userdir)

	# Generate RSA and ED25519 keypair and store all keys.
	key = RetroPrivateKey()
	key.gen()

	path = path_join(userdir, 'key.pem')
	key.save(path, pw)

	pubkey = key.get_public()
	pkid   = pubkey.get_keyid()
	path   = path_join(userdir, pkid + '.pem')
	pubkey.save(path)

	# Create sub dirs ...
	os_mkdir(path_join(userdir, 'friends'))
	os_mkdir(path_join(userdir, 'msg'))


	print("\nCreated new retro account!\n")
	print(" Username: \033[1;33m" + username + "\033[0m")
	print(" Location: " + userdir)
	print()
	print("Now send your retro public key ({}) to luken@gmx.net\n"\
		"to finish the registration!\n".format(username+'.pem'))
	print(" Public key: \033[1;33m" + path + "\033[0m")
	print()

	return True


def chose_account_name(accounts_dir=None):
	"""
	Let user select account from list with all existing accounts.

	If there's just a single account, return that account name.
	If there are more than one account, print a list of all accounts
	and let user select one of them.

	Args:
	  accounts_dir: Path to account directory
	Return:
	  The username of selected account
	"""

	if not accounts_dir:
		accounts_dir = path_join(expanduser('~'),
				'.retro/accounts')

	users = os_listdir(accounts_dir)
	if not users:
		print("You don't have any accounts yet!")
		return None

	if len(users) == 1:
		# Just one account? Return it's name!
		return users[0]
	else:
		# More than one account? Select one!
		print("Select account\n")
		for i,u in enumerate(users):
			print(" [{}] {}".format(i,u))
		try:
			val = input("\nEnter account id: ")
			id  = int(val)
			return users[id]
		except:
			print("Invalid input '{}'".format(val))
			return None

