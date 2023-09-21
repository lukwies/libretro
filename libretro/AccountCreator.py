from os.path import join as path_join
from os.path import exists as path_exists
from os import mkdir as os_mkdir
from getpass import getpass
import logging

from libretro.protocol import *
from libretro.Config import Config
from libretro.net import NetClient
from libretro.AccountDb import AccountDb
from libretro.crypto import RetroPrivateKey, RetroPublicKey
from libretro.crypto import random_buffer, derive_key, create_salt_file
from libretro.RegKey import RegKey

"""\
Create and register a new retro account which can either be
a normal user account or a bot account.


# Account directory of normal users

  ~/.retro/accounts/<username>
     |__ .salt		# Salt file
     |__ account.db	# Account database
     |__ friends.db	# Friends database
     |__ msg/		# Holds all message dbs

# Account directory of bots

  ~/.retro/bots/<botname>
     |__ .salt		# Salt file
     |__ account.db	# Account database
     |__ friends.db	# Friends database

"""

LOG = logging.getLogger(__name__)

class AccountCreator:

	def __init__(self):
		"""\
		Initialize AccountCreator.
		"""
		self.conf     = Config()
		self.acc_path = self.conf.accounts_dir


	def create_account(self, regkey_file, is_bot=False,
			validate_password=False):
		"""\
		Create and register new user or bot account.
		NOTE: This will ask user to enter some values

		Args:
		  regkey_file: Path to registration keyfile.
		  is_bot:      Account is bot?

		Return:
		  True on success, False on error
		"""

		if is_bot:
			# If creating a bot account, the account
			# path will be ~/.retro/bots/
			self.acc_path = self.conf.bots_dir

			# Create ~/.retro/bots if not exists
			if not path_exists(self.acc_path):
				os_mkdir(self.acc_path)

		# Connect to server, send regkey and
		# receive userid.
		conn, userid = self.__handshake(regkey_file)
		if not conn: return False

		# Read user/botname from user
		username = self.__read_username(is_bot)
		if not username: return False

		# Read password from user (repeat)
		password = self.__read_password(validate_password)
		if not password: return False

		# Generate retro keypair
		key,pubkey = self.__gen_keys()
		if not key: return False

		# Send public key to server a
		ok = self.__send_pubkey(conn, pubkey)
		if not ok: return False

		conn.close()

		try:
			# Create directories
			accpath = path_join(self.acc_path, username)
			os_mkdir(accpath)

			# Create random salt and store it. Then derive
			# masterkey from password and salt.
			salt_file = path_join(accpath, ".salt")
			salt = create_salt_file(salt_file, saltlen=32)
			master_key = derive_key(password, salt, 16).hex()

			# Create encrypted account database
			db = AccountDb(accpath)
			db.create(master_key, userid, username, key)

			# Create friend directory
			if not is_bot:
				# The message directory is only for
				# non-bot accounts.
				os_mkdir(path_join(accpath, "msg"))

			print(". Created {}Account \033[1;33m{}\033[0m"\
				.format("Bot " if is_bot else "", username))
			return True

		except Exception as e:
			print("! create_account: "+str(e))
			return False


	def __handshake(self, regkey_file):
		"""\
		Connects to the retro server, sends
		the registration key and receives the
		userid for the new account on success.
		Args:
		  regkey_file: Path to registration keyfile
		Return:
		  conn, userid
		"""
		try:
			# Load configs (Needed for server settings)
			self.conf.load()
		except Exception as e:
			print("! Load config: " + str(e))
			return None,None

		regkey = RegKey()
		conn   = NetClient(
			self.conf.server_address,
			self.conf.server_port,
			self.conf.server_hostname,
			self.conf.server_certfile)
		try:
			# Load registration key
			regkey.read_file(regkey_file)
		except Exception as e:
			print("! Regkey.load: "+str(e))
			return None,None

		try:
			# Connect to server and send regkey
			conn.connect()
			conn.send_packet(Proto.T_REGISTER,
				regkey.bytes())
		except Exception as e:
			print("! Failed to connect: "+str(e))
			return None,None

		try:
			# Receive response that should be
			# either T_SUCCESS or T_ERROR.
			pckt = conn.recv_packet(timeout_sec=5)
		except Exception as e:
			print("! Failed to receive response: "\
				+str(e))
			return None,None

		if not pckt:
			print("! Receive timeout")
		elif pckt[0] == Proto.T_ERROR:
			print("! Server: "+pckt[1].decode())
		elif pckt[0] != Proto.T_SUCCESS:
			print("! Invalid packet type {}".format(pckt[0]))
		else:
			userid = pckt[1]
			print(". Handshake done, userid="+userid.hex())
			return conn, userid

		conn.close()
		return None,None


	def __read_username(self, is_bot=False):
		"""\
		Read user- or botname for userinput.
		This will check if the account already exists.

		Args:
		  is_bot: Account is bot?

		Return:
		  True or False
		"""
		try:
			prompt = "Enter botname: " if is_bot else "Enter username: "
			username = input(prompt)
			if not username: return None
		except KeyboardInterrupt:
			print("\n! Abort")
			return None
		except:
			print("! "+str(e))
			return None

		try:
			# Validate username
			AccountCreator.validate_username(username)
		except Exception as e:
			print("! " +str(e))
			return None

		accpath = path_join(self.acc_path, username)
		if path_exists(accpath):
			print("! Account {} already exists".format(username))
			print("! Account-path: " + accpath)
			return None

		return username


	def __read_password(self, validate=False):
		"""\
		Read password from userinput.
		This will ask the user to enter the password twice
		to avoid misstyping.

		Args:
		  validate: Validate if password is secure?
		Return:
		  The password on success, None on error
		"""
		try:
			pw = getpass("Enter password: ")
			if not pw: return None

			# Validate if is secure password?
			if validate:
				try:
					AccountCreator.validate_password(pw)
				except Exception as e:
					print("! "+str(e))
					return None

			pw2 = getpass("Repeat password: ")
			if not pw2 or pw != pw2:
				print("! Passwords mismatch")
				return None
			return pw

		except Exception as e:
			print(str(e))
			return None

	def __gen_keys(self):
		"""\
		Generate RSA and ED25519 keypairs.
		"""
		key = RetroPrivateKey()
		key.gen()
		pubkey = key.get_public()
		return key, pubkey


	def __send_pubkey(self, conn, pubkey):
		"""\
		Send public key to server and receive
		either T_SUCCESS or T_ERROR.

		Args:
		  conn:   Connection
		  pubkey: RetroPubliKey instance

		Return:
		  True or False
		"""
		conn.send_packet(Proto.T_PUBKEY,
			pubkey.get_pem_string().encode())

		pckt = conn.recv_packet(timeout_sec=10)

		if not pckt:
			print("! Send pubkey: Timeout")
		elif pckt[0] == Proto.T_ERROR:
			print("! Send pubkey: Server: " +pckt[1].decode())
		elif pckt[0] != Proto.T_SUCCESS:
			print("! Send pubkey: Invalid packet type {}"\
				.format(pckt[0]))
		else:	return True

		return False


	@staticmethod
	def validate_username(username, min_len=3, max_len=12):
		"""\
		Validates given username.
		Raises:
		  ValueError: On invalid format
		"""
		l = len(username)

		if l < min_len or l > max_len:
			# Length must be in min_len,max_len
			raise ValueError("Username '{}' has "\
				"invalid length {}".forat(
				username, l))
		elif not username.isalnum():
			# Only alpha-numeric characters allowed
			raise ValueError("Username '{}' contains "\
				"invalid characters")
		elif not username[0].isalpha():
			# Name must start with alphabetic character
			raise ValueError("Username must start with "\
				"alphabetic character")


	@staticmethod
	def validate_password(password, min_length=8):
		"""\
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
