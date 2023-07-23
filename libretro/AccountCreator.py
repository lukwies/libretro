from os.path import join as path_join
from os.path import exists as path_exists
from os.path import expanduser
from os import mkdir as os_mkdir
import logging
from getpass import getpass

from libretro.protocol import *
from libretro.Config import Config
from libretro.net import NetClient
from libretro.crypto import RetroPrivateKey, RetroPublicKey
from libretro.RegKey import RegKey


"""\
Create and register a new retro account.

1) Read registration key file
2) Connect to server and send regkey
3) if error quit, if success ...
4) Let user input name and password
5) Generate retro keys
6) Send public key to server
7) Create account dirtree

CLIENT                SERVER
  |---- T_REGISTER ---->|
  |     regkey (32)     |

  |<--- T_SUCCESS ------|
  |     userid (8)      |

  |---- T_PUBKEY ------>|
  |     pubkey (n)      |

  |<--- T_SUCCESS ------|



  ~/.retro/accounts/
     |__ <username>/            # User directory
        |__ key.pem             # Private keys
        |__ <userid>.pem	# Public keys
        |__ msgs/		# Messages
        |__ friends/            # Friends

"""

LOG = logging.getLogger(__name__)

class AccountCreator:

	def __init__(self):
		self.conf = Config()


	def create_account(self, regkey_file):
		"""\
		Create and register new account.

		1) Read regkey file
		2) Connect to server and send regkey
		3) if error quit, if success ...
		4) Read username and password
		5) Generate retro keys
		6) Send public key to server
		7) Create account dirtree

		Args:
		  regkey_file: Path to registration
			       keyfile.
		Return:
		  True on success, False on error
		"""

		# Connect to server, send regkey and
		# receive userid.
		conn, userid = self.__handshake(regkey_file)
		if not conn: return False

		# Read username of new account from user
		username = self.__read_username()
		if not username: return False

		# Read password from user (twice)
		password = self.__read_password()
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
			apath = path_join(self.conf.accounts_dir, username)
			os_mkdir(apath)
			os_mkdir(path_join(apath, "msg"))
			os_mkdir(path_join(apath, "friends"))

			# Save key pairs
			key.save(path_join(apath, "key.pem"), password)
			pubkey.save(path_join(apath, userid.hex()+".pem"))

			print(". Created Account \033[1;33m{}\033[0m"\
				.format(username))
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


	def __read_username(self):
		"""\
		Read usernam from userinput.
		This will also check if entered username already
		exists.
		"""
		try:
			username = input("Enter username: ")
			if not username: return None
#			validate_username(username)
		except KeyboardInterrupt:
			print("\n! Abort")
			return None
		except:
			print("! "+str(e))
			return None

		accpath = path_join(self.conf.accounts_dir,
				username)
		if path_exists(accpath):
			print("! You already have an account "\
				"named '" + username + "'")
			return None

		return username


	def __read_password(self, secure=True):
		try:
			pw = getpass("Enter password: ")
			if not pw: return None

#			if secure:
#				validate_password(pw)

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
		"""
		conn.send_packet(Proto.T_PUBKEY,
				pubkey.to_pem())

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


#rk = RegKey()
#rk.gen()
#rk.write_file("regkey.txt")


#ac = AccountCreator()
#ac.create_account("regkey.txt")
