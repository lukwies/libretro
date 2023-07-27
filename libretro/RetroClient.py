import logging

from libretro.protocol import *
from libretro.net import NetClient
from libretro.crypto import random_buffer

from libretro.Config import Config
from libretro.Account import Account
from libretro.Friend import Friend
from libretro.MsgHandler import MsgHandler
from libretro.MsgStore import MsgStore

"""\
Requires the following directory tree:

~/.retro/
  |__ config.txt			# Base config (server settings)
  |__ server-cert.pem			# Server certificate
  |__ accounts/				# All accounts
      |__ <username>/			# User directory
          |__ key.pem			# Private key
          |__ <userID>.pem		# Public key
	  |
          |__ friends/			# Friends directory
              |__ <userID1>.pem		# Pubkey of friend 1
              |__ <userID2>.pem		# Pubkey of friend 2
	      |__ ...

config-file (~/.retro/config.txt)
	[server]
	address = ADDRESS
	port = PORT
	certificate = PATH
	hostname = STRING

"""

LOG = logging.getLogger()

class RetroClient:

	def __init__(self):
		"""
		Create a retro client.
		"""
		self.conf       = Config()  # Base configs
		self.conn       = None	# TLS connection context
		self.account    = None	# User account
		self.msgHandler = None	# Message handler
		self.msgStore   = None	# Message storage


	def load(self, username, password, is_bot=False):
		"""\
		Load all settings.

		NOTE: Call this before running any other functions.
		NOTE: This will also setup the root logger.

		1. Read base configs from ~/.retro/config.txt
		2. Read account infos from ~/.retro/accounts/USER

		Args:
		  username: Name of account user
		  password: Account password
		  is_bot:   Is bot account?

		Raises:
		  Exception: If failed to load config, account, ...
		"""
		# Get server settings from config.txt
		self.conf.load()

		# Init logging
		logfile = self.conf.logfile
		if is_bot: logfile = logfile.replace('.txt', '.bot.txt')

#		fh = logging.StreamHandler(sys.stdout)
		fh = logging.FileHandler(logfile, mode='w')
		fh.setLevel(self.conf.loglevel)

		formatter = logging.Formatter(
				"%(asctime)s  %(levelname)s  "\
				"%(name)s  %(message)s",
				datefmt="%H:%M:%S")
		fh.setFormatter(formatter)

		LOG.setLevel(self.conf.loglevel)
		LOG.addHandler(fh)

		# Load account
		self.load_account(username, password, is_bot)


	def load_account(self, username, password, is_bot=False):
		"""\
		(Re)load account
		"""

		# Setup TLS client
		self.conn = NetClient(
				self.conf.server_address,
				self.conf.server_port,
				self.conf.server_hostname,
				self.conf.server_certfile)

		# Load account settings, friends, ...
		self.account = Account(self.conf)
		self.account.load(username, password, is_bot)

		# connect everything
		self.msgHandler = MsgHandler(self.account)
		self.msgStore   = MsgStore(self.account)


	def connect(self):
		"""\
		Connect to server and perform handshake.
		Raises:
		  Exception
		"""

		# Establish TLS connection
		self.conn.connect()

		# Create random nonce and sign it with our
		# private key.
		nonce = random_buffer(32)
		signature = self.account.key.sign(nonce)

		try:
			# Send T_HELLO packet
			self.conn.send_packet(
				Proto.T_HELLO,
				self.account.id,
				nonce,
				signature)

			# Receive encrypted random value
			res = self.conn.recv_packet(
				timeout_sec=self.conf.recv_timeout)
		except: raise

		if not res:
			raise Exception("Timeout")
		elif res[0] == Proto.T_ERROR:
			raise Exception(res[1].decode())
		elif res[0] != Proto.T_SUCCESS:
			raise Exception("Invalid protocol "\
				"type ({})".formt(res[0]))


	def send(self, data):
		self.conn.send(data)

	def send_packet(self, pckt_type, *data):
		self.conn.send_packet(pckt_type, *data)


	def recv(self, recv_size=2048, timeout_sec=None):
		return self.conn.recv(recv_size=recv_size,
				timeout_sec=timeout_sec)

	def recv_packet(self, timeout_sec=None):
		return self.conn.recv_packet(timeout_sec=timeout_sec)


	def close(self):
		if self.conn:
			self.conn.close()

	def get_hoststr(self):
		# Get "hostname":"port"
		return self.conn.tostr()

