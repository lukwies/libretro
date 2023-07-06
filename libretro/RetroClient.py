from os.path import exists as path_exists
from os.path import join as path_join
from os.path import expanduser
from os import mkdir as os_mkdir
from os import listdir as os_listdir
from sys import exit as sys_exit
from getpass import getpass
import configparser as confparse
import logging as LOG
from base64 import b64encode

from libretro.net import TLSClient
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


config-file (~/.retro/config.txt)
	[server]
	address = ADDRESS
	port = PORT
	certificate = PATH
	hostname = STRING

"""


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


	def load(self, username, password):
		"""\
		Load all settings.
		NOTE: Call this before running any other functions.

		1. Read base configs from ~/.retro/config.txt
		2. Read account infos from ~/.retro/accounts/USER
		"""
		# Get server settings from config.txt
		if not self.conf.load():
			return False

		# Init logging
		if self.conf.logfile:
			LOG.basicConfig(level=self.conf.loglevel,
					format=self.conf.logformat,
					filename=self.conf.logfile,
					filemode='w',
					encoding='utf-8')
		else:
			LOG.basicConfig(level=self.conf.loglevel,
					format=self.conf.logformat)

		return self.load_account(username, password)


	def load_account(self, username, password):
		"""\
		(Re)load account
		"""

		# Setup TLS client
		self.conn = TLSClient(
				self.conf.server_address,
				self.conf.server_port,
				self.conf.server_hostname,
				self.conf.server_certfile)

		# Load account settings, friends, ...
		self.account = Account(self.conf)
		self.account.load(username, password)

		# connect everything
		self.msgHandler = MsgHandler(self.account)
		self.msgStore   = MsgStore(self.account)
		return True


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
		sig   = self.account.key.sign(nonce, True)

		# Send the username to the server
		self.conn.send_dict({
			'type'  : 'login',
			'user'  : self.account.id,
			'nonce' : b64encode(nonce).decode(),
			'sig'   : sig.decode()
			})

		# Receive encrypted random value
		res = self.conn.recv_dict(['type'],
			timeout_sec=self.conf.recv_timeout)
		if res == None:
			raise Exception("Receive timeout")
		elif res['type'] == 'error':
			raise Exception(res['msg'])
		elif res['type'] != 'welcome':
			raise Exception(
				"Received invalid type '"+res['type']+"'")

		LOG.info("Connected to {}:{}".format(self.conn.host,self.conn.port))
		LOG.info(res['msg'])


	def send(self, data):
		return self.conn.send(data)

	def send_dict(self, dct):
		return self.conn.send_dict(dct)


	def recv(self, recv_size=2048, timeout_sec=None):
		return self.conn.recv(recv_size=recv_size,
				timeout_sec=timeout_sec)

	def recv_dict(self, keys=['type'], timeout_sec=None):
		return self.conn.recv_dict(force_keys=keys,
				timeout_sec=timeout_sec)


	def close(self):
		if self.conn:
			self.conn.close()

	def get_hoststr(self):
		# Get "hostname":"port"
		return self.conn.host + ":" + str(self.conn.port)

