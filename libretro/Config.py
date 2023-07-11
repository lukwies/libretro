import configparser
from os.path import join   as path_join
from os.path import exists as path_exists
from os.path import expanduser
import logging as LOG

import traceback


"""\
Basic configs
"""

RETRO_MAX_FILESIZE = 0x40000000

class Config:
	def __init__(self, basedir=None):

		if not basedir:
			basedir = path_join(expanduser('~'),
					'.retro')

		self.basedir      = basedir
		self.config_file  = path_join(self.basedir, "config.txt")
		self.accounts_dir = path_join(self.basedir, "accounts")
		self.download_dir = self.__get_download_dir()

		# [default]
		self.loglevel     = LOG.INFO
		self.logformat    = '%(levelname)s  %(message)s'
		self.logfile      = path_join(self.basedir, 'log.txt')
		self.recv_timeout = 5

		# [server]
		self.server_address   = "127.0.0.1"
		self.server_hostname  = self.server_address
		self.server_port      = 8443
		self.server_fileport  = 8444
		self.server_audioport = 8445
		self.server_certfile  = path_join(self.basedir, 'server-cert.pem')


	def load(self):
		"""\
		Read config file "basedir/config.txt"

		Raises:
		  Exception: If failed to open/read config file
		"""
		try:
			LOG.debug("Loading configs from " + self.config_file)
			conf = configparser.ConfigParser()
			conf.read(self.config_file)

			# [default]
			self.loglevel = self.loglevel_string_to_level(
						conf.get('default', 'loglevel',
							fallback='DEBUG'))
			self.logfile  = conf.get('default', 'logfile',
					fallback=self.logfile)
			self.logformat = conf.get('default', 'logformat',
					fallback=self.logformat)
			self.recv_timeout = conf.get('default',
					'recv_timeout',
					fallback=self.recv_timeout)

			# [server]
			self.server_address = conf.get('server', 'address',
						fallback=self.server_address)
			self.server_port = conf.getint('server', 'port',
						fallback=self.server_port)
			self.server_fileport = conf.getint('server',
						'fileport',
						fallback=self.server_fileport)
			self.server_audioport = conf.getint('server',
						'audioport',
						fallback=self.server_audioport)
			self.server_hostname = conf.get('server', 'hostname',
						fallback=self.server_hostname)
			self.server_certfile = conf.get('server', 'certificate',
						fallback=self.server_certfile)
			return True
		except configparser.NoOptionError as e:
			raise Exception("Config.load: " + str(e))
		except Exception as e:
			raise Exception("Config.load: " + str(e))
#			LOG.error("Reading config file '"+self.config_file+"'")
#			LOG.error("Config: " + str(e))
#			traceback.print_exc()
#			return False


	def debug(self):
		LOG.debug("SETTINGS:")
		LOG.debug("[default]")
		LOG.debug("  loglevel       = {}".format(self.loglevel))
		LOG.debug("  logfile        = {}".format(self.logfile))
		LOG.debug("  logformat      = '{}'".format(self.logformat))
		LOG.debug("  recv_timeout   = {}".format(self.recv_timeout))
		LOG.debug("[server]")
		LOG.debug("  address        = {}".format(self.server_address))
		LOG.debug("  hostname       = {}".format(self.server_hostname))
		LOG.debug("  port           = {}".format(self.server_port))
		LOG.debug("  fileport       = {}".format(self.server_fileport))
		LOG.debug("  audioport      = {}".format(self.server_audioport))


	def loglevel_string_to_level(self, loglevel_str):
		"""\
		Return loglevel from string.
		Supported strings: 'ERROR', 'WARN', 'INFO',
				   'DEBUG'
		Return:
			Loglevel
		Raise:
			ValueError: If unsupported level string
		"""
		levels = {
			'error'   : LOG.ERROR,
			'warning' : LOG.WARNING,
			'info'    : LOG.INFO,
			'debug'   : LOG.DEBUG
		}
		levstr = loglevel_str.lower()
		if levstr not in levels:
			raise ValueError("Invalid loglevel string '{}'"\
				.format(loglevel_str))
		else:
			return levels[levstr]




	def __get_download_dir(self):
		home = expanduser('~')
		check_dirs = ["downloads", "Downloads"]

		for dir in check_dirs:
			path = path_join(home, dir)
			if path_exists(path):
				return path

		# No valid download directory, create our own
		# one at ~/.retro/downloads
		path = path_join(home, ".retro/downloads")
		os_mkdir(path)
		return path
