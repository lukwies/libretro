from os.path import basename as path_basename
from os.path import join as path_join
from os import listdir as os_listdir
import logging

from libretro.crypto import RetroPublicKey


LOG = logging.getLogger(__name__)

"""\
A friend is another peer within the retro network,
of whom we already know the public-key and username.

All friend information is stored in an encryted sqlite
database (FriendDB.py).

Files:
  ~/.retro/accounts/<username>/friends/
     |__ friend.db
     |__ msg/
         |__ <friend1dbname>
	 |__ ...

"""
class Friend:

	# Status
	ONLINE  = 0
	OFFLINE = 1
	UNKNOWN = 2

	def __init__(self):

		self.id     = None	# Friends userid (8 byte)
		self.name   = None	# Friends username
		self.pubkey = RetroPublicKey() # Friends pubkey

		self.msgdbname = None	# Name of msgdb file

		# Current friend status (OFFLINE,ONLINE,UNKNONW)
		self.status = Friend.OFFLINE

		# Just a counter for unseen messages.
		# For gui purpose only..
		self.unseen_msgs = 0

	'''
	def load(self, name, path):
		"""\
		Load friends public key from given path and
		set name and userid.

		Args:
		  name: Friends name
		  path: Path to friends public key
		"""
		self.name = name
		self.pubkey.load(path)

		# Get friends userid from filename
		hexid   = path_basename(path).replace('.pem', '')
		self.id = bytes.fromhex(hexid)

		LOG.debug("Loaded friend, name='{}' id={}"\
			.format(self.name, self.id.hex()))
	'''

	""" TODO
	def load2(self, userid, username, path):
		self.id   = userid
		self.name = username
		self.path = path

		self.pubkey.load(
			path_join(path, "key.pem"))

		LOG.debug("Loaded friend, name='{}' id={}"\
			.format(self.name, self.id.hex()))

	def get_msgdb_path(self):
		return path_join(self.path, "msg.db")
	"""
