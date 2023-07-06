from os.path import basename as path_basename
from os.path import join as path_join
from os import listdir as os_listdir
import logging as LOG

from libretro.crypto import RetroPublicKey

"""
A friend is another peer within the retro network,
of whom we already know the public-key and username.

Friend information is stored as follows:

  ~/.retro/accounts/<username>/friends/
     |__ <friendID-1>.pem
     |__ <friendID-2>.pem
     |__ ...

  ~/.retro/accounts/<username>/msg/
     |__ <friendID-1>.db
     |__ <friendID-2>.db
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

		# Current friend status (OFFLINE,ONLINE,UNKNONW)
		self.status = Friend.OFFLINE

		# Just a counter for unseen messages.
		# For gui purpose only..
		self.unseen_msgs = 0


	def load(self, name, path):
		"""
		Load friends public key from given path and
		set name and userid.

		Args:
		  name: Friends name
		  path: Path to friends public key
		"""
		self.name = name
		self.pubkey.load(path)
		self.id = self.pubkey.get_keyid(hexify=True)

		LOG.debug("Loaded friend, name='{}' id={}"\
			.format(self.name, self.id))

