from libretro.crypto import RetroPublicKey

class Friend:
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

	ONLINE  = 0
	OFFLINE = 1
	UNKNOWN = 2

	def __init__(self):

		self.id     = None	# Friends userid (8 byte)
		self.name   = None	# Friends username
		self.pubkey = RetroPublicKey() # Friends pubkey

		# Name of database holding all messages sent between
		# user and friend. This is a random name, generated
		# when adding this friend to a user account.
		self.msgdbname = None

		# Current friend status (OFFLINE,ONLINE,UNKNONW)
		self.status = Friend.OFFLINE

		# Just a counter for unseen messages.
		# For gui purpose only..
		self.unseen_msgs = 0

