from os.path import join as path_join
from os.path import basename as path_basename
import logging as LOG
from sqlcipher3 import dbapi2 as sqlcipher
from time import time as time_now

from libretro.crypto import hash_sha256

"""
This database is made to resolve a friend's userid to its
username. It just contains a single table:

 +--------------------+
 | friends            |
 +-----------+--------+
 | _id       | _name  |
 | TEXT (PK) | TEXT   |
 +-----------+--------+

"""
class FriendDb:

	CREATE_TABLE_FRIENDS = \
		'''CREATE TABLE IF NOT EXISTS friends (
			_id TEXT UNIQUE NOT NULL,
			_name TEXT NOT NULL)'''

	def __init__(self, path, password):
		"""
		Args:
		"""
		self.path = path
		self.key  = hash_sha256(password.encode(), True)


	def add(self, userid, username):
		"""
		Add friend to database.
		"""
		db = self.__open()
		db.execute(
			"INSERT INTO friends VALUES (?, ?)",
			(userid, username))
		db.commit()
		db.close()


	def get_all(self):
		"""
		Get all entries from table 'friends' and return them
		as a dictionary, where key is the userid and value
		the username.
		"""
		db  = self.__open()
		all = {}
		q   = "SELECT * FROM friends"

		for row in db.execute(q):
			all[row[0]] = row[1]

		db.close()
		return all


	def get_id(self, username):
		db  = self.__open()
		q   = "SELECT _id FROM friends WHERE _name=?"
		res = db.execute(q, (username,))
		id  = res.fetchone()[0]
		db.close()
		return id


	def get_name(self, userid):
		db   = self.__open()
		q    = "SELECT _name FROM friends WHERE _id=?"
		res  = db.execute(q, (userid,))
		name = res.fetchone()[0]
		db.close()
		return name


	def __open(self):
		"""
		Open database.
		"""
		db = sqlcipher.connect(self.path, check_same_thread=False)
		db.execute("pragma key='" + self.key + "'")
		db.execute(FriendDb.CREATE_TABLE_FRIENDS)
		db.commit()
		return db
