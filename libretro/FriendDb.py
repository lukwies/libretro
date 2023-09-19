from os.path import join as path_join
from os.path import exists as path_exists
from os.path import basename as path_basename
import logging
from sqlcipher3 import dbapi2 as sqlcipher
from time import time as time_now

from libretro.Friend import Friend
from libretro.crypto import hash_sha256, random_buffer

LOG = logging.getLogger(__name__)

"""
This database stores all friend informations.

 +-----------------------------------------------+
 | friends            		                 |
 +-----------+--------+------+------+------------+
 | _id       | _name  | _rsa | _ec  | _msgdbname |
 | BLOB (PK) | TEXT   | TEXT | TEXT | TEXT       |
 +-----------+--------+------+------+------------+

 _id        -  A friends ID (8 byte)
 _name      - Username of friend
 _rsa       - Public RSA key of friend
 _ec        - Public ED25519 key of friend
 _msgdbname - The name of the sqlite database where
              all messages of the conversation with
	      a friend are stored.

 NOTE: Public keys are stored as PEM-strings including
       prefix and suffix ("------ BEGIN ...", "----- END ..")

"""
class FriendDb:

	CREATE_TABLE_FRIENDS = \
		'''CREATE TABLE IF NOT EXISTS friends (
			_id BLOB UNIQUE NOT NULL,
			_name TEXT NOT NULL,
			_rsa TEXT NOT NULL,
			_ec TEXT NOT NULL,
			_msgdbname TEXT NOT NULL)'''

	@staticmethod
	def get_random_dbname(friends_dir):
		"""\
		Get a random (not existing) filename for
		a message database.
		Return:
		   filename,filepath
		"""
		msgdir = path_join(friends_dir, "msg")
		while True:
			filename = random_buffer(16, True)
			filepath = path_join(msgdir, filename)
			if not path_exists(filepath):
				return filename


	def __init__(self, path, password):
		"""
		Args:
		"""
		self.path = path
		self.key  = hash_sha256(password.encode(), True)


	def add(self, friend):
		"""\
		Add friend to database.
		"""
		db = self.__open()
		rsapem,ecpem = friend.pubkey.get_pem()
		db.execute(
			"INSERT INTO friends VALUES (?,?,?,?,?)",
			(friend.id, friend.name, rsapem,
			ecpem, friend.msgdbname))
		db.commit()
		db.close()

	def delete_by_id(self, userid):
		"""\
		Delete Friend by userid.
		"""
		db = self.__open()
		db.execute("DELETE FROM friends"\
			" WHERE _id=?;", (userid,))
		db.commit()
		db.close()


	def load_all(self):
		"""\
		Loads all friends from the database and return
		a dictionary where ids are the friendids and
		values are Friend instances.
		"""
		db  = self.__open()
		friends = {}
		q = "SELECT * FROM friends"

		for row in db.execute(q):
			LOG.debug("Loading friend '"+row[1]+"' ...")
			LOG.debug("Row len: {}".format(len(row)))
			LOG.debug("DB ROW: [\n"+row[2]+"\n]\n")
			friend = Friend()
			friend.id = row[0]
			friend.name = row[1]
			friend.pubkey.load_strings(row[2], row[3])
			friend.msgdbname = row[4]
			friends[friend.id] = friend

		db.close()
		return friends


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
