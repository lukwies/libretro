from os.path import join as path_join
from sqlcipher3 import dbapi2 as sqlcipher
import logging

from libretro.crypto import RetroPrivateKey
from libretro.crypto import random_buffer

LOG = logging.getLogger(__name__)

"""\
Encryted database holding account information.

- User Id
- Username
- Private RSA key
- Private ED25519 key


+----------------------------+
| account                    |
+------+-------+------+------+
| _id  | _name | _rsa | _ec  |
| BLOB | TEXT  | TEXT | TEXT |
+------+-------+------+------+

"""
class AccountDb:

	DBNAME = "account.db"

	CREATE_TABLE = """CREATE TABLE IF NOT EXISTS account (
				_id BLOB,
				_name TEXT,
				_rsa TEXT,
				_ec TEXT)"""

	def __init__(self, account_path):
		self.account_path = account_path
		self.db_path = path_join(account_path, self.DBNAME)


	def create(self, pw, userid, username, retroPrivKey):
		"""\
		Creates account database and inserts the one
		and only row...
		"""
		rsa,ec = retroPrivKey.get_pem_strings()
		db = self.__open(pw)
		q = "INSERT INTO account VALUES (?,?,?,?)"
		db.execute(q, (userid, username, rsa, ec))
		db.commit()
		db.close()


	def select(self, pw):
		"""\
		Load account settings.

		Return:
		  userid,username,RetroPrivKey
		"""
		db = self.__open(pw)
		row = db.execute("SELECT * FROM account").fetchone()
		userid = row[0]
		username = row[1]
		privkey = RetroPrivateKey()
		privkey.load_pem_strings(row[2], row[3])
		db.close()

		return userid,username,privkey


	def __open(self, pw):
		db = sqlcipher.connect(self.db_path,
				check_same_thread=False)
		db.execute("pragma key='" + pw + "'")
		db.execute(self.CREATE_TABLE)
		db.commit()
		return db
