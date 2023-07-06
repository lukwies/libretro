from os.path import join as path_join
from os.path import basename as path_basename
import logging as LOG
from sqlcipher3 import dbapi2 as sqlcipher
from time import time as time_now

"""
The message store is a cached system for storing chat messages.
It holds all active conversations between the current user and
its friends. All messages of a single conversation are stored
within an encrypted sqlite database. A database connection will
be closed if no selects/inserts applied in a certain timeinterval.

Each of these conversations is identified by the friends name ID.
All message db's are located at ~/.retro/accounts/<USER>/msg/

"""
class MsgStore:

	def __init__(self, account, close_conversation_after=5*60):
		"""
		Init message store.
		Args:
		  account: Retro user account
		  close_conversation_after: Timeout for closing db
		"""
		self.account = account
		self.path    = path_join(account.path, "msg")
		self.close_conversation_after = close_conversation_after

		# Dictionary with conversations where key=FriendName
		# and value=Conversation
		self.conversations = {}


	def close(self):
		"""
		Close all database connections
		"""
		for db in self.conversations.values():
			db.close()


	def add_msg(self, friend, msg):
		"""
		Add message to conversation with friend.
		This will open the according database if not open.
		Args:
		  friend: Friend object
		  msg:    Message dictionary
		    Format: {
			'type'       : 'message'|'file-message'
			'from'       : USER,
			'to'         : USER,
			'time'       : TIME,
			'msg'        : MESSAGE,
			'unseen'     : 0|1
			# Only if type = 'file-message'
			'fileid'     : FILE_ID,
			'filename'   : FILE_NAME,
			'size'       : FILE_SIZE,
			'key'        : ENCR_KEY,
			'downloaded' : IS_DOWNLOADED
		    }
		Raises:
		  Exception

		"""
		self._open_conversation(friend)
		self.conversations[friend.name].add_msg(msg)
		self._close_unused_conversations()


	def get_msgs(self, friend, last_n=None, msg_type=None):
		"""
		Get all messages of conversation with given friend.
		This will open the according database if not open.
		Args:
		  friend: Friend object
		  last_n: Last <n> messages
		  msg_type: Select only messages with given type.
			    Can either be 'f' for file messages,
			    or 'm' for normal messages.
		Return:
		  List with messages
		"""
		self._open_conversation(friend)
		msgs = self.conversations[friend.name]\
				.get_msgs(last_n, msg_type)
		self._close_unused_conversations()
		return msgs

	def get_not_downloaded_files(self, friend, last_n=None):
		"""
		Get all messages containing files that aren't
		downloaded yet.
		Return:
		  List with messages
		"""
		self._open_conversation(friend)
		msgs = self.conversations[friend.name]\
				.get_not_downloaded_files(last_n)
		self._close_unused_conversations()
		return msgs


	def set_all_seen(self, friend):
		"""
		Set unseen=0 to all messages of friend.
		"""
		self._open_conversation(friend)
		n = self.conversations[friend.name]\
				.set_all_seen()
		self._close_unused_conversations()


	def get_num_unseen(self, friend):
		"""
		Returns the number of unseen messages
		from given friend.
		Args:
		  friend: Friend object
		Return:
		  Number of unseen messages
		"""
		self._open_conversation(friend)
		n = self.conversations[friend.name]\
				.get_num_unseen()
		self._close_unused_conversations()
		return n


	def set_file_downloaded(self, friend, fileid):
		"""
		Set state of file to downloaded
		"""
		self._open_conversation(friend)
		self.conversations[friend.name]\
				.set_file_downloaded(fileid)
		self._close_unused_conversations()



	def _open_conversation(self, friend):
		"""
		Make sure there's an open conversation with
		given friend.
		"""
		if friend.name not in self.conversations:
			db_path = path_join(self.path,
					friend.name+".msg")
			conv = MsgDB()
			conv.open(db_path, self.account.pw)
			self.conversations[friend.name] = conv


	def _close_unused_conversations(self):
		"""
		Close conversations that have not been updated
		since self.close_conversation_after seconds.
		"""
		now = time_now()
		fr_names = list(self.conversations.keys())

		for name in fr_names:
			conv = self.conversations[name]
			if now - conv.last_action > 20*60:
				conv.close()
				self.conversations.pop(name)



"""
For each friend there's an encrypted sqlite3 db containing
all messages of the conversation between a friend and the
client. Each entry has the flag '_read' which tells us if
a message has been read by the user or not.

 +--------------------------------------------------------------+
 | msg                                                          |
 +-----------+----------+-------+-----+-------+-------+---------+
 | _id       | _type    | _from | _to | _time | _msg  | _unseen |
 | INT (PK)  | CHAR(1)  | TEXT  | TEXT| TEXT  | TEXT  | INT     |
 +-----------+----------+-------+-----+-------+-------+---------+

_type can be either 'm' for messages, 'f' for files.
_unseen tells us if a message was seen by the receiver


+--------------------------------------------------------------+
| files						       	       |
+----------+---------+-----------+-------+-------+-------------+
| _msgid   | _fileid | _filename | _size | _key  | _downloaded |
| INT (FK) | TEXT    | TEXT      | INT   | TEXT  | INT         |
+----------+---------+-----------+-------+-------+-------------+

{
  'type' : 'message',
  'from' : USER_NAME,
  'to'   : USER_NAME
  'time' : MSG_SENT_TIME,
  'msg'  : MSG_TEXT
}

{
  'type' :  'file-message'
  'from' : USER_NAME,
  'to'   : USER_NAME
  'time' : MSG_SENT_TIME,
  'msg'  : MSG_TEXT
  'fileid: FILE_ID,
  'filename': FILE_NAME,
  'size' : FILE_SIZE,
  'key' : base64(KEY),
  'downloaded' : True|False
  }
}


"""
class MsgDB:

	CREATE_TABLE_MSG = \
		'''CREATE TABLE IF NOT EXISTS msg (
			_id INTEGER PRIMARY KEY,
			_type CHAR(1),
			_from TEXT NOT NULL,
			_to TEXT NOT NULL,
			_time TEXT NOT NULL,
			_msg TEXT NOT NULL,
			_unseen INTEGER);'''

	CREATE_TABLE_FILES = \
		'''CREATE TABLE IF NOT EXISTS files (
			_msgid INTEGER,
			_fileid TEXT,
			_filename TEXT,
			_size INTEGER,
			_key TEXT,
			_downloaded INTEGER,
			FOREIGN KEY (_msgid) REFERENCES msg(_id));'''

	def __init__(self):
		"""
		Args:
		"""
		self.db   = None
		self.path = None
		self.last_action = time_now()


	def open(self, path, password):
		"""
		Open database.
		NOTE: The database password is created as
		      password + basename(path)
		Args:
		  path:
		  password:
		Throws:
		  Exception
		"""
		self.path = path
		pw = password + path_basename(path)
		self.db = sqlcipher.connect(path, check_same_thread=False)
		self.db.execute("pragma key='" + pw + "'")
		self.db.execute(MsgDB.CREATE_TABLE_MSG)
		self.db.execute(MsgDB.CREATE_TABLE_FILES)
		self.db.commit()
		pw = None


	def close(self):
		if self.db != None:
			self.db.close()
			self.db = None


	def add_msg(self, msg):
		"""
		Add message to database.
		Args:
		  msg:    Message dictionary
		    Format: {
			'type'       : 'message'|'file-message'
			'from'       : USER,
			'to'         : USER,
			'time'       : TIME,
			'msg'        : MESSAGE,
			'unseen'     : 0|1
			# Only if type = 'file-message'
			'fileid'     : FILE_ID,
			'filename'   : FILE_NAME,
			'size'       : FILE_SIZE,
			'key'        : ENCR_KEY,
			'downloaded' : IS_DOWNLOADED
		    }

		Raises:
		  Exception
		"""
		if not self.db:
			raise ValueError("MsgDB.add_msg: Database closed")

		# To have less memory the database stores the message type
		# as single char ('m':'message', 'f':'file-message')
		typ = 'm' if msg['type'] == 'message' else 'f'


		# Create entry in table 'msg'...
		q  = "INSERT INTO msg (_type,_from,_to,_time,_msg,_unseen)"\
			" VALUES (?, ?, ?, ?, ?, ?);"
		self.db.execute(q, (typ, msg['from'], msg['to'],
				msg['time'], msg['msg'], msg['unseen']))
		self.db.commit()


		if typ == 'f':
			# Message is 'file-message', create entry in
			# table 'files'...
			msgid = self.__get_last_msgid()
			q = "INSERT INTO files VALUES (?,?,?,?,?,?);"
			self.db.execute(q, (msgid,
					msg['fileid'],
					msg['filename'],
					msg['size'],
					msg['key'],
					msg['downloaded']))
			self.db.commit()



		self.last_action = time_now()


	def add_msgs(self, msgs):
		"""
		Add a list of messages.
		Throws:
		  Exception
		"""
		for msg in msgs:
			self.add_msg(msg)


	def get_msgs(self, last_n=None, _type=None):
		"""
		Get last_n (if set) messages from message store.
		Args:
		  last_n: Last n messages (by time)
		  _type: Select only messages with given type
			('f' or 'm')
		Return:
		  List with messages (dictionaries)
		Throws:
		  Exception
		"""
		if not self.db:
			raise ValueError("MsgStore.get_msgs: Database closed")

		self.last_action = time_now()
		msgs = []

		if _type:
			q = "SELECT * FROM msg WHERE _type=? ORDER BY _time;"
			result = self.db.execute(q, (_type,))
		else:
			q = "SELECT * FROM msg ORDER BY _time;"
			result = self.db.execute(q)

		for row in result:
			msgid = row[0]

			if row[1] == 'm':
				msg = self.__row_to_msg(row)
			elif row[1] == 'f':
				msg = self.__get_filemsg(row)
			else:	continue
			msgs.append(msg)

		if last_n != None:
			return msgs[-last_n:]
		else:	return msgs



	def get_not_downloaded_files(self, last_n=None):
		"""
		Get all file messages containing not downloaded
		files.
		Return:
		  List with messsages
		"""
		if not self.db:
			raise Exception("MsgStore: Database "\
					"is closed!")

		self.last_action = time_now()
		msgs = []

		result = self.db.execute(
			"SELECT * FROM msg WHERE _type='f';")

		for row in result:
			msg = self.__get_filemsg(row, downloaded=0)
			if msg: msgs.append(msg)

		if last_n != None:
			return msgs[-last_n:]
		else:	return msgs



	def set_all_seen(self):
		"""
		Set unseen=0 to all messages.
		"""
		q  = "UPDATE msg SET _unseen=0;"
		self.db.execute(q)
		self.db.commit()


	def get_num_unseen(self):
		"""
		Get number of unseen messages.
		"""
		q = "SELECT count(*) FROM msg "\
			"WHERE _unseen=1;"
		res = self.db.execute(q)
		return res.fetchone()[0]


	def set_file_downloaded(self, fileid):
		"""
		Set file to downloaded=1.
		"""
		q = "UPDATE files SET _downloaded=1 "\
			"WHERE _fileid=?;"
		self.db.execute(q, (fileid,))
		self.db.commit()


	def __get_last_msgid(self):
		# Get hightest message id
		q = "SELECT max(_id) FROM msg;"
		res = self.db.execute(q)
		return int(res.fetchone()[0])


	def __row_to_msg(self, row):
		# Convert row of table 'msg' to message dict
		return {
			'type'   : 'file-message' if row[1]=='f' else 'message',
			'from'   : row[2],
			'to'     : row[3],
			'time'   : row[4],
			'msg'    : row[5],
			'unseen' : row[6] }


	def __get_filemsg(self, msg_row, downloaded=None):
		# Build file-message from row of table 'msg'
		# and selected file infos from table 'files'.
		# Args:
		#   msg_row:
		#   downloaded: None    = Don't care
		#		0|False = Only not downloaded
		#		1|True  = Only downloaded
		# Return:
		#  Message with type 'file-message' or
		#  None on error or missing data.
		q = "SELECT * FROM files WHERE _msgid=?"
		if downloaded != None:
			q += " AND _downloaded={}".format(downloaded)

		msg = self.__row_to_msg(msg_row)

		for file_row in self.db.execute(q, (msg_row[0],)):
			msg['fileid']     = file_row[1]
			msg['filename']   = file_row[2]
			msg['size']       = file_row[3]
			msg['key']        = file_row[4]
			msg['downloaded'] = file_row[5]
			return msg
		return None
"""

msg = {
	'from' : 'r2d2',
	'to': 'peilnix',
	'time' : '2023-1-23 20:23',
	'msg' : 'Hello World'
}

db = MsgStore()
if db.open("test.db", "password"):
	db.add_msg(msg)

	msgs = db.get_msgs()
	print(msgs)
	db.close()
"""
