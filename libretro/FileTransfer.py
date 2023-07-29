import logging

from os      import stat     as os_stat
from os.path import join     as path_join
from os.path import basename as path_basename
from base64  import b64encode,b64decode

from libretro.protocol import *
from libretro.Config import RETRO_MAX_FILESIZE
from libretro.Friend import Friend
from libretro.net    import NetClient
from libretro.crypto import hash_sha256, random_buffer
from libretro.crypto import aes_encrypt_from_file
from libretro.crypto import aes_decrypt_to_file


LOG = logging.getLogger(__name__)


def filesize_to_string(filesize):
	"""\
	Returns formatted string from given filesize.
	"""
	KB = 1024
	MB = KB*KB
	GB = MB*KB

	if filesize < KB:
		return str(filesize) + " b"
	elif filesize < MB:
		return str(round(filesize/KB,1)) + " Kb"
	elif filesize < GB:
		return str(round(filesize/MB, 2)) + " Mb"
	else:
		return str(round(filesize/GB, 3)) + " Gb"

"""\
Logic for transferring a file between two retro clients.
Let's assume Alice want's to send a file to Bob.

- Alice loads file, encrypts it and sends it to the fileserver.
- Alice sends an end2end message to bob containing the file's
  id and decryption key.
- Bob receives that message, sends the fileid to the fileserver,
   downloads, decrypts and stores the file.

For more information check the file Protocol.md at
https://github.com/lukwies/libretro

"""

class FileTransfer:
	"""\
	Handles all the file up/downloading.
	"""

	def __init__(self, retro):
		"""\
		Args:
		  retro: RetroClient instance
		"""
		self.cli        = retro
		self.conf       = retro.conf
		self.msgHandler = retro.msgHandler


	def upload_file(self, friend:Friend, filepath:str):
		"""\
		Upload file to server and send a Proto.T_FILEMSG
		to receiver of file.

		Args:
		  friend:   Receiver Friend object
		  filepath: Path to file

		Return:
		  filename,filesize

		Raises:
		  Exception
		"""
		try:
			filename = path_basename(filepath)
			filesize = os_stat(filepath).st_size
			fileid   = self.__get_fileid(filename)
		except Exception as e:
			LOG.error("upload: "+str(e))
			raise Exception("FileUpload: "+str(e))

		# Encrypt/compress file
		try:
			key  = random_buffer(32)
			data = aes_encrypt_from_file(key, filepath)
		except Exception as e:
			raise Exception("Encrypt file '{}', {}"\
				.format(filepath, e))

		# Connect to fileserver
		conn = self.__connect()

		# Send initial packet (fileid and filesize)
		conn.send_packet(Proto.T_FILE_UPLOAD,
			fileid, struct.pack('!I', len(data)))

		self.__recv_ok(conn)

		# Upload encrytped file
		conn.send(data)

		self.__recv_ok(conn)
		conn.close()

		# Send file-message to user
		file_dict = {
			'fileid'   : fileid.hex(),
			'filename' : filename,
			'key'      : b64encode(key).decode(),
			'size'     : filesize
		}
		msg,e2e_buffer = self.cli.msgHandler.make_file_msg(
					friend,	file_dict)
		self.cli.send_packet(Proto.T_FILEMSG, e2e_buffer)

		return filename,filesize



	def download_file(self, friend:Friend, fileid:bytes,
			filename:str, key:bytes):
		"""\
		Download file from server, decrypt and store it.

		Args:
		  friend:   Sender Friend object
		  fileid:   Fileid (16 byte)
		  filename: Filename (not path!)
		  key:      Encryption key (base64)

		Return:
		  filename,filesize

		Raises:
		  Exception
		"""

		filepath = path_join(self.conf.download_dir,
				filename)

		# Connect to fileserver
		conn = self.__connect()

		# Send initial packet
		conn.send_packet(Proto.T_FILE_DOWNLOAD, fileid)

		# Must receive T_SUCCESS and filesize
		pckt = self.__recv_ok(conn)

		filesize = struct.unpack('!I', pckt[1])[0]
		data     = b''
		nrecv    = 0

		# Receive file contents
		while nrecv < filesize:
			buf = conn.recv(timeout_sec=self.conf.recv_timeout)
			if not buf: break
			data  += buf
			nrecv += len(buf)
		conn.close()

		if nrecv != filesize:
			raise Exception("FileTransfer: Failed to download "\
				"'{}', stopped at {}/{}".format(filename,
				nrecv, filesize))

		# Decrypt/Decompress and store to file
		try:
			aes_decrypt_to_file(key, data, filepath)
		except Exception as e:
			raise Exception("Failed to decrypt file"\
				" '{}': {}".format(filename, e))

		return filename,filesize


	def __connect(self):
		#Connect to fileserver.
		try:
			cli = NetClient(
				self.conf.server_address,
				self.conf.server_fileport,
				self.conf.server_hostname,
				self.conf.server_certfile)
			cli.connect()
			return cli
		except Exception as e:
			LOG.error("Failed to connect to fileserver, "+str(e))
			raise e


	def __recv_ok(self, conn):
		# Wait for packet type == 'ok'
		# Return:
		#   msg: Received packet on success
		#   None: on error
		try:
			pckt = conn.recv_packet(timeout_sec=10)
			if not pckt:
				raise Exception("FileServer: timeout")

			elif pckt[0] == Proto.T_ERROR:
				raise Exception("FileServer: "\
					+ pckt[1].decode())

			elif pckt[0] != Proto.T_SUCCESS:
				raise Exception("FileTransfer: "\
					"Invalid response type: {}"\
					.format(pckt[0]))
			else:
				return pckt
		except Exception as e:
			raise Exception("FileServer: " + str(e))



	def __get_fileid(self, filename):
		# Generate fileid out of filename and random
		idbuf  = filename.encode()+random_buffer(16)
		fileid = hash_sha256(idbuf)[:Proto.FILEID_SIZE]
		return fileid

		return os_stat(path).st_size


