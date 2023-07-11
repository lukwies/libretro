import socket
from ssl import SSLContext, PROTOCOL_TLS_SERVER, PROTOCOL_TLS_CLIENT
import json
import select
import logging as LOG
from threading import Lock

class TLSClient:
	"""\
	TLS Client
	"""
	def __init__(self, host='127.0.0.1', port=8443,
			hostname=None,
			cert_path='cert.pem'):
		self.host     = host
		self.port     = port
		self.hostname = hostname
		self.certpath = cert_path

		if not hostname:
			self.hostname=host

		self.ssl  = None
		self.conn = None


	def connect(self):
		"""\
		Connect to server
		"""
		if self.conn:
			return
		try:
			LOG.info("TLSClient: connecting to {}:{} ..."\
				.format(self.host, self.port))
			client = socket.create_connection((self.host,self.port))

			self.ssl = SSLContext(PROTOCOL_TLS_CLIENT)
			self.ssl.load_verify_locations(self.certpath)
			self.conn = self.ssl.wrap_socket(client,
				server_hostname=self.hostname)

		except Exception as e:
			LOG.error("TLSClient.connect: " + str(e))
			raise #Exception("TLSClient.connect: " + str(e))


	def send(self, data):
		"""\
		Send all data.
		"""
		if not self.conn: return
		nsent = 0
		while nsent < len(data):
			n = self.conn.send(data[nsent:])
			nsent += n


	def recv(self, max_bytes=4096, timeout_sec=None):
		"""\
		Receive data
		Return:
		  Data: Received data
		  None: Timeout
		"""
		if timeout_sec and not can_read(self.conn, timeout_sec):
			return None
		return self.conn.recv(max_bytes)


	def send_dict(self, dct):
		"""\
		Send dictionary.
		"""
		if self.conn:
			send_dictionary(self.conn, dct)


	def recv_dict(self, force_keys=[], max_bytes=4096,
			timeout_sec=None):
		"""\
		Receive dictionary
		Return:
		  Dict: Received dictionary
		  None: Timeout
		Raises:
		  TypeError, Exception
		"""
		return recv_dictionary(self.conn,
				force_keys=force_keys,
				max_bytes=max_bytes,
				timeout_sec=timeout_sec)

	def close(self):
		"""\
		Close ssl conn
		"""
		if self.conn:
			self.conn.close()
			self.conn = None

#	def cipher(self):
#		self.conn.cipher()


def send_dictionary(conn, dct):
	"""\
	Send dictionary
	"""
	try:
		data = json.dumps(dct)
		LOG.debug("Send {}".format(data))
		conn.sendall(data.encode())
		return True
	except Exception as e:
		LOG.error("net.send_dictionary: " + str(e))
		LOG.error("> Dict: [{}]".format(dct))
		LOG.error("> Data: [{}]".format(data))
		return False


def recv_dictionary(conn, force_keys=[], max_bytes=4096,
		timeout_sec=None):
	"""\
	Receive data and convert it to dictionary.
	Args:
	  conn:        SSL connection
	  force_keys:  Keys in given list MUST exist in dict
	  max_bytes:   Max size of recv buffer
	  timeout_sec: Receive timeout in seconds (None=No timeout).
	Return:
	  Packet dictionary
	  None: Timeout

	Raises:
	   Exception
	"""
	if timeout_sec and not can_read(conn, timeout_sec):
		return None
	try:
		data = conn.recv(max_bytes).decode()
		dct  = json.loads(data)
		if type(dct) != dict:
			LOG.error("Invalid msg "\
				"format '{}'".format(data.decode()))
			raise Exception("Invalid protocol '{}'".format(type(dct)))
		for k in force_keys:
			if k not in dct:
				#LOG.warning("net.recv_dictionary: "\
				#	"Missing key '{}' in packet dict".format(k))
				raise Exception("Packet has no key '{}'".format(k))

		LOG.debug("Recv {}".format(data))
		return dct

	except TypeError as te:
		raise Exception(str(te))
	except Exception as e:
		raise Exception("Server closed connection")


def can_read(conn, timeout_sec):
	"""\
	Check wheather there is data awailable at the given
	connection before timeout exceeds.
	Args:
	  conn:        Connection
	  timeout_sec: Timeout in seconds
	Return:
	  True:  Data is awailable to receive
	  False: Timeout exceeded
	  None:  Select error
	"""
	try:
		ready = select.select([conn], [],
				[], timeout_sec)
		if ready[0]:
			return True
		else:	return False

	except select.error as e:
		LOG.error("libretro.net.can_read: "\
			"select failed, " + str(e))
		return None



class TCPSocket:
	"""\
	Simple TCP socket.
	"""
	def __init__(self, fd=None, addr=None):
		"""\
		Init socket
		"""
		self.fd    = fd	   # Socket
		self.addr  = addr   # Address
		self.rlock = Lock() # Read lock
		self.wlock = Lock() # Write lock

		# Internally used socket status.
		# 0=None, 1=connected, 2=listen
		self.__status = 0


	def is_connected(self):
		""" Is socket connected ? """
		return self.__status == 1


	def is_listening(self):
		""" Is socket listening ? """
		return self.__status == 2


	def get_addrstr(self):
		"""\
		Get socket address as 'host:port' string.
		"""
		self.__check_fd()
		return "{}:{}".format(self.addr[0],
				self.addr[1])


	def connect(self, host, port):
		"""\
		Connect to given host/port
		"""
		self.fd = socket.socket(
				socket.AF_INET,
				socket.SOCK_STREAM)

		self.addr = (host,port)

		self.fd = socket.create_connection(
				self.addr)
		self.__status = 1


	def listen(self, host, port, backlog=10):
		"""\
		Listen at given address.
		"""
		self.fd = socket.socket(
				socket.AF_INET,
				socket.SOCK_STREAM)
		self.addr = (host,port)
		self.fd.setsockopt(socket.SOL_SOCKET,
				socket.SO_REUSEADDR, 1)
		self.fd.bind((host, port))
		self.fd.listen(backlog)
		self.__status = 2


	def accept(self, timeout_sec=None):
		"""\
		Accept with timeout.

		Return:
		  TCPSocket: On success
		  False:     On timeout
		  None:      On error
		Throws:
		  ValueError: If socket is not setup
		"""
		self.__check_fd()

		if timeout_sec:
			res = can_read(self.fd, timeout_sec)
			if not res: return res

		fd,addr = self.fd.accept()
		tcpSock = TCPSocket(fd, addr)
		tcpSock.__status = 1

		return tcpSock


	def send(self, data):
		"""\
		Send data.
		"""
		self.__check_fd()
		self.fd.sendall(data)


	def recv(self, max_bytes=4096, timeout_sec=None):
		"""\
		Receive data (with timeout).
		Return:
		  None:  Error
		  False: Timeout
		  Data:  Received bytes
		"""
		self.__check_fd()

		if timeout_sec:
			res = can_read(self.fd, timeout_sec)
			if not res: return res

		return self.fd.recv(max_bytes)


	def close(self, how=None):
		"""\
		Close socket.
		If shutdown is given, socket.shutdown() is
		called before closing the socket.

		Args:
		  how:  'r'  - Close for reading
			'w'  - Close for writing
			'rw' - Close for both
		"""

		hows = {
			'r'  : socket.SHUT_RD,
			'w'  : socket.SHUT_WR,
			'rw' : socket.SHUT_RDWR
		}

		try:
			if how:
				if how not in hows:
					raise ValueError("TCPSocket.close "\
						"parameter 'how' must be "\
						"'r', 'w' or 'rw'")
				self.fd.shutdown(hows[how])

			self.fd.close()
			self.fd.__status = 0

		except ValueError:
			raise
		except:
			# Ignore 'bad filedescriptor'
			pass


	def __check_fd(self):
		"""\
		Raises ValueError if fd is not setup.
		"""
		if self.__status == 0:
			raise ValueError("TCPSocket: Neither "\
				"connected nor listening")
