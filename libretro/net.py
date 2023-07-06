from socket import socket, AF_INET, SOCK_STREAM, create_connection
from ssl import SSLContext, PROTOCOL_TLS_SERVER, PROTOCOL_TLS_CLIENT
import json
import select
import logging as LOG

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
			self.ssl = SSLContext(PROTOCOL_TLS_CLIENT)
			self.ssl.load_verify_locations(self.certpath)
			client = create_connection((self.host,self.port))
			self.conn = self.ssl.wrap_socket(client, server_hostname=self.hostname)
		except Exception as e:
			LOG.error("TLSClient.connect: " + str(e))
			raise #Exception("TLSClient.connect: " + str(e))


	def send(self, data):
		"""\
		Send all data.
		"""
		if self.conn:
			self.conn.sendall(data)


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
		conn.sendall(data.encode())
		LOG.debug("Sent dict: {}".format(data))
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
		data = conn.recv(max_bytes)
		dct  = json.loads(data.decode())
		if type(dct) != dict:
			LOG.error("Invalid msg "\
				"format '{}'".format(data.decode()))
			raise Exception("Invalid protocol '{}'".format(type(dct)))
		for k in force_keys:
			if k not in dct:
				#LOG.warning("net.recv_dictionary: "\
				#	"Missing key '{}' in packet dict".format(k))
				raise Exception("Packet has no key '{}'".format(k))
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
		ready = select.select([conn], [], [],
				timeout_sec)
		if ready[0]:
			return True
		else:
			#LOG.debug("net.can_read: timeout after {} sec"\
			#	.format(timeout_sec))
			return False

	except select.error as e:
		LOG.error("net.can_read: select failed, " + str(e))
		return None


