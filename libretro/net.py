import socket
from ssl import SSLContext, PROTOCOL_TLS_SERVER, PROTOCOL_TLS_CLIENT
import json
import select
import logging
from threading import Lock

from libretro.protocol import *

LOG = logging.getLogger(__name__)

class NetClient:
	"""\
	TLS Client
	"""
	def __init__(self, host='127.0.0.1', port=8443,
			hostname=None, certpath=None):
		self.host     = host
		self.port     = port
		self.hostname = hostname
		self.certpath = certpath

		self.conn     = None
		self.ssl      = None
		self.is_ssl   = certpath != None


	def set_conn(self, conn, address):
		"""\
		Set connection and address
		"""
		self.conn = conn
		self.host = address[0]
		self.port = address[1]

	def tostr(self):
		return self.host + ":" + str(self.port)

	def connect(self):
		"""\
		Connect to server
		"""
		if self.conn:
			return
		try:
			LOG.info("connecting to {}:{} ..."\
				.format(self.host, self.port))
			conn = socket.create_connection((self.host,self.port))

			if self.is_ssl:
				self.ssl = SSLContext(PROTOCOL_TLS_CLIENT)
				self.ssl.load_verify_locations(self.certpath)
				self.conn = self.ssl.wrap_socket(conn,
					server_hostname=self.hostname)
			else:	self.conn = conn

		except Exception as e:
			LOG.error("connect: " + str(e))
			raise #Exception("TLSClient.connect: " + str(e))


	def send(self, data):
		"""\
		Send all data.
		"""
#		nsent = 0
#		while nsent < len(data):
#			nsent += self.conn.send(data[nsent:])
		self.conn.sendall(data)

	def send_packet(self, pckt_type, *data):
		"""\
		Send packet.
		Args:
		  pckt_type: Type of packet (Proto.T_*)
		  *data: Payload args
		"""
#		self.send(Proto.pack_packet(pckt_type, *data))
		if data:
			payload = b''.join(data)
			hdr = Proto.pack_header(pckt_type, len(payload))
			self.send(hdr)
			self.send(payload)
		else:
			hdr = Proto.pack_header(pckt_type, 0)
			self.send(hdr)


	def recv(self, max_bytes=4096, timeout_sec=None):
		"""\
		Receive data
		Return:
		  Data:  Received data
		  False: Timeout
		Raises:
		  if failed to receive/select
		"""
		if can_read(self.conn, timeout_sec):
			return self.conn.recv(max_bytes)
		else:	return False

	def recv_all(self, n_bytes, timeout_sec=None):
		"""\
		Receive n bytes.
		Return:
		  Data:  Received data
		  False: Timeout
		Raises:
		  if failed to receive/select
		"""
		nrecv = 0
		data  = b''

		while nrecv < n_bytes:
			buf = self.recv(n_bytes-nrecv, timeout_sec)
			if not buf: return buf

			data += buf
			nrecv += len(buf)

#			print("recv_all: {}/{} byte".format(nrecv, n_bytes))

		return data


	def recv_packet(self, timeout_sec=None):
		"""\
		Receive packet.
		Return:
		  - On success, the packet type and payload will
		    be returned ([0]: Packet type, [1]: Payload).
		  - On timeout return value is False
		  - On error None
		Raises:
		"""
		try:
			hdr = self.recv_all(8, timeout_sec)
			if not hdr: return hdr
		except Exception as e:
			raise Exception("NetClient.recv_packet: "\
				"Failed to recv header, "+str(e))

		version,pckt_type,pckt_size = Proto.unpack_header(hdr)
#		print("RECV header: t={} n={}".format(pckt_type, pckt_size))
#		print("     bytes:  "+hdr.hex())

		if version != RETRO_PROTOCOL_VERSION:
			raise ValueError("Invalid protocol: "\
				"{} != {}".format(version,
				RETRO_PROTOCOL_VERSION))
		data = None

		if pckt_size > 0:
			try:
				data = self.recv_all(pckt_size,
						timeout_sec)
				if not data:
					LOG.error("recv_packet: TIMEOUT")
					return data

#				print("     data:   "+data.hex())
			except Exception as e:
				raise Exception("NetClient.recv_packet: "\
					"Failed to recv payload ({} byte),"\
					" {}".format(pckt_size, e))
		return pckt_type,data


	def close(self):
		"""\
		Close connection.
		"""
		if self.conn:
			self.conn.close()
			self.conn = None


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
	Raises:
	  if select() failed
	"""
	if not timeout_sec:
		return True

	ready = select.select([conn], [],
			[], timeout_sec)
	if ready[0]:
		return True
	else:	return False
#	except Exception as e:
#		LOG.error("can_read: select, "+str(e))
#		return None

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
