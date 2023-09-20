import struct

"""\
Each packet sent over the retro networks starts
with an 8 byte header. It contains the protocl
version, packet type and payload size.

 0   2   4       8
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+
 | V | T | S     | P ...		  |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+

 V = Protocol version (2 byte)
 T = Packet Type (See PacketTypes) (2 byte)
 S = Size of payload (4 byte)
 P = Payload


T_HELLO
	userid (8 byte)
	nonce  (32 byte)
	signature (32 byte)

T_CHATMSG, T_FILEMSG, T_START
	8 byte    Sender ID
	8 byte    Receiver ID
        256 byte  Header [kM+IV+HMAC+TS]
	64 byte   Message Signature
	n byte    Body

T_CALL_STOP, T_CALL_REJECT, T_CALL_ACCEPT
	8 byte    Sender ID
	8 byte    Receiver ID

T_FILE_UPLOAD
	16 byte    File ID
	4 byte     File Size
T_FILE_DOWNLOAD
	16 byte    File ID



32+16+32+6]
"""

# Protocol version
RETRO_PROTOCOL_VERSION = 0x0001
RETRO_PROTOCOL_VERSION_STR = "0.1"


class Proto:
	# Packet header types
	T_SUCCESS		= 1
	T_ERROR			= 2
	T_HELLO			= 3
	T_GOODBYE		= 4
	T_REGISTER		= 5
	T_PUBKEY		= 6
	T_GET_PUBKEY		= 7
	T_CHATMSG		= 10
	T_FILEMSG		= 11
	T_FRIENDS		= 20
	T_FRIEND_ONLINE		= 21
	T_FRIEND_OFFLINE	= 22
	T_FRIEND_UNKNOWN	= 23
	T_FILE_UPLOAD		= 31
	T_FILE_DOWNLOAD		= 32


	HDR_SIZE     = 8   # Size of retro header (in byte)
	USERID_SIZE  = 8   # UserId size (bytes)
	FILEID_SIZE  = 16  # FileId size (bytes)
	REGKEY_SIZE  = 32  # Registration key size
	AES_KEY_SIZE = 32  # AES key size
	IV_SIZE      = 16  # IV size
	HMAC_SIZE    = 32  # HMAC size
	RSA_SIZE     = 256 # RSA key size
	EC_SIZE      = 64  # Ed25519 key size

	UNPACK_T_HELLO  = [8, 32, None]
	UNPACK_T_E2EMSG = [8, 8, RSA_SIZE, EC_SIZE, None]


	@staticmethod
	def pack_header(pckt_type, size=0):
		"""\
		Create a packet header.
		Args:
		  pckt_type: Packet type
		  size:      Payload size
		Return:
		  Packet header (bytes)
		"""
		return struct.pack('!HHi',
			RETRO_PROTOCOL_VERSION,
			pckt_type, size)


	@staticmethod
	def unpack_header(pckt_hdr_buffer):
		"""\
		Unpack packet header buffer (8 byte)

		Return:
		  1) Protocol version (2 byte)
		  2) Packet type (2 byte)
		  3) Payload size (4 byte)
		"""
		return struct.unpack('!HHi', pckt_hdr_buffer)


	@staticmethod
	def pack_packet(pckt_type, *data):
		"""\
		Create a packet.
		Args:
		  pckt_type: Packet type
		  *data:     Data to add to the packet.
			     All args MUST be bytes!
		Return:
		  Packet (bytes)
		"""
		if data:
			payload = b''.join(data)
			return Proto.pack_header(pckt_type,
				len(payload))+payload
		else:	return Proto.pack_header(pckt_type)


	@staticmethod
	def unpack_packet(pckt_buf, data_sizes=[]):
		"""\
		Unpack a packet buffer.

		Args:
		  pckt_buffer: Packet (bytes) WITHOUT header!!!
		  data_sizes:  List with the length of
			       each item in the packet.
		Return:
		  A list with all items

		Usage:
		  data_names = ['from', 'to', 'msg']
		  data_sizes = [8, 8, None]

		  res = PacketBuilder.unpack(pckt_buffer, data_sizes)
		  for name,value in zip(data_names, res):
		  	print("{} = '{}'".format(name,value))

		"""
		pckt_items = []
		i = 0

		for size in data_sizes:
			if i >= len(pckt_buf):
				raise ValueError("Packet buffer too small"\
					" to unpack")
			if size:
				pckt_items.append(pckt_buf[i:i+size])
				i += size
			else:
				pckt_items.append(pckt_buf[i:])
				i += len(pckt_buf[i:])
		return pckt_items


	@staticmethod
	def friend_status_str(friend_status):
		"""\
		Return string from friend status.
		Args:
		  friend_status: One of the packet types T_FRIEND_*
		Return:
		  String name of friend status
		"""
		if friend_status == Proto.T_FRIEND_ONLINE:
			return "online"
		elif friend_status == Proto.T_FRIEND_OFFLINE:
			return "offline"
		else:	return "unknown"


	@staticmethod
	def hexstr_to_userid(hex_string):
		"""\
		Parses hexadecimal string to userid.
		Args:
		  hex_string: Hexadecimal userid string
		Return:
		  userid (8 byte)
		Raises:
		  ValueError: If given string has invalid format
		"""
		if not hex_string or len(hex_string) != 16:
			raise ValueError("Userid string has "\
				"invalid length ({})"\
				.format(len(hex_string)))
		try:
			return bytes.fromhex(hex_string)
		except:	raise ValueError("Userid has invalid format")

