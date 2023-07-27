from time import strftime
import logging
import json


from libretro.protocol import *
from libretro.crypto import random_buffer
from libretro.crypto import aes_encrypt, aes_decrypt
from libretro.crypto import hmac_sha256, hash_sha512


LOG = logging.getLogger(__name__)

"""\
End2End message en/decryption.


An unencrypted chat message has the following format:

  {
    'type'   : Proto.T_CHATMSG|Proto.T_FILEMSG
    'from'   : USERID,
    'to'     : USERID,
    'time'   : SENT_TIME (yyyy-mm-dd HH:MM),
    'msg'    : MESSAGE TEXT
    'unseen' : 1|0

    'fileid      : FILE_ID,	# These values are
    'filename'   : FILE_NAME,	# only existant if
    'size'       : FILE_SIZE,	# message type is
    'key'        : base64(KEY),	# Proto.T_FILEMSG
    'downloaded' : True|False	#
  }

An encrypted chat message looks like:

  version	2 byte
  packet type	2 byte (T_CHATMSG|T_FILEMSG|T_START_CALL)
  payload size	4 byte
  from		8 byte
  to		8 byte
  header	256 byte
  signature	64 byte
  body		...

"""

class MsgHandler:


	def __init__(self, account):
		"""\
		Create message handler for given client.
		Args:
		  account: RetroClient account
		"""
		self.account = account


	def make_msg(self, friend, text, msg_type=Proto.T_CHATMSG):
		"""\
		Create an en2end encrypted message.

		Args:
		  friend:   Friend that shall receive the message
		  text:     Message text
		  msg_type: Message type (Proto.T_CHATMSG|Proto.T_FILEMSG)

		Return:
		  message:     Unencrypted message as dictionary
		  pckt_buffer: Encrypted message as byte buffer

		Raises:
		  ValueError: If friend doesn't exist
		"""
		# Generate Master key (kM) and hash it with sha512
		kM = random_buffer(32)
		kH = hash_sha512(kM)

		# Split hashed master key to encryption key (kE) and
		# signing key (kS)
		kE = kH[:32]
		kS = kH[32:]

		# Encrypt the message text using encryption key (kE)
		enc, iv = aes_encrypt(kE, text.encode())

		# Calculate hmac of IV+enc_data using sign key (kS)
		hmac = hmac_sha256(kS, iv+enc)

		# Get current date
		now = strftime('%y-%m-%d %H:%M')

		# Create RSA encrypted header (kM+IV+HMAC+Timestamp).
		header_raw = kM + iv + hmac + now.encode()
		header = friend.pubkey.encrypt(header_raw)

		# Sign message with accounts signing key.
		signature = self.account.key.sign(enc)

		# Create e2e packet buffer
		e2e_buf = self.account.id + friend.id + \
			  header + signature + enc

		# Create message dictionaries
		msg = {
			'type'   : msg_type,
			'from'   : self.account.name,
			'to'     : friend.name,
			'time'   : now,
			'msg'    : text,
			'unseen' : 0
		}

		return msg,e2e_buf


	def make_file_msg(self, friend, file_dict):
		"""\
		Create an end2end encrypted file message.
		Args:
		  file_dict: File settings
			{
			  'fileid: FILE_ID,
			  'filename': FILE_NAME,
			  'size' : FILE_SIZE,
			  'key' : base64(KEY),
			}
		Return:
		  msg,packet_buffer
		"""
		msg,e2e_buf = self.make_msg(friend,
				json.dumps(file_dict),
				msg_type=Proto.T_FILEMSG)
		msg = dict(msg, **file_dict)
		msg['msg'] = ''

		return msg,e2e_buf


	def decrypt_msg(self, msg_type, e2e_msg):
		"""\
		Decrypt end2end message.
		(See description on top of page)
		Supported message types are:
			Proto.T_CHATMSG
			Proto.T_FILEMSG
			Proto.T_START_CALL
		Args:
		  msg_type: Type of received packet
		  e2e_msg: e2e enctypted message (bytes)
		Return:
		  Friend (sender), Decrypted message (dictionary)

		Raises:
			Exception, ValueError
		"""
		mfrom, mto, mhdr, msig, mbody =\
			Proto.unpack_packet(e2e_msg, Proto.UNPACK_T_E2EMSG)

		# Check if message sender is one of our friends.
		if mfrom not in self.account.friends:
			raise ValueError(
				"No such friend '"+mfrom.hex()+"'")
		friend = self.account.friends[mfrom]

		# Verify message signature (ed25519)
		if not friend.pubkey.verify(msig, mbody):
			raise ValueError("Invalid msg signature "\
				"from '" + mfrom.hex() + "'")

		# Decrypt received message header (rsa)
		hdr = self.account.key.decrypt(mhdr)

		# Get keyE+keyH+IV+HMAC from buffer
		kM    = hdr[:32]		# Master key
		iv    = hdr[32:48]		# IV
		hmac  = hdr[48:80]		# HMAC
		dtime = hdr[80:].decode()	# Sent datetime

		# Get encryption key (kE) and signing key (kS)
		kH = hash_sha512(kM)
		kE = kH[:32]
		kS = kH[32:]

		# Calculate HMAC from iv+encrypted message using
		# extracted encryption key (kE) and see if it's
		# the same as the received one.
		hmac2 = hmac_sha256(kS, iv+mbody)
		if hmac != hmac2:
			LOG.warning("HMAC's do not match!")
			LOG.warning("  hmac1: "+hmac.hex())
			LOG.warning("  hmac2: "+hmac2.hex())
			raise ValueError("HMAC's mismatch")

		# Decrypt and decode message
		msg_text = aes_decrypt(kE, mbody, iv)
		msg_text = msg_text.decode()

		# Build (decrypted) message dict
		msg_res = {
			'type'   : msg_type,
			'from'   : friend.name,
			'to'     : self.account.name,
			'time'   : dtime,
			'msg'    : '',
			'unseen' : 1
		}

		if msg_type == Proto.T_FILEMSG:
			file_dict = json.loads(msg_text)
			msg_res = dict(msg_res, **file_dict)
			msg_res['downloaded'] = False
		elif msg_type == Proto.T_START_CALL:
			call_dict = json.loads(msg_text)
			msg_res = dict(msg_res, **call_dict)
		else:
			msg_res['msg'] = msg_text

		return friend,msg_res



	def get_message(self, sender, receiver, text,
			unseen=False, msgtype=Proto.T_CHATMSG):
		"""\
		Get (not-encrypted) message.
		"""
		return {
			'type'   : msgtype,
			'from'   : sender,
			'to'     : receiver,
			'time'   : strftime('%y-%m-%d %H:%M'),
			'msg'    : text,
			'unseen' : unseen
		}
