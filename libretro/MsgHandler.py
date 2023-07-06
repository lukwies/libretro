from base64 import b64encode,b64decode
from time import strftime
import logging as LOG
import json

import zlib

from libretro.crypto import random_buffer
from libretro.crypto import aes_encrypt, aes_decrypt, hmac_sha256
from libretro.crypto import hash_sha512


"""
End2End message en/decryption.


An unencrypted chat message has the following format:

  {
    'type'   : 'message'|'file-message'
    'from'   : USERID,
    'to'     : USERID,
    'time'   : SENT_TIME (yyyy-mm-dd HH:MM),
    'msg'    : MESSAGE TEXT
    'unseen' : 1|0

    'fileid      : FILE_ID,	# These values are
    'filename'   : FILE_NAME,	# only existant if
    'size'       : FILE_SIZE,	# message type is
    'key'        : base64(KEY),	# 'file-message'
    'downloaded' : True|False	#
  }

An encrypted chat message looks like:

  {
    'type'   : 'message'|'file-message'
    'from'   : USERID,
    'to'     : USERID,
    'header' : [key+IV+HMAC(body)+SENT_TIME] (rsa-encrypted)
    'sig'    : ED25519 signature of (ecrypted) body,
    'body'   : body
  }

  If type is 'file-message' the (decrytped) body is a
  dictionary holding the file informations.
  {
    'fileid'   : FILE_ID  (hex,n=32),
    'filename' : FILE_NAME (string),
    'size'     : FILE_SIZE (long int),
    'key'      : ENCR_KEY (base64)
  }

"""

class MsgHandler:


	def __init__(self, account):
		"""
		Create message handler for given client.
		Args:
		  account: RetroClient account
		"""
		self.account = account


	def make_msg(self, friend, text, msg_type='message'):
		"""
		Create a new en2end encrypted message.

		Args:
		  friend:   Friend that shall receive the message
		  text:     Message text
		  msg_type: Message type (Default: 'message')

		Return:
		  This function returns two dictionaries,
		  the message and the end2end-encrypted message.

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
		# The header will be base64 encoded.
		header_raw = kM + iv + hmac + now.encode()
		header = friend.pubkey.encrypt(header_raw,
				encode_base64=True)

		# Sign message with accounts signing key.
		# Signature will be base64 encoded.
		signature = self.account.key.sign(enc, True)

		# Base64 encode message body
		body = b64encode(enc)

		# Create message dictionaries
		msg = {
			'type'   : msg_type,
			'from'   : self.account.name,
			'to'     : friend.name,
			'time'   : now,
			'msg'    : text,
			'unseen' : 0
		}

		e2e_msg = {
			'type'   : msg_type,
			'from'   : self.account.id,
			'to'     : friend.id,
			'header' : header.decode(),
			'sig'    : signature.decode(),
			'body'   : body.decode()
		}
		return msg,e2e_msg


	def make_file_msg(self, friend, file_dict):
		"""
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
		  msg,e2e_msg
		"""
		msg,e2e_msg = self.make_msg(friend,
				json.dumps(file_dict),
				msg_type='file-message')
		msg = dict(msg, **file_dict)
		msg['msg'] = ''

		return msg,e2e_msg


	def decrypt_msg(self, msg):
		"""
		Decrypt end2end message.
		(See description on top of page)

		Args:
		  msg: e2e enctypted message (dictionary)
		Return:
		  Decrypted message (dictionary)

		Raises:
			Exception, ValueError
		"""

		# Check if message sender is one of our friends.
		if msg['from'] not in self.account.friends:
			raise ValueError("MsgHandler.make_msg: "\
				"No such friend '"+msg['from']+"'")
		friend = self.account.friends[msg['from']]

		# Decode aes encrypted message body from base64
		enc = b64decode(msg['body'])

		# Decode signature from base64
		sig = b64decode(msg['sig'])

		# Verify message signature (ed25519)
		if not friend.pubkey.verify(sig, enc):
			raise ValueError("Invalid msg signature "\
				"from '" + msg['from'] + "'")

		# Decrypt received message header (rsa)
		hdr = self.account.key.decrypt(msg['header'], True)

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
		hmac2 = hmac_sha256(kS, iv+enc)
		if hmac != hmac2:
			LOG.warning("HMAC's do not match!")
			LOG.warning("  hmac1: {}".format(hmac))
			LOG.warning("  hmac2: {}".format(hmac2))
			raise ValueError("HMAC's mismatch")

		# Decrypt and decode message
		msg_text = aes_decrypt(kE, enc, iv)
		msg_text = msg_text.decode()

		# Build (decrypted) message dict
		msg_res = {
			'type'   : msg['type'],
			'from'   : friend.name,
			'to'     : self.account.name,
			'time'   : dtime,
			'msg'    : '',
			'unseen' : 1
		}

		if msg['type'] == 'file-message':
			file_dict = json.loads(msg_text)
			msg_res = dict(msg_res, **file_dict)
			msg_res['downloaded'] = False
		else:
			msg_res['msg'] = msg_text

		return msg_res



	def get_message(self, sender, receiver, text,
			unseen=False, msgtype='message'):
		"""
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
