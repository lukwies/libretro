"""\

This file contains all crypto functions/classes used
by retro.

author: Lukas Wiese (16.May 2023)

"""

from os import chmod as os_chmod
from os import urandom as os_urandom
from os import stat as os_stat

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode,b64decode

import zlib
import logging

LOG = logging.getLogger(__name__)

"""\
A retro user key consists of 2 different keys, a RSA-2048 key used
for decryption and an ED25519 key used for signing.

Both keys are stored within a single file named 'key.pem' and looks
like the following:

	-----BEGIN ENCRYPTED PRIVATE KEY-----
	Private RSA key
	-----END ENCRYPTED PRIVATE KEY-----

	-----BEGIN ENCRYPTED PRIVATE KEY-----
	Private ed25519 key
	-----END ENCRYPTED PRIVATE KEY-----
"""

class RetroPrivateKey:
	"""
	Private key
	"""

	def __init__(self):
		self.rsa = None
		self.ec  = None


	def gen(self):
		"""
		Generate 2048bit RSA key and EC signing key.
		"""
		self.rsa = rsa.generate_private_key(
				public_exponent=65537,
				key_size=2048)
		self.ec = Ed25519PrivateKey.generate()


	def load_pem_strings(self, rsa_pem, ec_pem):
		"""\
		Init private keys by parsing given PEM strings.
		"""
		self.rsa = load_pem_private_key(
				data=rsa_pem.encode('utf-8'),
				password=None)
		self.ec = load_pem_private_key(
				data=ec_pem.encode('utf-8'),
				password=None)


	def get_pem_strings(self):
		"""\
		Returns both, the rsa and ed25519 key as PEM strings.
		"""
		srsa = self.rsa.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption())
		sec = self.ec.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption())
		return srsa.decode(), sec.decode()


	def decrypt(self, data, data_is_base64=False):
		"""\
		Decrypt given data using the private RSA key.
		Args:
		  data: Data to decrypt
		  data_is_base64: Base64-encoded data?
		Return:
		  Decrypted data (bytes)
		"""
		if data_is_base64:
			data = b64decode(data)

		dec = self.rsa.decrypt(
			data,
			rsa_padding.OAEP(
			  mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
			  algorithm=hashes.SHA256(), label=None))
		return dec


	def sign(self, data, encode_base64=False):
		"""\
		Sign given data using the ed25519 key.
		Args:
		  data:          Data to sign (bytes).
		  encode_base64: Return signature in base64?
		Return:
		  Signature in bytes or base64
		"""
		sig = self.ec.sign(data)
		return b64encode(sig) if encode_base64 else sig


	def get_public(self):
		"""\
		Return RetroPublic key.
		"""
		pub = RetroPublicKey()
		pub.rsa = self.rsa.public_key()
		pub.ec  = self.ec.public_key()
		return pub



"""\
The public keyfile is named '<user>.pem' and looks like this:

	owner = peilnix

	-----BEGIN PUBLIC RSA KEY-----
	Private RSA key
	-----END PUBLIC KEY-----

	-----BEGIN PUBLIC ED25519 KEY-----
	Private ed25519 key
	-----END PUBLIC KEY-----

"""
class RetroPublicKey:
	def __init__(self):
		self.rsa = None
		self.ec  = None


	def load_pem_file(self, path):
		"""\
		Load public RSA and ED25519 keys.
		Args:
		  path: Path to public keyfile
		"""
		f = open(path, "r")
		data = f.read()
		f.close()
		self.load_pem_string(data)


	def load_pem_string(self, pem):
		"""\
		Load both keys from a concatenated PEM string.
		"""
		# Extract both keys
		try:
			start = pem.index("-----BEGIN")
			end   = pem[start+1:].index("-----BEGIN")
			k1 = pem[start:end-1].strip()
			k2 = pem[end:].strip()
			self.load_pem_strings(k1, k2)
		except:
			raise #ValueError("Invalid PEM format")

	def load_pem_strings(self, rsa_pem, ec_pem):
		"""\
		Load both keys from single pem strings.
		"""
		self.rsa = load_pem_public_key(data=rsa_pem.encode('utf-8'))
		self.ec  = load_pem_public_key(data=ec_pem.encode('utf-8'))


	def save_pem_file(self, path):
		"""\
		Save public keys to file. The filemode will be set to 600.
		Args:
		  path: Path to public keyfile
		"""
		key_file = open(path, "w")
		key_file.write(self.get_pem_string())
		key_file.close()
		os_chmod(path, 0o600)


	def get_pem_string(self):
		"""\
		Get keys as concatenated PEM string.
		Return:
		  rsapem + "\n" + ecpem
		"""
		srsa,sec = self.get_pem_strings()
		return srsa + '\n' + sec


	def get_pem_strings(self):
		"""\
		Get PEM strings.
		"""
		srsa = self.rsa.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo)
		sec = self.ec.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo)
		return srsa.decode(),sec.decode()


	def to_der(self):
		"""\
		Get keys as DER buffer.
		Return:
		  rsa-der, ec-der
		"""
		srsa = self.rsa.public_bytes(
			encoding=serialization.Encoding.DER,
			format=serialization.PublicFormat.SubjectPublicKeyInfo)
		sec = self.ec.public_bytes(
			encoding=serialization.Encoding.DER,
			format=serialization.PublicFormat.SubjectPublicKeyInfo)
		return srsa,sec


	def encrypt(self, data, encode_base64=False):
		"""\
		Encrypt given data using the public RSA key.
		Args:
		  data: Data to encrypt (bytes)
		  encode_base64: Base64-encode encrypted data?
		Return:
		  Encrypted data (bytes)
		"""
		enc = self.rsa.encrypt(data, rsa_padding.OAEP(
			mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(), label=None))
		return b64encode(enc) if encode_base64 else enc


	def verify(self, signature, data, sig_is_base64=False):
		"""\
		Verify given signature.
		Args:
		  signature:     The signature (bytes)
		  data:          Data (bytes)
		  sig_is_base64: Is signature base64-encoded?
		Return:
		  True if signature is valid, else False
		"""
		try:
			if sig_is_base64:
				signature = b64decode(signature)
			self.ec.verify(signature, data)
			return True
		except:
			return False


########################################

def random_buffer(length, return_hex=False):
	"""\
	Returns random buffer with given length.
	"""
	if return_hex:
		return os_urandom(int(length/2)).hex()
	else:	return os_urandom(length)

def derive_key(password, outlen, iterations=10000, return_hex=False):
	"""\
	Derive key or password from given password.
	"""
	key = password.encode()
	for i in range(iterations):
		key = hash_sha512(key)
	if return_hex:
		key = key.hex()
	return key[:outlen]

def hash_sha256(data, return_hex=False):
	"""\
	Hash data with sha256
	Args:
	  data:  Data to hash
	  return_hex: Return hash as hex?
	Return:
	  Sha256 hash
	"""
	h = hashes.Hash(hashes.SHA256())
	h.update(data)
	dig = h.finalize()
	return dig.hex() if return_hex else dig

def hash_sha512(data, return_hex=False):
	"""\
	Hash data with sha512
	Args:
	  data:  Data to hash
	  return_hex: Return hash as hex?
	Return:
	  Sha256 hash
	"""
	h = hashes.Hash(hashes.SHA512())
	h.update(data)
	dig = h.finalize()
	return dig.hex() if return_hex else dig


def hmac_sha256(key, data):
	"""\
	Calculate HMAC-SHA256 from given data and given key.
	Args:
	  key:  Signing key
	  data: Bytes to sign
	Return:
	  Signature (bytes)
	"""
	h = hmac.HMAC(key, hashes.SHA256())
	h.update(data)
	sig = h.finalize()
	return sig


def aes_encrypt(key, data):
	"""\
	Encrypt data using AES-256-cbc.
	Args:
	  data: Bytes to encrypt
	  key:  Encryption key
	Return:
	  Encrypted,IV
	"""
	iv   = random_buffer(16)
	aes  = Cipher(algorithms.AES(key), modes.CBC(iv))

	padder = aes_padding.PKCS7(256).padder()
	data   = padder.update(data) + padder.finalize()

	encr = aes.encryptor()
	ct   = encr.update(data) + encr.finalize()

	return ct,iv


def aes_decrypt(key, data, iv):
	"""\
	Decrypt data using AES-256-cbc.
	Args:
	  key:  Decryption key
	  data: Encrypted bytes
	  iv:   IV
	Return:
	  Decrytped string data
	"""

	aes  = Cipher(algorithms.AES(key), modes.CBC(iv))
	decr = aes.decryptor()
	dec  = decr.update(data) + decr.finalize()

	unpadder = aes_padding.PKCS7(256).unpadder()
	dec = unpadder.update(dec) + unpadder.finalize()

	return dec


def aes_encrypt_from_file(key, filepath):
	"""\
	Compress/Encrypt file to buffer.
	The encrypted buffer contains the IV, HMAC and cipher
	text and will be formatted likes this:

	  [0-15]   IV
	  [16-47]  HMAC
	  [48-...] CIPHER-TEXT

	Return:
	  IV+HMAC+CYPHER_TEXT
	"""
	f    = open(filepath, 'rb')
	data = zlib.compress(f.read())
	f.close()

	enc,iv = aes_encrypt(key, data)
	hmac   = hmac_sha256(key, enc)

	return iv+hmac+enc


def aes_decrypt_to_file(key, file_buf, filepath):
	"""\
	Decrypt/Decompress file_buf (IV+HMAC+DATA)
	and store it to given filepath.
	"""
	iv   = file_buf[:16]
	hmac = file_buf[16:48]
	enc  = file_buf[48:]

	hmac2 = hmac_sha256(key, enc)
	if hmac != hmac2:
		raise Exception("HMAC's mismatch")

	fout = open(filepath, 'wb')
	dec  = aes_decrypt(key, enc, iv)
	fout.write(zlib.decompress(dec))
	fout.close()

