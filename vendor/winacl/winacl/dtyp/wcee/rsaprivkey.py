import io
import math

from cryptography.hazmat.primitives.asymmetric import rsa

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/5cf2e6b9-3195-4f85-bc18-05b50e6d4e11
class RSAPrivateKeyBlob:
	def __init__(self):
		self.type = None
		self.version = None
		self.reserved = None
		self.keyalg = None
		self.magic = None
		self.bitlen = None
		self.pubexp = None
		self.modulus = None
		self.p = None
		self.q = None
		self.dp = None
		self.dq = None
		self.iq = None
		self.d = None

	@staticmethod
	def from_bytes(data):
		return RSAPrivateKeyBlob.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		pk = RSAPrivateKeyBlob()
		pk.type = buff.read(1)[0]
		pk.version = buff.read(1)[0]
		pk.reserved = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		pk.keyalg = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pk.magic = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pk.bitlen = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		c8 = int(math.ceil(pk.bitlen/8))
		c16 = int(math.ceil(pk.bitlen/16))
		pk.pubexp = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pk.modulus = int.from_bytes(buff.read(c8), byteorder='little', signed=False)
		pk.p = int.from_bytes(buff.read(c16), byteorder='little', signed=False)
		pk.q = int.from_bytes(buff.read(c16), byteorder='little', signed=False)
		pk.dp = int.from_bytes(buff.read(c16), byteorder='little', signed=False)
		pk.dq = int.from_bytes(buff.read(c16), byteorder='little', signed=False)
		pk.iq = int.from_bytes(buff.read(c16), byteorder='little', signed=False)
		pk.d = int.from_bytes(buff.read(c8), byteorder='little', signed=False)
		return pk

	def get_key(self):
		public_numbers = rsa.RSAPublicNumbers(self.pubexp, self.modulus)
		numbers = rsa.RSAPrivateNumbers(self.p, self.q, self.d, self.dp, self.dq, self.iq, public_numbers)
		# cryptography >= 42 dropped the old Backend-based key-loading method; the
		# numbers object builds the key itself now, with no backend argument.
		return numbers.private_key(unsafe_skip_rsa_key_validation=False)

	def get_pubkey(self):
		public_numbers = rsa.RSAPublicNumbers(self.pubexp, self.modulus)
		return public_numbers.public_key()

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
		return t

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/540b7b8b-2232-45c8-9d7c-af7a5d5218ed
class BCRYPTRSAKeyBlob:
	def __init__(self):
		self.magic = None
		self.bitlen = None
		self.pubexplen = None
		self.moduluslen = None
		self.plen = None
		self.qlen = None
		self.pubexp = None
		self.modulus = None
		self.p = None
		self.q = None

	@staticmethod
	def from_bytes(data):
		return BCRYPTRSAKeyBlob.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		pk = BCRYPTRSAKeyBlob()
		pk.magic = buff.read(4)
		pk.bitlen = int.from_bytes(buff.read(4), 'little', signed=False)
		pk.pubexplen = int.from_bytes(buff.read(4), 'little', signed=False)
		pk.moduluslen = int.from_bytes(buff.read(4), 'little', signed=False)
		pk.plen = int.from_bytes(buff.read(4), 'little', signed=False)
		pk.qlen = int.from_bytes(buff.read(4), 'little', signed=False)
		pk.pubexp = int.from_bytes(buff.read(pk.pubexplen), 'big', signed=False)
		pk.modulus = int.from_bytes(buff.read(pk.moduluslen), 'big', signed=False)
		pk.p = int.from_bytes(buff.read(pk.plen), 'big', signed=False)
		pk.q = int.from_bytes(buff.read(pk.qlen), 'big', signed=False)
		return pk

	def get_key(self):
		phi = (self.p - 1) * (self.q - 1)
		d = rsa._modinv(self.pubexp, phi)
		dmp1 = rsa.rsa_crt_dmp1(d, self.p)
		dmq1 = rsa.rsa_crt_dmq1(d, self.q)
		iqmp = rsa.rsa_crt_iqmp(self.p, self.q)
		numbers = rsa.RSAPrivateNumbers(
			p=self.p,
			q=self.q,
			d=d,
			dmp1=dmp1,
			dmq1=dmq1,
			iqmp=iqmp,
			public_numbers=rsa.RSAPublicNumbers(
				e=self.pubexp,
				n=self.modulus
			)
		)
		# cryptography >= 42 dropped the old Backend-based key-loading method; the
		# numbers object builds the key itself now, with no backend argument.
		return numbers.private_key(unsafe_skip_rsa_key_validation=False)

	def get_pubkey(self):
		public_numbers = rsa.RSAPublicNumbers(self.pubexp, self.modulus)
		return public_numbers.public_key()

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
		return t