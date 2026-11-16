from kerbad import logger
from kerbad.protocol.asn1_structs import KerberosResponse
from kerbad.common.target import KerberosTarget
from asysocks.unicomm.common.target import UniProto
from asysocks.unicomm.client import UniClient
from asysocks.unicomm.common.packetizers import Packetizer
from kerbad.protocol.errors import KerberosReplyMalformedError

# Size of the TCP record mark that precedes every Kerberos message (RFC 4120 7.2.2).
_LENGTH_PREFIX_SIZE = 4


async def _read_one_reply(connection, addr):
	"""Read exactly one complete KDC reply, or say precisely why there is none.

	The connection's reader yields ``None`` on a transport error and simply
	ends when the peer closes before a whole message arrived. Both used to
	reach the caller as an unrelated ``TypeError`` / ``StopAsyncIteration``.
	"""
	read_gen = connection.read()
	try:
		try:
			packet = await read_gen.__anext__()
		except StopAsyncIteration:
			packet = None
	finally:
		await read_gen.aclose()
	if packet is None:
		raise KerberosReplyMalformedError(
			'The KDC at %s closed the connection before a complete reply was received (truncated KDC reply)' % addr
		)
	return packet


class KerberosPacketizer(Packetizer):
	def __init__(self, buffer_size = 65535):
		Packetizer.__init__(self, buffer_size)
		self.buffer_size = buffer_size
		self.in_buffer = b''
	
	def process_buffer(self):
		# RFC 4120 7.2.2: over TCP every message is preceded by a 4-byte
		# big-endian length that does NOT count itself. The buffer still holds
		# that prefix here, so a message is complete only once the buffer has
		# ``length + 4`` bytes. Comparing against ``length`` alone hands over a
		# message up to 4 bytes short whenever the first read ends inside its
		# last 4 bytes (do not revert: locked by
		# tests/unit/vendor/test_kerbad_tcp_packetizer_length_prefix.py).
		if len(self.in_buffer) >= _LENGTH_PREFIX_SIZE:
			length = int.from_bytes(self.in_buffer[:_LENGTH_PREFIX_SIZE], byteorder = 'big', signed = False)
			if len(self.in_buffer) >= length + _LENGTH_PREFIX_SIZE:
				data = self.in_buffer[_LENGTH_PREFIX_SIZE:_LENGTH_PREFIX_SIZE+length]
				self.in_buffer = self.in_buffer[length+_LENGTH_PREFIX_SIZE:]
				yield data
				
	async def data_out(self, data):
		yield data

	async def data_in(self, data):
		if data is None:
			yield data
		self.in_buffer += data
		for packet in self.process_buffer():
			yield packet


class KerberosPWChangePacketizer(Packetizer):
	def __init__(self, buffer_size = 65535):
		Packetizer.__init__(self, buffer_size)
		self.buffer_size = buffer_size
		self.in_buffer = b''
	
	def process_buffer(self):
		# RFC 4120 7.2.2: over TCP every message is preceded by a 4-byte
		# big-endian length that does NOT count itself. The buffer still holds
		# that prefix here, so a message is complete only once the buffer has
		# ``length + 4`` bytes. Comparing against ``length`` alone hands over a
		# message up to 4 bytes short whenever the first read ends inside its
		# last 4 bytes (do not revert: locked by
		# tests/unit/vendor/test_kerbad_tcp_packetizer_length_prefix.py).
		if len(self.in_buffer) >= _LENGTH_PREFIX_SIZE:
			length = int.from_bytes(self.in_buffer[:_LENGTH_PREFIX_SIZE], byteorder = 'big', signed = False)
			if len(self.in_buffer) >= length + _LENGTH_PREFIX_SIZE:
				data = self.in_buffer[_LENGTH_PREFIX_SIZE:_LENGTH_PREFIX_SIZE+length]
				self.in_buffer = self.in_buffer[length+_LENGTH_PREFIX_SIZE:]
				yield data
				
	async def data_out(self, data):
		yield data

	async def data_in(self, data):
		if data is None:
			yield data
		self.in_buffer += data
		for packet in self.process_buffer():
			yield packet

class AIOKerberosPWChangeClientSocket:
	def __init__(self, target:KerberosTarget):
		self.target = target
	
	def get_addr_str(self):
		return '%s:%d' % (self.target.get_hostname_or_ip(), self.target.port)
	
	async def sendrecv(self, data, throw:bool = False):
		client = None
		connection = None
		try:
			packetizer = KerberosPWChangePacketizer()
			client = UniClient(self.target, packetizer)
			connection = await client.connect()
			if self.target.protocol == UniProto.CLIENT_TCP:
				length = len(data).to_bytes(4, byteorder = 'big', signed = False)
				await connection.write(length + data)

				krb_message = await _read_one_reply(connection, self.get_addr_str())

			elif self.target.protocol == UniProto.CLIENT_UDP:
				raise Exception('Not implemented!')

			return krb_message
		finally:
			if connection is not None:
				await connection.close()

class AIOKerberosClientSocket:
	def __init__(self, target:KerberosTarget):
		self.target = target
	
	def get_addr_str(self):
		return '%s:%d' % (self.target.get_hostname_or_ip(), self.target.port)
	
	async def sendrecv(self, data, throw:bool = False):
		client = None
		connection = None
		try:
			packetizer = KerberosPacketizer()
			client = UniClient(self.target, packetizer)
			connection = await client.connect()
			if self.target.protocol == UniProto.CLIENT_TCP:
				length = len(data).to_bytes(4, byteorder = 'big', signed = False)
				await connection.write(length + data)

				packet = await _read_one_reply(connection, self.get_addr_str())
				try:
					krb_message = KerberosResponse.load(packet)
				except (ValueError, TypeError) as e:
					# asn1 could not decode what the KDC sent: say so, instead
					# of letting a bare "Insufficient data" travel upward as
					# an unexplained failure.
					raise KerberosReplyMalformedError(
						'Malformed or truncated KDC reply from %s (%d bytes): %s' % (self.get_addr_str(), len(packet), e)
					) from e

			elif self.target.protocol == UniProto.CLIENT_UDP:
				raise Exception('Not implemented!')

			return krb_message
		finally:
			if connection is not None:
				await connection.close()


