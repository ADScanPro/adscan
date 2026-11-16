
import socket

from kerbad.protocol.asn1_structs import KerberosResponse
from kerbad.protocol.errors import KerberosErrorCode, KerberosError, KerberosReplyMalformedError
from asysocks.unicomm.common.target import UniProto

class KerberosClientSocket:
	def __init__(self, target):
		self.target = target
		self.soc_type = target.protocol
		self.dst_ip = target.get_hostname_or_ip()
		self.dst_port = int(target.port)
		self.soc = None
		
	def __str__(self):
		t = '===KerberosClientSocket===\r\n'
		t += 'soc_type: %s\r\n' % self.soc_type
		t += 'dst_ip: %s\r\n' % self.dst_ip
		t += 'dst_port: %s\r\n' % self.dst_port
		
		return t

	def get_addr_str(self):
		return '%s:%d' % (self.dst_ip, self.dst_port)
		
	def create_soc(self):
		if self.soc_type == UniProto.CLIENT_TCP:
			self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.soc.connect((self.dst_ip, self.dst_port))

		elif self.soc_type == UniProto.CLIENT_UDP:
			self.soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			
		else:
			raise Exception('Unknown socket type!')
			
	def sendrecv(self, data, throw = True):
		#throw variable indicates wether to create an exception when a kerberos error happens or just return the kerberos error"
		#for any other exceptions types (eg. connection related errors) an exception will be raised regardless

		self.create_soc()
		try:
			if self.soc_type == UniProto.CLIENT_TCP:
				length = len(data).to_bytes(4, byteorder = 'big', signed = False)
				self.soc.sendall(length + data)
				buff = b''
				total_length = -1
				while True:
					temp = b''
					temp = self.soc.recv(4096)
					if temp == b'':
						if buff != b'':
							# The peer closed with the record mark (and possibly part
							# of the message) still in the buffer: never hand that to
							# the asn1 decoder as if it were a reply.
							raise KerberosReplyMalformedError(
								'The KDC at %s closed the connection before a complete reply was received (truncated KDC reply)' % self.get_addr_str()
							)
						break
					buff += temp
					if total_length == -1:
						if len(buff) >= 4:
							total_length = int.from_bytes(buff[:4], byteorder = 'big', signed = False)
							if total_length == 0:
								raise Exception('Returned data length is 0! This means the server did not understand our message')
					
					if total_length != -1:
						if len(buff) == total_length + 4:
							buff = buff[4:]
							break
						elif len(buff) > total_length + 4:
							raise Exception('Got too much data somehow')
						else:
							continue
							
				
			elif self.soc_type == UniProto.CLIENT_UDP:
				self.soc.sendto(data, (self.dst_ip, self.dst_port))
				while True:
					buff, addr = self.soc.recvfrom(65535)
					if addr[0] == self.dst_ip:
						break
					else:
						# got a message from a different IP than the target, strange!
						# continuing, but this might result in an infinite loop
						continue
			if buff == b'':
				raise Exception('Server closed the connection!')
			try:
				krb_message = KerberosResponse.load(buff)
			except (ValueError, TypeError) as e:
				raise KerberosReplyMalformedError(
					'Malformed or truncated KDC reply from %s (%d bytes): %s' % (self.get_addr_str(), len(buff), e)
				) from e
			if krb_message.name == 'KRB_ERROR' and throw == True:
				raise KerberosError(krb_message)
			return krb_message
		finally:
			self.soc.close()
