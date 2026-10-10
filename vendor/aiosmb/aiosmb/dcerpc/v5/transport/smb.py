
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.dcerpc.v5.rpcrt import MSRPCRespHeader

class DCERPCSMBTransport:
	def __init__(self, target):
		self.target = target
		self.smbfile = None
		
		self._max_send_frag = None
		self._recv_buffer = b''

	def get_session_key(self):
		return self.target.smb_connection.get_session_key()
	
	async def connect(self):
		# TODO: if the smb connection is not set up, we need to set it up
		try:
			unc_path = '\\\\%s\\%s%s' % (self.target.smb_connection.target.get_hostname_or_ip(), 'IPC$', self.target.pipe)
			self.smbfile = SMBFile.from_uncpath(unc_path)
			# open_rpc_pipe() matches impacket's own named-pipe CREATE request
			# byte-for-byte (desiredAccess/shareMode/createOptions/
			# createDisposition) -- see its docstring. The generic open(mode=
			# 'wp') used a broader, non-standard combination of these four
			# fields; see BACKLOG.md's PIPE_BROKEN entry for why this matters.
			_, err = await self.smbfile.open_rpc_pipe(self.target.smb_connection)
			return True, err
		except Exception as e:
			return None, e

	async def disconnect(self):
		try:
			await self.smbfile.close()
		except Exception as e:
			return None, e
	
	async def send(self, data, forceWriteAndx = 0, forceRecv = 0):
		try:
			if self._max_send_frag:
				offset = 0
				while 1:
					toSend = data[offset:offset+self._max_send_frag]
					if not toSend:
						break
					total_writen, err = await self.smbfile.write(toSend)
					if err is not None:
						raise err
					offset += len(toSend)
					
			else:
				total_writen, err = await self.smbfile.write(data)
				if err is not None:
					raise err
			
			return True, None
		except Exception as e:
			return None, e

	# old
	#async def recv(self, count): #async def recv(self, forceRecv = 0, count = 0):
	#	try:
	#		#print(count)
	#		data, err = await self.smbfile.read(count)
	#		#print('recv %s' % repr(data))
	#		return data, err
	#	except Exception as e:
	#		return None, e


	# old
	#async def recv(self, count):
	#	try:
	#		hdr_data, err = await self.smbfile.read(24)
	#		if err is not None:
	#			raise err
	#		response_header = MSRPCRespHeader(hdr_data)
	#
	#		msg_data, err = await self.smbfile.read(response_header['frag_len'])
	#		if err is not None:
	#			raise err
	#
	#		return hdr_data+msg_data, None
	#	except Exception as e:
	#		return None, e
		

	async def recv(self, count):
		try:
			if len(self._recv_buffer) >= 24:
				tbuff = self._recv_buffer
				self._recv_buffer = b''
				return tbuff, None

			hdr_data, err = await self.smbfile.read() # this will read MaxReadSize bytes
			if err is not None:
				raise err
			hdr_data += self._recv_buffer
			self._recv_buffer = b''
			response_header = MSRPCRespHeader(hdr_data)

			dlen = len(hdr_data)

			if response_header['frag_len'] == dlen:
				return hdr_data, None
			
			if dlen > response_header['frag_len']:
				self._recv_buffer = hdr_data[response_header['frag_len']:]
				return hdr_data[:response_header['frag_len']], None
			
			body_len = response_header['frag_len'] - len(hdr_data)
			msg_data, err = await self.smbfile.read(body_len)
			if err is not None:
				raise err

			return hdr_data + msg_data, None
		except Exception as e:
			return None, e