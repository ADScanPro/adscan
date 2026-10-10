from pathlib import PureWindowsPath, PurePath, Path
from aiosmb.wintypes.access_mask import FileAccessMask
from aiosmb.protocol.smb2.commands import *
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass
from aiosmb.protocol.smb2.commands.query_info import SecurityInfo
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes

import io
import datetime
import asyncio
from contextlib import asynccontextmanager
from aiosmb.connection import SMBConnection
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from aiosmb.commons.utils.tschecker import tssplit
from aiosmb.protocol.smb2.commands.create import CREATE_TIMEWARP_TOKEN

class SMBFile:
	def __init__(self):
		self.tree_id = None
		self.parent_dir = None
		self.fullpath:str = None
		self.unc_path:str = None
		self.share_path:str = None
		self.name:str = None
		self.size:int = None
		self.creation_time:datetime.datetime = None
		self.last_access_time:datetime.datetime = None
		self.last_write_time:datetime.datetime = None
		self.change_time:datetime.datetime = None
		self.allocation_size:datetime.datetime = None
		self.attributes:FileAttributes = None
		self.file_id:int = None
		self.security_descriptor:SECURITY_DESCRIPTOR = None
		self.vstimestamp:str = None
		#internal
		self.__connection = None
		self.__position = 0
		self.is_pipe = False
		self.maxreadsize = None
		self.mode = ''
	
	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc_val, exc_tb):
		await self.close()

	def get_vscopy(self, vstimestamp:str = None):
		if vstimestamp is None:
			return SMBFile.from_uncpath(self.unc_path)
		return SMBFile.from_uncpath(self.unc_path + vstimestamp)

	@staticmethod
	def prepare_mirror_path(basedir:str, unc_path:str, path_with_file = True):
		unc_path = unc_path.lstrip('\\')
		unc = PureWindowsPath('\\\\\\\\' + unc_path)
		host = unc.parts[1].replace('.'	, '_')
		share = unc.parts[2]
		if share.find('$') != -1:
			share = share[:-1] + '_'
		if path_with_file is True:
			dirs = [host, share] + list(unc.parts[3:-1])
		else:
			dirs = [host, share] + list(unc.parts[3:])
		path_to_create = Path(basedir).joinpath(*dirs).resolve()
		return path_to_create
	
	@staticmethod
	def from_uncpath(unc_path:str):
		"""
		Creates SMBFile object from the UNC path supplied.
		Example uncpath: \\\\127.0.0.1\\C$\\temp\\test.exe
		"""
		unc = PureWindowsPath(unc_path)
		f = SMBFile()
		f.share_path = unc.drive
		f.name, f.vstimestamp = tssplit(unc.name)
		f.fullpath = '\\'.join(list(unc.parts[1:-1])+[f.name])
		f.unc_path = unc_path

		return f

	@staticmethod
	def from_remotepath(connection:SMBConnection, remotepath:str):
		"""
		Creates SMBFile object from the connection and the remote path supplied.
		Example remotepath: \\C$\\temp\\test.exe
		"""
		temp = '\\\\%s\\%s'
		if remotepath[0] == '\\':
			temp = '\\\\%s%s'
		unc = temp % (connection.target.get_hostname_or_ip(), remotepath)
		return SMBFile.from_uncpath(unc)
	
	@staticmethod
	def from_smbtarget(target:str):
		"""
		Creates SMBFile object from the SMBUrl object
		"""
		if target.path is None:
			return None
		
		fpath = target.path.replace('/','\\')
		if fpath.startswith('\\') is False:
			fpath = '\\' + fpath
		temp = '\\\\%s%s'
		unc = temp % (target.get_hostname_or_ip(), fpath)
		return SMBFile.from_uncpath(unc)

	@staticmethod
	def from_pipename(connection:SMBConnection, pipename:str):
		return SMBFile.from_uncpath('\\\\%s\\IPC$\\%s' % (connection.target.get_hostname_or_ip(), pipename))

	@staticmethod
	async def delete_unc(connection:SMBConnection, remotepath:str):
		try:
			remfile = SMBFile.from_uncpath(remotepath)
			tree_entry, err = await connection.tree_connect(remfile.share_path)
			if err is not None:
				raise err
			tree_id = tree_entry.tree_id

			desired_access = FileAccessMask.DELETE | FileAccessMask.FILE_READ_ATTRIBUTES
			share_mode = ShareAccess.FILE_SHARE_DELETE
			create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE 
			create_disposition = CreateDisposition.FILE_OPEN
			file_attrs = 0

			file_id, err = await connection.create(tree_id, remfile.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = False)
			if err is not None:
				raise err
			if file_id is not None:
				await connection.close(tree_id, file_id)

			await connection.tree_disconnect(tree_id)
			return True, None
		
		except Exception as e:
			return False, e

	@staticmethod
	async def delete_rempath(connection:SMBConnection, remotepath:str):
		try:
			remfile = SMBFile.from_remotepath(connection, remotepath)
			tree_entry, err = await connection.tree_connect(remfile.share_path)
			if err is not None:
				raise err
			tree_id = tree_entry.tree_id

			desired_access = FileAccessMask.DELETE | FileAccessMask.FILE_READ_ATTRIBUTES
			share_mode = ShareAccess.FILE_SHARE_DELETE
			create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE 
			create_disposition = CreateDisposition.FILE_OPEN
			file_attrs = 0

			file_id, err = await connection.create(tree_id, remfile.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = False)
			if err is not None:
				raise err
			if file_id is not None:
				await connection.close(tree_id, file_id)

			await connection.tree_disconnect(tree_id)
			return True, None
		
		except Exception as e:
			return False, e

	async def delete(self):
		"""Deletes the file. If the file is open, a flush will be performed followed by a close then a delete."""
		try:
			await self.close()
			#remfile = SMBFile.from_remotepath(connection, remotepath)
			tree_entry, err = await self.__connection.tree_connect(self.share_path)
			if err is not None:
				raise err
			tree_id = tree_entry.tree_id

			desired_access = FileAccessMask.DELETE | FileAccessMask.FILE_READ_ATTRIBUTES
			share_mode = ShareAccess.FILE_SHARE_DELETE
			create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE 
			create_disposition = CreateDisposition.FILE_OPEN
			file_attrs = 0

			file_id, err = await self.__connection.create(
				tree_id, 
				self.fullpath, 
				desired_access, 
				share_mode, 
				create_options, 
				create_disposition, 
				file_attrs, 
				return_reply = False
			)

			if err is not None:
				raise err
			if file_id is not None:
				await self.__connection.close(tree_id, file_id)

			await self.__connection.tree_disconnect(tree_id)
			return True, None
		
		except Exception as e:
			return False, e

	async def get_security_descriptor(self, connection:SMBConnection):
		"""Fetches the security descriptor of the file."""
		if self.security_descriptor is None:
			file_id = None
			try:
				tree_id = self.tree_id
				if self.tree_id is None:
					tree_entry, err = await connection.tree_connect(self.share_path)
					if err is not None:
						raise err
					tree_id = tree_entry.tree_id

				desired_access = FileAccessMask.READ_CONTROL
				share_mode = ShareAccess.FILE_SHARE_READ
				create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT 
				file_attrs = 0
				create_disposition = CreateDisposition.FILE_OPEN

				if self.vstimestamp is not None:
					create_context = [CREATE_TIMEWARP_TOKEN.from_timestamp(self.vstimestamp)]
				else:
					create_context = []
				file_id, err = await connection.create(tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, create_contexts=create_context)
				if err is not None:
					raise err

				self.security_descriptor, err = await connection.query_info(
					tree_id,
					file_id,
					info_type = QueryInfoType.SECURITY, 
					information_class = FileInfoClass.NONE, 
					additional_information = SecurityInfo.ATTRIBUTE_SECURITY_INFORMATION | SecurityInfo.DACL_SECURITY_INFORMATION | SecurityInfo.OWNER_SECURITY_INFORMATION | SecurityInfo.GROUP_SECURITY_INFORMATION, 
					flags = 0, 
				)
				if err is not None:
					raise err
			except Exception as e:
				return None, e

			finally:
				if file_id is not None:
					await connection.close(tree_id, file_id)
				if tree_id is not None and self.tree_id is None:
					await connection.tree_disconnect(tree_id)

		return self.security_descriptor, None

	async def __read(self, size:int, offset:int):
		"""
		This is the main function for reading.
		It does not do buffering, so if more data is returned it will just discard it
		If less data is returned than requested it will do more reads until the requested size is reached.
		Do not call this directly as it could go in an infinite loop 
		"""
		if self.is_pipe == True:
			data, remaining, err = await self.__connection.read(self.tree_id, self.file_id, offset = offset, length = size)
			return data, err
			
		buffer = b''
		if size > self.__connection.MaxReadSize:
			i = size // self.__connection.MaxReadSize
			for _ in range(i+1):
				data, remaining, err = await self.__connection.read(self.tree_id, self.file_id, offset = offset, length = self.__connection.MaxReadSize)
				if err is not None:
					return None, err
				offset += len(data)
				buffer += data
				
			return buffer[:size], err
		else:
			data, remaining, err = await self.__connection.read(self.tree_id, self.file_id, offset = offset, length = self.__connection.MaxReadSize)
			if err is not None:
				return None, err
			buffer += data
				
			return buffer[:size], err

	async def __write(self, data:bytes, position_in_file:int = 0):
		"""
		Data must be bytes
		"""
		try:
			remaining = len(data)
			total_bytes_written = 0
			offset = 0
				
			while remaining != 0:
				bytes_written, err = await self.__connection.write(self.tree_id, self.file_id, data[offset:len(data)], offset = position_in_file + offset)
				if err is not None:
					raise err
				total_bytes_written += bytes_written
				remaining -= bytes_written
				offset += bytes_written
				
			return total_bytes_written, None
		except Exception as e:
			return None, e

	async def open(self, connection:SMBConnection, mode:str = 'r', share_mode = None):
		try:
			self.__connection = connection
			self.maxreadsize = connection.MaxReadSize
			self.mode = mode
			if 'p' in self.mode:
				self.is_pipe = True
				self.size = 0
			
			if not self.tree_id:
				tree_entry, err = await connection.tree_connect(self.share_path)
				if err is not None:
					raise err
				self.tree_id = tree_entry.tree_id
			

			#then connect to file
			if 'r' in mode and 'w' in mode:
				raise ValueError('must have exactly one of read/write mode')
				
			if 'r' in mode:
				desired_access = FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_READ_ATTRIBUTES
				share_mode = ShareAccess.FILE_SHARE_READ if share_mode is None else share_mode
				create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT 
				file_attrs = 0
				create_disposition = CreateDisposition.FILE_OPEN

				if self.vstimestamp is not None:
					create_context = [CREATE_TIMEWARP_TOKEN.from_timestamp(self.vstimestamp)]
				else:
					create_context = []
				
				self.file_id, smb_reply, err = await connection.create(self.tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, create_contexts=create_context, return_reply = True)
				if err is not None:
					raise err
				self.size = smb_reply.EndofFile
				
			elif 'w' in mode:
				if self.vstimestamp is not None:
					raise Exception('Cannot write to a file with a timestamp!')

				desired_access = FileAccessMask.GENERIC_READ | FileAccessMask.GENERIC_WRITE
				share_mode = ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE if share_mode is None else share_mode
				create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT 
				file_attrs = 0
				create_disposition = CreateDisposition.FILE_OPEN_IF #FILE_OPEN ? might cause an issue?
				
				self.file_id, smb_reply, err = await connection.create(self.tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = True)
				if err is not None:
					raise err
				self.size = smb_reply.EndofFile
				
			else:
				raise Exception('ONLY read and write is supported at the moment!')
			
			return True, None
		except Exception as e:
			return False, e

	async def open_rpc_pipe(self, connection:SMBConnection):
		"""Open a DCE/RPC named pipe (e.g. \\pipe\\winreg) for the transport.

		Matches impacket's smbconnection.openFile() DEFAULTS byte-for-byte on
		the SMB2 CREATE request, instead of the generic write-mode open()'s
		GENERIC_READ|GENERIC_WRITE / FILE_SHARE_READ|FILE_SHARE_WRITE /
		FILE_SYNCHRONOUS_IO_NONALERT / FILE_OPEN_IF combination (which
		DCERPCSMBTransport.connect() previously used via open(mode='wp') --
		correct for a generic read/write FILE, but never audited against what
		impacket's own named-pipe client actually requests).

		Four fields differ from the generic open():
		  desiredAccess:      FILE_READ_DATA|FILE_WRITE_DATA   (not GENERIC_*)
		  shareMode:          FILE_SHARE_READ only             (not +WRITE)
		  createOptions:      FILE_NON_DIRECTORY_FILE only     (no SYNCHRONOUS_IO_NONALERT)
		  createDisposition:  FILE_OPEN                        (not FILE_OPEN_IF)

		Why this matters (live finding 2026-10-07, a CrowdStrike-protected
		host): this SMB2 CREATE happens ONCE, before any DCE/RPC traffic
		flows over the pipe, and governs the access check applied to every
		subsequent WRITE/READ on it. Requesting a broader, less standard
		access/share/option combination than impacket's own named-pipe client
		is exactly the class of "raw SMB2 framing" divergence
		BACKLOG.md's PIPE_BROKEN entry flagged as the remaining suspect once
		the DCE/RPC-payload-level comparison came up byte-identical.
		"""
		try:
			self.__connection = connection
			self.is_pipe = True
			self.size = 0
			self.mode = 'rwp'

			if not self.tree_id:
				tree_entry, err = await connection.tree_connect(self.share_path)
				if err is not None:
					raise err
				self.tree_id = tree_entry.tree_id

			desired_access = FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA
			share_mode = ShareAccess.FILE_SHARE_READ
			create_options = CreateOptions.FILE_NON_DIRECTORY_FILE
			create_disposition = CreateDisposition.FILE_OPEN
			file_attrs = FileAttributes.FILE_ATTRIBUTE_NORMAL

			self.file_id, smb_reply, err = await connection.create(self.tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = True)
			if err is not None:
				raise err
			self.size = smb_reply.EndofFile

			return True, None
		except Exception as e:
			return False, e

	async def download(self, connection:SMBConnection ,local_path:str, share_mode = ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE):
		"""Downloads the file to the local path. File must not be open."""
		try:
			# if treeid is already present, we won't be closing it after download
			closetree = True if self.tree_id is None else False
			if self.is_pipe:
				raise Exception('Cannot download a pipe!')
			if self.__connection is not None:
				raise Exception('Cannot download a file that is already open!')
			
			_, err = await self.open(connection, 'r', share_mode = share_mode)
			if err is not None:
				raise err
			
			local_path = Path(local_path)
			if local_path.is_dir():
				local_path = local_path.joinpath(self.name)
			
			with open(local_path, 'wb') as f:
				async for data, err in self.read_chunked():
					if err is not None:
						raise err
					if not data:
						break
					f.write(data)
			
			return str(local_path.absolute()), None
		except Exception as e:
			return None, e #this should return "None, e" and NOT "False, e"
		finally:
			await self.close()
			if self.tree_id is not None and closetree is True:
				await connection.tree_disconnect(self.tree_id)
		
	async def open_pipe(self, connection:SMBConnection, mode:str):
		try:
			self.__connection = connection
			self.is_pipe = True
			self.size = 0
			share_mode = 0
			file_attrs = 0x80
			create_options = 0
			create_disposition = CreateDisposition.FILE_OPEN
			desired_access = 0
			if 'r' in mode:
				desired_access |= FileAccessMask.FILE_READ_DATA
			if 'w' in mode:
				desired_access |= FileAccessMask.FILE_WRITE_DATA

			tree_entry, err = await self.__connection.tree_connect(self.share_path)
			if err is not None:
				raise err
			self.tree_id = tree_entry.tree_id
			self.file_id, smb_reply, err = await self.__connection.create(self.tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = True)
			if err is not None:
				raise err

			return True, None
		except Exception as e:
			return False, e
		
		
	async def seek(self, offset:int, whence:int = 0):
		"""Sets the current position of the file buffer to the given offset."""
		try:
			if whence == 0:
				if offset < 0:
					raise Exception('Offset must be > 0 when whence is 0')
				if offset > self.size:
					raise Exception('Seeking outside of file size!')
				self.__position = offset
			
			elif whence == 1:
				if 0 < self.__position + offset < self.size:
					self.__position += offset
				else:
					raise Exception('Seeking outside of file size!')
			
			elif whence == 2:
				if 0 < self.size + offset < self.size:
					self.__position = self.size + offset
				else:
					raise Exception('Seeking outside of file size!')
			
			return True, None
		except Exception as e:
			return None, e
		
	async def read(self, size:int = -1):
		try:
			if self.is_pipe is True:
				if size == -1:
					size = self.__connection.MaxReadSize
				data, err = await self.__read(size, 0)
				return data, err
			
			if size > self.size:
				size = -1
				#raise Exception('Requested read size %s is larger than the file size %s' % (hex(size), hex(self.size)))

			if size == 0:
				return b'', None
				#raise Exception('Cant read 0 bytes')
				
			elif size == -1:
				if self.__position == self.size:
					return b'', None
				data, err = await self.__read(self.size - self.__position, self.__position)
				if err is not None:
					raise err
				self.__position += len(data)
				
				return data, err
				
			elif size > 0:
				if self.__position == self.size:
					return b'', None
				if size + self.__position > self.size:
					size = self.size - self.__position
				data, err = await self.__read(size, self.__position)
				if err is not None:
					raise err
				self.__position += len(data)
				return data, err

		except Exception as e:
			return None, e

	async def read_chunked(self, size:int = -1, chunksize:int = -1):
		"""
		Much like read, but yields chuks of chunksize untill the full size is read
		Use this when reading large files as a whole, as this method doesn't caches 
		the whole data read in memory, only chunskize
		chunksize -1 will use the maximum chunk allowed by the underlying connection layer, it is advised to not set manually!
		"""
		if self.is_pipe is True:
			raise Exception('Cant stream pipes!')

		if chunksize == -1:
			chunksize = self.__connection.MaxReadSize

		if size == 0:
			yield None, None
			
		elif size == -1:
			while True:
				req_size = chunksize
				if self.size - self.__position < chunksize:
					req_size = self.size - self.__position
					if req_size == 0:
						#consumed all data
						yield None, None
						raise StopIteration

				data, err = await self.__read(req_size, self.__position)
				if err is None:
					self.__position += len(data)
				yield data, err
			
		elif size > 0:
			if self.__position == self.size:
				yield None, None
				raise StopIteration
			if size + self.__position > self.size:
				size = self.size - self.__position

			while True:
				req_size = chunksize
				if size - self.__position < chunksize:
					req_size = size - self.__position
				if req_size == 0:
					yield None, None
					raise StopIteration
				data, err = await self.__read(req_size, self.__position)
				if err is None:
					self.__position += len(data)
				yield data, err
			
	async def write(self, data:bytes):
		"""Writes the given bytes to the file from the current position."""
		try:
			if len(data) < self.__connection.MaxWriteSize:
				count, err = await self.__write(data, self.__position)
				if err is not None:
					raise err
				if self.is_pipe == False:
					self.__position += count
				return count, None

			total_writen = 0

			while total_writen != len(data) :
				count, err = await self.__write(data[total_writen:total_writen+self.__connection.MaxWriteSize], self.__position)
				if err is not None:
					raise err
				total_writen += count
				if self.is_pipe == False:
					self.__position += count		

			return total_writen, None
		
		except Exception as e:
			return None, e

	async def write_buffer(self, buffer:io.BytesIO):
		"""Writes the contents of the buffer(or file handle) to the file. Doesnt work with pipes!"""
		try:
			if self.is_pipe == True:
				raise Exception('Doesnt work with pipes!')
			
			total_writen = 0
			while True:
				await asyncio.sleep(0) #to make sure we are not consuming all CPU
				chunk = buffer.read(self.__connection.MaxWriteSize)
				if len(chunk) == 0:
					return total_writen, None
				bytes_written, err = await self.__write(chunk, self.__position)
				if err is not None:
					raise err

				self.__position += bytes_written
				total_writen += bytes_written
			return total_writen, None
		except Exception as e:
			return None, e
		
	async def flush(self):
		"""Issues a flush command on the SMB protocol"""
		if 'w' not in self.mode:
			return
		await self.__connection.flush(self.tree_id, self.file_id)			
		
	async def close(self):
		"""Closes the file including the fileId"""
		if self.file_id is None:
			return
		if self.tree_id is None:
			return
		
		try:
			await self.flush()
		except:
			pass
		await self.__connection.close(self.tree_id, self.file_id)
	
	def tell(self) -> int:
		"""Returns current position in file"""
		return self.__position
		
	def __str__(self):
		t = '===== FILE =====\r\n'
		for k in self.__dict__:
			if k.startswith('parent_'):
				continue
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		
		return t

@asynccontextmanager
async def smb_open(path:str, mode = 'r', connection = None) -> SMBFile:
	"""
	Opens a file on the remote server
	path can be a smb:// url or a path like \\\\server\\share\\path\\to\\file
	"""
	try:
		if path.lower().startswith('smb'):
			from aiosmb.commons.connection.factory import SMBConnectionFactory
			factory = SMBConnectionFactory.from_url(path)
			if connection is None:
				connection = factory.get_connection()
				async with connection:
					_, err = await connection.login()
					if err is not None:
						raise err
					file = factory.get_file()
					_, err = await file.open(connection, mode)
					if err is not None:
						raise err
					yield file
					return
			else:
				file = factory.get_file()
				_, err = await file.open(connection, mode)
				if err is not None:
					raise err
				yield file
				return
		else:
			file = SMBFile.from_remotepath(connection, path)
			_, err = await file.open(connection, mode)
			if err is not None:
				raise err
			yield file
			return
	finally:
		if file is not None:
			await file.close()


async def amain():
	url = 'smb2+ntlm-password://TEST\\Administrator:Passw0rd!1@10.10.10.2/C$/temp/repodata.json'
	async with smb_open(url, 'rb') as f:
		data, err = await f.read(1024)
		print(data)
		print(len(data))
	
	from aiosmb.commons.connection.factory import SMBConnectionFactory
	connection = SMBConnectionFactory.from_url(url).get_connection()
	_, err = await connection.login()
	if err is not None:
		raise err
		
	async with smb_open('C$/temp/repodata.json', 'rb', connection=connection) as f:
		while True:
			data, err = await f.read(1024)
			print(data)
			print(len(data))
			if data == b'':
				break

	async with smb_open('C$/temp/repodata1.json', 'wb', connection=connection) as f:
		_, err = await f.write(b'HELLO')
		if err is not None:
			print(err)
	
	async with smb_open('C$/temp/repodata1.json', 'rb', connection=connection) as f:
		data, err = await f.read(1024)
		if err is not None:
			print(err)
			return
		print(data)
		print(len(data))
	
	print('DONE!')

if __name__ == '__main__':
	import asyncio
	asyncio.run(amain())

