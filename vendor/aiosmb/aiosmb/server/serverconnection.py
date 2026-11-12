import enum
import io
import asyncio
import datetime
import traceback
import typing
from dataclasses import dataclass, field
from pathlib import Path

from aiosmb import logger
from aiosmb.commons.exceptions import *
from aiosmb.protocol.smb.command_codes import SMBCommand
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.protocol.smb.message import SMBMessage
from aiosmb.protocol.smb.commands import *
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.protocol.smb2.commands.tree_connect import *
from aiosmb.protocol.smb2.commands import *
from aiosmb.protocol.smb2.headers import *
from aiosmb.protocol.smb2.command_codes import *
from aiosmb.protocol.common import *
from aiosmb.wintypes.dtyp.constrcuted_security.guid import *
from aiosmb.protocol.smb2.commands.sessionsetup import *
from aiosmb.protocol.smb2.commands.create import *
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass


def convert_to_ft(linux_filetime:int):
	return int((linux_filetime + 11644473600) * 10000000)

class SMBConnectionStatus(enum.Enum):
	NEGOTIATING = 'NEGOTIATING'
	SESSIONSETUP = 'SESSIONSETUP'
	RUNNING = 'RUNNING'
	CLOSED = 'CLOSED'

@dataclass
class FileEntry:
	file_id:int = None
	path:Path = None
	handle:io.FileIO = None

@dataclass
class TreeEntry:
	file_entries:dict[int, FileEntry] = field(default_factory=dict)
	hostname:str = None
	path:Path = None
	tree_id:int = None

@dataclass
class DirEnumState:
	entries:list[str] = field(default_factory=list)
	index:int = 0
	pattern:str = '*'
	info_class:FileInfoClass = None



class SMBServerConnection:
	def __init__(self, settings, connection, connection_id, shutdown_evt = None):
		self.settings = settings
		self.gssapi = self.settings.create_new_gssapi(connection)
		self.connection_id = connection_id
		
		#######DONT CHANGE THIS
		#use this for smb2 > self.supported_dialects = [NegotiateDialects.WILDCARD, NegotiateDialects.SMB202, NegotiateDialects.SMB210]
		#self.supported_dialects = [NegotiateDialects.SMB202, NegotiateDialects.SMB210]
		self.supported_dialects = self.settings.preferred_dialects #[NegotiateDialects.WILDCARD, NegotiateDialects.SMB311]
		#######
		
		self.connection = connection
		self.incoming_task = None
		
		self.selected_dialect = None
		self.signing_required = self.settings.RequireSigning
		self.encryption_required = False
		self.last_treeid = 10
		
		self.status = SMBConnectionStatus.NEGOTIATING
		
		self.OutstandingResponsesEvent = {}
		self.OutstandingRequests = {}
		self.OutstandingResponses = {}

		self.pending_table = {}
		
		self.SequenceWindow = 0
		self.MaxTransactSize = self.settings.MaxTransactSize
		self.MaxReadSize = self.settings.MaxReadSize
		self.MaxWriteSize = self.settings.MaxWriteSize
		self.ServerGuid = self.settings.ServerGuid

		self.SupportsFileLeasing = False
		self.SupportsMultiCredit = False
		
		self.SupportsDirectoryLeasing = False
		self.SupportsMultiChannel = False
		self.SupportsPersistentHandles = False
		self.SupportsEncryption = False
		self.ClientCapabilities = 0
		self.ServerCapabilities = NegotiateCapabilities.LARGE_MTU #NegotiateCapabilities.DFS | NegotiateCapabilities.LARGE_MTU
		self.ClientSecurityMode = 0
		self.ServerSecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
		if self.signing_required is True:
			self.ServerSecurityMode |= NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
		
		self.SessionId = 0
		self.SessionKey = None

		self.last_treeid = 1

		self.__treeid_to_entry = {}

	async def run(self):
		self.incoming_task = asyncio.create_task(self.__handle_smb_in())
		return self.incoming_task
	
	async def stop(self):
		try:
			await self.print('[INF] Stopping connection')
			if self.incoming_task is not None:
				self.incoming_task.cancel()
			if self.connection is not None:
				await self.connection.close()
		except Exception as e:
			traceback.print_exc()
			await self.print('[ERR] %s' % e)

	async def print(self, msg):
		if self.settings.log_callback is not None:
			await self.settings.log_callback(f'[SMBSERVERCONN][{self.connection_id}] {msg}')

	def get_new_tree_id(self):
		self.last_treeid += 1
		return self.last_treeid

	async def __handle_smb_in(self):
		"""
		Waits from SMB message bytes from the transport in_queue, and fills the connection table.
		This function started automatically when calling connect.
		Pls don't touch it.
		"""
		try:
			async for msg_data in self.connection.read():
				if msg_data is None:
					break
				
				if msg_data[0] < 252:
					raise Exception('Unknown SMB packet type %s' % msg_data[0])

				if msg_data[0] == 0xFD:
					raise Exception('SMB2_COMPRESSED_DATA_HEADER is not implemented yet')

				if msg_data[0] == 0xFC:
					raise Exception('SMB2_COMPRESSED_TRANSFORM_HEADER is not implemented yet')
					
				if msg_data[0] == 0xFE:
					#version2
					try:
						msg = SMB2Message.from_bytes(msg_data)
						await self.print('[PACKET] %s' % msg)
					except Exception as e:
						raise Exception('Failed to parse SMB data. Probably not implemented feature.')

					if self.status == SMBConnectionStatus.NEGOTIATING:
						await self.negotiate(msg)
					elif self.status == SMBConnectionStatus.SESSIONSETUP:
						await self.session_setup(msg)
					
					elif self.status == SMBConnectionStatus.RUNNING:
						if msg.header.Command == SMB2Command.TREE_CONNECT:
							await self.tree_connect(msg)
						elif msg.header.Command == SMB2Command.CREATE:
							await self.create(msg)
						elif msg.header.Command == SMB2Command.IOCTL:
							await self.ioctl(msg)
						elif msg.header.Command == SMB2Command.ECHO:
							await self.echo(msg)
						elif msg.header.Command == SMB2Command.QUERY_DIRECTORY:
							await self.query_directory(msg)
						elif msg.header.Command == SMB2Command.CLOSE:
							await self.close(msg)
						else:
							print('SMB2 command not implemented! %s' % msg.header.Command)
							continue
				if msg_data[0] == 0xFF:
					#version1
					msg = SMBMessage.from_bytes(msg_data)
					await self.print('[PACKET] %s' % msg)
					if self.status == SMBConnectionStatus.NEGOTIATING:
						if msg.header.Command == SMBCommand.SMB_COM_NEGOTIATE:
							await self.negotiate(msg)
					else:
						print('SMBv1 message recieved! This is unexpected! %s' % msg.header.Command)
						continue

				logger.log(1, '__handle_smb_in got new message with Id %s' % msg.header.MessageId)

				if msg.header.MessageId in self.pending_table:
					await self.pending_table[msg.header.MessageId].stop()
					del self.pending_table[msg.header.MessageId]
				
		except asyncio.CancelledError:
			return
		except:
			traceback.print_exc()
		finally:
			await self.stop()
	
	async def sendSMB(self, msg, compression_cb = None):
		"""
		Sends an SMB message to teh remote endpoint.
		msg: SMB2Message or SMBMessage
		Returns: MessageId integer
		"""
		try:
			if self.status == SMBConnectionStatus.NEGOTIATING:
				if isinstance(msg, SMBMessage):
					message_id = 0
					self.SequenceWindow += 1
				else:
					msg.header.CreditCharge = 1
					if msg.header.CreditReq is None:
						msg.header.CreditReq = 1
					msg.header.MessageId = self.SequenceWindow
					message_id = self.SequenceWindow
					self.SequenceWindow += 1

				self.OutstandingResponsesEvent[message_id] = asyncio.Event()
				await self.connection.write(msg.to_bytes())
				return message_id, msg, None
					
			if msg.header.Command is not SMB2Command.CANCEL:
				msg.header.MessageId = self.SequenceWindow
				self.SequenceWindow += 1
			
			msg.header.SessionId = self.SessionId
			
			if not msg.header.CreditCharge:
				msg.header.CreditCharge = 1

			
			
			if self.status != SMBConnectionStatus.SESSIONSETUP and msg.header.CreditReq is None:
				msg.header.CreditReq = 127
			
			message_id = msg.header.MessageId
			#print(msg)

			#creating an event for outstanding response
			self.OutstandingResponsesEvent[message_id] = asyncio.Event()
			await self.connection.write(msg.to_bytes())
			
			return message_id, msg, None
		except Exception as e:
			traceback.print_exc()
			return None, None, e
		
	async def negotiate(self, req):
		try:
			if (isinstance(req, SMBMessage) and 'SMB 2.???' in req.command.Dialects) or isinstance(req, SMB2Message):
					#if NegotiateDialects.WILDCARD in self.supported_dialects:
					reply = SMB2Message()
					reply.command = NEGOTIATE_REPLY()
					reply.command.SecurityMode = self.ServerSecurityMode
					reply.command.DialectRevision = NegotiateDialects.SMB202
					reply.command.NegotiateContextCount = 0
					reply.command.ServerGuid = self.ServerGuid
					reply.command.Capabilities = self.ServerCapabilities
					reply.command.MaxTransactSize = self.MaxTransactSize
					reply.command.MaxReadSize = self.MaxReadSize
					reply.command.MaxWriteSize = self.MaxWriteSize
					reply.command.SystemTime = datetime.datetime.utcnow()
					reply.command.ServerStartTime = datetime.datetime.utcnow()
					reply.command.SecurityBuffer = self.gssapi.get_mechtypes_list()
					reply.command.NegotiateContextOffset = 0
					reply.command.NegotiateContextList = []
					
					reply.header = SMB2Header_SYNC()
					reply.header.Command  = SMB2Command.NEGOTIATE
					reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
					reply.header.CreditCharge = 1
					await self.sendSMB(reply)

					self.selected_dialect = NegotiateDialects.SMB202

					
					self.SupportsMultiChannel = NegotiateCapabilities.MULTI_CHANNEL in self.ServerCapabilities
					self.SupportsFileLeasing = NegotiateCapabilities.LEASING in self.ServerCapabilities
					self.SupportsMultiCredit = NegotiateCapabilities.LARGE_MTU in self.ServerCapabilities
					
					self.status = SMBConnectionStatus.SESSIONSETUP
			return
		except Exception as e:
			traceback.print_exc()

	async def session_setup(self, msg):
		err = None
		try:
			maxiter = 5
			if self.SessionId == 0:
				self.SessionId += 1
			while maxiter > 0:
				reply = SMB2Message()
				reply.command = SESSION_SETUP_REPLY()
				reply.command.SessionFlags = 0
				try:
					await self.print('[INF] Calling authenticate_server')
					#reply.command.Buffer, to_continue, err  = await self.gssapi.authenticate(msg.command.Buffer)
					reply.command.Buffer, to_continue, err  = await self.gssapi.authenticate_server(msg.command.Buffer)
					await self.print('[INF] Authenticate results: %s, %s, %s' % (reply.command.Buffer, to_continue, err))
					
					if err is not None:
						raise err
					
					if to_continue is False and reply.command.Buffer is None:
						reply = SMB2Message()
						reply.command = SESSION_SETUP_REPLY()
						reply.command.SessionFlags = SessionFlags.SMB2_SESSION_FLAG_IS_GUEST

						reply.command.Buffer, err  = await self.gssapi.authenticate_server_finished()

						if err is not None:
							raise err

						reply.header = SMB2Header_SYNC()
						reply.header.Command  = SMB2Command.SESSION_SETUP
						reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
						#reply.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SIGNED
						reply.header.SessionId = self.SessionId
						
						reply.header.CreditCharge = 1
						reply.header.CreditReq = 1
						reply.header.Status = NTStatus.SUCCESS
						#reply.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SIGNED
						
						await self.sendSMB(reply)
						#self.SessionKey = self.gssapi.get_session_key()[:16]
						self.status = SMBConnectionStatus.RUNNING
						return False, None
					
				except Exception as e:
					#TODO: Clear this up, kerberos lib needs it's own exceptions!
					if str(e).find('Preauth') != -1:
						raise SMBKerberosPreauthFailed()
					else:
						raise e
						#raise SMBKerberosPreauthFailed()
				
				if to_continue is True:
					reply.header = SMB2Header_SYNC()
					reply.header.Command  = SMB2Command.SESSION_SETUP
					reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
					reply.header.SessionId = self.SessionId
					
					reply.header.CreditCharge = 1
					reply.header.CreditReq = 1
					reply.header.Status = NTStatus.MORE_PROCESSING_REQUIRED
					await self.sendSMB(reply)
				
				if to_continue is False:
					reply.header = SMB2Header_SYNC()
					reply.header.Command  = SMB2Command.SESSION_SETUP
					reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
					reply.header.SessionId = self.SessionId
					
					reply.header.CreditCharge = 1
					reply.header.CreditReq = 1
					reply.header.Status = NTStatus.SUCCESS
					reply.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SIGNED
					reply.header.CreditReq = 127

					await self.sendSMB(reply)

					#self.SessionKey = self.gssapi.get_session_key()[:16]
					self.status = SMBConnectionStatus.RUNNING

				return True, None
		except Exception as e:
			await self.print('[ERR] %s' % e)

			reply.header = SMB2Header_SYNC()
			reply.header.Command  = SMB2Command.SESSION_SETUP
			reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
			reply.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SIGNED
			reply.header.SessionId = self.SessionId
			reply.header.CreditCharge = 1
			reply.header.CreditReq = 127
			reply.header.Status = NTStatus.ACCESS_DENIED
			await self.sendSMB(reply)
			return False, None # none because relay doesnt need to know the error


	async def tree_connect(self, msg:SMB2Message):
		try:
			command = typing.cast(TREE_CONNECT_REQ, msg.command)
			# command.Path like \\hostname\sharename
			reply = SMB2Message()
			reply.header = SMB2Header_SYNC()
			reply.header.Command = SMB2Command.TREE_CONNECT
			reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
			reply.header.SessionId = self.SessionId
			reply.header.CreditCharge = 1
			reply.header.CreditReq = msg.header.CreditReq
			reply.header.Status = NTStatus.SUCCESS
			reply.command = TREE_CONNECT_REPLY()
			# Parse sharename
			try:
				_,_,_, share_name, *rest = command.Path.split('\\')
				print('TREE_CONNECT: %s' % share_name)
				print(rest)
			except Exception:
				share_name = command.Path

			if share_name.upper().endswith('IPC$'):
				reply.command.ShareType = ShareType.PIPE
			else:
				reply.command.ShareType = ShareType.DISK

			reply.command.ShareFlags = ShareFlags.SMB2_SHAREFLAG_MANUAL_CACHING
			reply.command.Capabilities = TreeCapabilities.SMB2_SHARE_CAP_NONE
			reply.command.MaximalAccess = FileAccessMask.GENERIC_ALL

			# Map sharename to on-disk path from settings.shares
			mapped = None
			for k, v in self.settings.shares.items():
				if k.lower() == share_name.lower():
					mapped = Path(v)
					break
			if mapped is None:
				reply.header.Status = NTStatus.BAD_NETWORK_NAME
				#await self.sendSMB(reply)
				await self.sendSMB2(msg, SMB2Command.TREE_CONNECT, reply.command, NTStatus.BAD_NETWORK_NAME)
				return
			tree_id = self.get_new_tree_id()
			reply.header.TreeId = tree_id
			self.__treeid_to_entry[tree_id] = TreeEntry(hostname=None, path=mapped, tree_id=tree_id)

			await self.sendSMB(reply)
		except Exception as e:
			traceback.print_exc()
	
	async def ioctl(self, msg:SMB2Message):
		try:
			command = typing.cast(IOCTL_REQ, msg.command)
			if command.CtlCode == CtlCode.FSCTL_DFS_GET_REFERRALS:
				reply = SMB2Message()
				reply.header = SMB2Header_SYNC()
				reply.header.Command = SMB2Command.IOCTL
				reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
				reply.header.SessionId = self.SessionId
				reply.header.CreditCharge = 1
				reply.header.CreditReq = msg.header.CreditReq
				reply.header.Status = NTStatus.FS_DRIVER_REQUIRED
				reply.header.messageId = msg.header.MessageId
				# we're currently not handling the DFS_GET_REFERRALS
				reply.command = IOCTL_REPLY()
				reply.command.CtlCode = command.CtlCode
				reply.command.FileId = command.FileId
				reply.command.InputOffset = command.InputOffset
				reply.command.InputCount = command.InputCount
				reply.command.OutputOffset = 0
				reply.command.OutputCount = 0
				reply.command.Flags = command.Flags
				reply.command.Reserved2 = command.Reserved2
				reply.command.Buffer = b''
				#await self.sendSMB(reply)
				await self.sendSMB2(msg, SMB2Command.IOCTL, reply.command, NTStatus.FS_DRIVER_REQUIRED)

		except Exception as e:
			traceback.print_exc()
		
	async def create(self, msg:SMB2Message):
		try:
			command = typing.cast(CREATE_REQ, msg.command)
			handle = None
			if command.Name is None:
				# this means we want to open the share which was specified in tree connect
				share = self.__treeid_to_entry[msg.header.TreeId].path
				print('OPENING SHARE %s' % share.name)
				# this must be a directory
				if not (share.exists() and share.is_dir()):
					raise Exception('Share %s does not exist' % share.name)
				
				reply = SMB2Message()
				reply.header = SMB2Header_SYNC()
				reply.header.Command = SMB2Command.CREATE
				reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
				reply.header.SessionId = self.SessionId
				reply.header.CreditCharge = 1
				reply.header.CreditReq = msg.header.CreditReq
				reply.header.Status = NTStatus.SUCCESS
				reply.command = CREATE_REPLY()
				reply.command.OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
				reply.command.Flags = CreateOptions.FILE_WRITE_THROUGH
				reply.command.CreateAction = CreateAction.FILE_CREATED
				reply.command.CreationTime = convert_to_ft(share.stat().st_ctime)
				reply.command.LastAccessTime = convert_to_ft(share.stat().st_atime)
				reply.command.LastWriteTime = convert_to_ft(share.stat().st_mtime)
				reply.command.ChangeTime = convert_to_ft(share.stat().st_mtime)
				reply.command.AllocationSize = 0
				reply.command.EndofFile = 0
				reply.command.FileAttributes = FileAttributes.FILE_ATTRIBUTE_DIRECTORY
				reply.command.FileId = 0
				reply.command.CreateContextsOffset = 0
				reply.command.CreateContextsLength = 0
			else:
				# this can be a file or a pipe or a printer etc.
				# we only handle files for now
				# first we need to translate the UNC path to a local path
				# this happens by getting the share name from the tree entry (via tree_id)
				if msg.header.TreeId not in self.__treeid_to_entry:
					raise Exception('Tree ID %s not found' % msg.header.TreeId)
				
				te = self.__treeid_to_entry[msg.header.TreeId]
				if te is None:
					raise Exception('Tree entry for Tree ID %s not found' % msg.header.TreeId)
				
				share = te.path

				file_name = command.Name
				local_path = share / Path(file_name).relative_to(share)
				if not local_path.exists():
					raise Exception('File %s does not exist' % local_path)
				if not local_path.is_file():
					raise Exception('File %s is not a file' % local_path)
				if local_path.is_file():
					file_id = 0
					handle = open(local_path, 'rb') #this must change based on the mode
					# store the handle in the file entry
					fe = FileEntry(path=local_path, handle=handle, file_id=file_id)
					te.file_entries[reply.command.FileId] = fe

				fstat = local_path.stat()
				reply = SMB2Message()
				reply.header = SMB2Header_SYNC()
				reply.header.Command = SMB2Command.CREATE
				reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
				reply.header.SessionId = self.SessionId
				reply.header.CreditCharge = 1
				reply.header.CreditReq = msg.header.CreditReq
				reply.header.Status = NTStatus.SUCCESS
				reply.command = CREATE_REPLY()
				reply.command.OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
				reply.command.Flags = CreateOptions.FILE_WRITE_THROUGH
				reply.command.CreateAction = CreateAction.FILE_CREATED
				reply.command.CreationTime = convert_to_ft(fstat.st_ctime)
				reply.command.LastAccessTime = convert_to_ft(fstat.st_atime)
				reply.command.LastWriteTime = convert_to_ft(fstat.st_mtime)
				reply.command.ChangeTime = convert_to_ft(fstat.st_mtime)
				reply.command.AllocationSize = fstat.st_size
				reply.command.EndofFile = fstat.st_size
				reply.command.FileAttributes = FileAttributes.FILE_ATTRIBUTE_NORMAL
				reply.command.FileId = fe.file_id
				reply.command.CreateContextsOffset = 0
				reply.command.CreateContextsLength = 0
			#await self.sendSMB(reply)
			await self.sendSMB2(msg, SMB2Command.CREATE, reply.command, NTStatus.SUCCESS)
		except Exception as e:
			traceback.print_exc()
	
	async def query_directory(self, msg:SMB2Message):
		try:
			command = typing.cast(QUERY_DIRECTORY_REQ, msg.command)
			# Validate tree and determine base path
			if msg.header.TreeId not in self.__treeid_to_entry:
				raise Exception('Tree ID %s not found' % msg.header.TreeId)
			te = self.__treeid_to_entry[msg.header.TreeId]
			share = te.path
			# FileId 0 means the directory opened by CREATE against the tree root/share
			# We support listing the root of the share for now
			base_path = share
			# Determine pattern
			pattern = command.FileName if command.FileName else '*'
			# Special-case: when client sends FileName of "\\" or "." in root, list all
			if pattern in ['\\\x00', '\\', '.', '.\x00']:
				pattern = '*'
			# Load or initialize enumeration state per TreeId
			if not hasattr(self, '_dir_enum_state'):
				self._dir_enum_state = {}
			state_key = (msg.header.TreeId, command.FileId)
			if QueryDirectoryFlag.SMB2_RESTART_SCANS in command.Flags or state_key not in self._dir_enum_state or QueryDirectoryFlag.SMB2_REOPEN in command.Flags:
				# Build fresh list according to pattern
				entries = []
				for child in base_path.iterdir():
					name = child.name
					try:
						from aiosmb.commons.utils.glob2re import glob2re
						import re
						if not re.match(glob2re(pattern), name):
							continue
					except Exception:
						if pattern not in ['*', None]:
							continue
					entries.append(name)
				self._dir_enum_state[state_key] = DirEnumState(entries=entries, index=0, pattern=pattern, info_class=command.FileInformationClass)
			state = self._dir_enum_state[state_key]
			# Build from current index forward until OutputBufferLength filled
			entries = []
			for name in state.entries[state.index:]:
				child = base_path / name
				st = child.stat()
				# Build directory info record based on requested class
				# NextEntryOffset filled later when concatenating
				creation_time = convert_to_ft(int(st.st_ctime))
				last_access_time = convert_to_ft(int(st.st_atime))
				last_write_time = convert_to_ft(int(st.st_mtime))
				change_time = convert_to_ft(int(st.st_mtime))
				allocation_size = 0 if child.is_dir() else st.st_size
				end_of_file = 0 if child.is_dir() else st.st_size
				attrs = FileAttributes.FILE_ATTRIBUTE_DIRECTORY if child.is_dir() else FileAttributes.FILE_ATTRIBUTE_NORMAL
				filename_bytes = name.encode('utf-16-le')
				fixed = b''
				fixed += (0).to_bytes(4, 'little', signed=False) # NextEntryOffset placeholder
				fixed += (0).to_bytes(4, 'little', signed=False) # FileIndex
				fixed += creation_time.to_bytes(8, 'little', signed=False)
				fixed += last_access_time.to_bytes(8, 'little', signed=False)
				fixed += last_write_time.to_bytes(8, 'little', signed=False)
				fixed += change_time.to_bytes(8, 'little', signed=False)
				fixed += end_of_file.to_bytes(8, 'little', signed=True)
				fixed += allocation_size.to_bytes(8, 'little', signed=True)
				fixed += attrs.value.to_bytes(4, 'little', signed=False)
				if command.FileInformationClass == FileInfoClass.FileFullDirectoryInformation:
					fixed += len(filename_bytes).to_bytes(4, 'little', signed=False)
					fixed += (0).to_bytes(4, 'little', signed=False) # EaSize
					entry = fixed + filename_bytes
				elif command.FileInformationClass == FileInfoClass.FileDirectoryInformation:
					# Same as Full but without EaSize
					fixed += len(filename_bytes).to_bytes(4, 'little', signed=False)
					entry = fixed + filename_bytes
				elif command.FileInformationClass == FileInfoClass.FileBothDirectoryInformation:
					# Full + ShortName fields
					fixed += len(filename_bytes).to_bytes(4, 'little', signed=False)
					fixed += (0).to_bytes(4, 'little', signed=False) # EaSize
					fixed += (0).to_bytes(1, 'little', signed=False) # ShortNameLength
					fixed += (0).to_bytes(1, 'little', signed=False) # Reserved
					fixed += b'\x00' * 24 # ShortName (12 WCHAR)
					fixed += (0).to_bytes(2, 'little', signed=False) # Reserved2
					entry = fixed + filename_bytes
				elif command.FileInformationClass == FileInfoClass.FileIdFullDirectoryInformation:
					# Add FileId (8 bytes) then FileNameLength and EaSize
					file_id = getattr(st, 'st_ino', 0)
					fixed += file_id.to_bytes(8, 'little', signed=False)
					fixed += len(filename_bytes).to_bytes(4, 'little', signed=False)
					fixed += (0).to_bytes(4, 'little', signed=False) # EaSize
					entry = fixed + filename_bytes
				elif command.FileInformationClass == FileInfoClass.FileIdBothDirectoryInformation:
					# Both + FileId
					fixed += len(filename_bytes).to_bytes(4, 'little', signed=False)
					fixed += (0).to_bytes(4, 'little', signed=False) # EaSize
					fixed += (0).to_bytes(1, 'little', signed=False) # ShortNameLength
					fixed += (0).to_bytes(1, 'little', signed=False) # Reserved
					fixed += b'\x00' * 24 # ShortName (12 WCHAR)
					fixed += (0).to_bytes(2, 'little', signed=False) # Reserved2
					file_id = getattr(st, 'st_ino', 0)
					fixed += file_id.to_bytes(8, 'little', signed=False)
					entry = fixed + filename_bytes
				else:
					# Unsupported info class, skip for now
					continue
				
				if len(entry) % 8 != 0:
					entry += b'\x00' * (8 - len(entry) % 8)
				entries.append(entry)

			# Concatenate entries with proper NextEntryOffset (8-byte aligned) and enforce OutputBufferLength
			max_len = command.OutputBufferLength if command.OutputBufferLength else 65535
			buffer = b''
			emitted = 0
			for i, entry in enumerate(entries):
				cur_len = len(entry)
				# compute 8-byte alignment padding for this entry when followed by another
				padded_len = (cur_len + 7) & ~7
				pad_len = padded_len - cur_len
				# determine buffer start position for this entry
				start_pos = len(buffer)
				# If this entry alone doesn't fit, stop
				if start_pos + cur_len > max_len:
					break
				# Decide if we can chain a next entry: we need room for this entry + its padding + at least the next entry header
				can_chain_next = False
				if i + 1 < len(entries):
					next_len = len(entries[i+1])
					if start_pos + cur_len + pad_len + next_len <= max_len:
						can_chain_next = True
				# Append current entry
				buffer += entry
				emitted += 1
				if can_chain_next:
					# write NextEntryOffset (padded length) and append padding
					buffer = bytearray(buffer)
					buffer[start_pos:start_pos+4] = padded_len.to_bytes(4, 'little', signed=False)
					buffer = bytes(buffer)
					if pad_len:
						buffer += b'\x00' * pad_len
				else:
					# last entry in this chunk: leave NextEntryOffset as 0 and do not pad
					pass
			# Advance enumeration index by number of emitted entries
			state.index += emitted

			reply = SMB2Message()
			reply.header = SMB2Header_SYNC()
			reply.header.Command = SMB2Command.QUERY_DIRECTORY
			reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
			reply.header.SessionId = self.SessionId
			reply.header.TreeId = msg.header.TreeId
			reply.header.CreditCharge = 1
			reply.header.CreditReq = msg.header.CreditReq if msg.header.CreditReq else 1
			
			# Check if we have no data to return (either no buffer or all entries consumed)
			if len(buffer) == 0 or (emitted == 0 and state.index >= len(state.entries)):
				# No entries matched, nothing fits, or enumeration is complete
				reply.header.Status = NTStatus.NO_MORE_FILES
				reply.command = ERROR_REPLY()
				await self.sendSMB2(msg, SMB2Command.QUERY_DIRECTORY, reply.command, NTStatus.NO_MORE_FILES)
			else:
				reply.header.Status = NTStatus.SUCCESS
				reply.command = QUERY_DIRECTORY_REPLY()
				reply.command.Data = buffer
				await self.sendSMB2(msg, SMB2Command.QUERY_DIRECTORY, reply.command, NTStatus.SUCCESS)
			#await self.sendSMB(reply)
			
		except Exception as e:
			traceback.print_exc()

	async def close(self, msg:SMB2Message):
		try:
			command = typing.cast(CLOSE_REQ, msg.command)
			reply = SMB2Message()
			reply.header = SMB2Header_SYNC()
			reply.header.Command = SMB2Command.CLOSE
			reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
			reply.header.SessionId = self.SessionId
			reply.header.TreeId = msg.header.TreeId
			reply.header.CreditCharge = 1
			reply.header.CreditReq = msg.header.CreditReq
			reply.header.Status = NTStatus.SUCCESS
			reply.command = CLOSE_REPLY()
			reply.command.Flags = CloseFlag.NONE
			reply.command.Reserved = 0
			# Try to find the file entry by TreeId and FileId
			fe = None
			if msg.header.TreeId in self.__treeid_to_entry:
				te = self.__treeid_to_entry[msg.header.TreeId]
				if command.FileId in te.file_entries:
					fe = te.file_entries.pop(command.FileId)
			if fe and fe.handle:
				try:
					fe.handle.close()
				except Exception:
					pass
			# Fill attributes if requested
			if CloseFlag.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB in command.Flags and fe is not None:
				st = fe.path.stat()
				reply.command.CreationTime = convert_to_ft(int(st.st_ctime))
				reply.command.LastAccessTime = convert_to_ft(int(st.st_atime))
				reply.command.LastWriteTime = convert_to_ft(int(st.st_mtime))
				reply.command.ChangeTime = convert_to_ft(int(st.st_mtime))
				reply.command.AllocationSize = 0 if fe.path.is_dir() else st.st_size
				reply.command.EndofFile = 0 if fe.path.is_dir() else st.st_size
				reply.command.FileAttributes = (FileAttributes.FILE_ATTRIBUTE_DIRECTORY if fe.path.is_dir() else FileAttributes.FILE_ATTRIBUTE_NORMAL).value
				reply.command.Flags = CloseFlag.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
			await self.sendSMB(reply)
		except Exception as e:
			traceback.print_exc()
	
	
	async def echo(self, msg:SMB2Message):
		try:
			command = typing.cast(ECHO_REQ, msg.command)
			reply = SMB2Message()
			reply.header = SMB2Header_SYNC()
			reply.header.Command = SMB2Command.ECHO
			reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
			reply.header.SessionId = self.SessionId
			reply.header.CreditCharge = msg.header.CreditCharge if msg.header.CreditCharge else 1
			reply.header.CreditReq = msg.header.CreditReq if msg.header.CreditReq else 1
			reply.header.Status = NTStatus.SUCCESS
			reply.command = ECHO_REPLY()
			await self.sendSMB(reply)
		except Exception as e:
			traceback.print_exc()
	
	async def sendSMB2(self, orgiginator:SMB2Message, command:SMB2Command, reply, status = NTStatus.SUCCESS):
		print(f"[DEBUG] sending SMB2 message with MessageId {orgiginator.header.MessageId}")
		replymsg = SMB2Message()
		replymsg.header = SMB2Header_SYNC()
		replymsg.header.MessageId = orgiginator.header.MessageId
		replymsg.header.Command = command
		replymsg.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
		replymsg.header.SessionId = self.SessionId
		# Fix: CreditCharge should match the request's CreditCharge (credits consumed)
		replymsg.header.CreditCharge = orgiginator.header.CreditCharge
		# Fix: CreditReq should be the credits we're granting back to the client
		replymsg.header.CreditReq = orgiginator.header.CreditReq if orgiginator.header.CreditReq else 1
		replymsg.header.Status = status
		replymsg.command = reply
		await self.sendSMB(replymsg)