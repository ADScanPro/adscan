import enum
import asyncio
import datetime
import traceback
import typing

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


class SMBConnectionStatus(enum.Enum):
	NEGOTIATING = 'NEGOTIATING'
	SESSIONSETUP = 'SESSIONSETUP'
	RUNNING = 'RUNNING'
	CLOSED = 'CLOSED'
	

class SMBRelayServerConnection:
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
		self.ServerCapabilities = NegotiateCapabilities.DFS | NegotiateCapabilities.LARGE_MTU
		self.ClientSecurityMode = 0
		self.ServerSecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
		if self.signing_required is True:
			self.ServerSecurityMode |= NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
		
		self.SessionId = 0
		self.SessionKey = None

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
			# Surface the REAL error: an exception with an empty __str__ (e.g.
			# asyncio.TimeoutError) used to log a blank "[ERR] " line, masking the
			# real connection-teardown/relay failure. Fall back to repr/type.
			_exc_detail = str(e) or repr(e) or type(e).__name__
			await self.print('[ERR] %s' % _exc_detail)

	async def print(self, msg):
		if self.settings.log_callback is not None:
			await self.settings.log_callback(f'[SMBSERVERCONN][{self.connection_id}] {msg}')

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
						#res, err = await self.session_setup(msg)
						#if res is False:
						#	# this means we can drop the connection
						#	return
					
					elif self.status == SMBConnectionStatus.RUNNING:
						if msg.header.Command == SMB2Command.TREE_CONNECT:
							await self.tree_connect(msg)
						elif msg.header.Command == SMB2Command.CREATE:
							await self.create(msg)
						elif msg.header.Command == SMB2Command.IOCTL:
							return
							await self.ioctl(msg)
				
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
		except Exception:
			pass
		finally:
			await self.stop()
		
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
		except Exception:
			pass

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
					await self.print('[INF] Calling authenticate_relay_server')
					#reply.command.Buffer, to_continue, err  = await self.gssapi.authenticate(msg.command.Buffer)
					reply.command.Buffer, to_continue, err  = await self.gssapi.authenticate_relay_server(msg.command.Buffer)
					await self.print('[INF] Authenticate results: %s, %s, %s' % (reply.command.Buffer, to_continue, err))
					
					if err is not None:
						raise err
					
					if to_continue is False and reply.command.Buffer is None:
						reply = SMB2Message()
						reply.command = SESSION_SETUP_REPLY()
						reply.command.SessionFlags = 0

						reply.command.Buffer, err  = await self.gssapi.authenticate_relay_server_finished()

						if err is not None:
							raise err

						reply.header = SMB2Header_SYNC()
						reply.header.Command  = SMB2Command.SESSION_SETUP
						reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
						reply.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SIGNED
						reply.header.SessionId = self.SessionId
						
						reply.header.CreditCharge = 1
						reply.header.CreditReq = 1
						reply.header.Status = NTStatus.SUCCESS
						reply.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SIGNED
						
						await self.sendSMB(reply)
						self.SessionKey = self.gssapi.get_session_key()[:16]
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


					


					self.SessionKey = self.gssapi.get_session_key()[:16]
					self.status = SMBConnectionStatus.RUNNING

				return True, None
		except Exception as e:
			# Surface the REAL error: exceptions with an empty __str__ (e.g.
			# asyncio.TimeoutError) used to log a blank "[ERR] " line, masking
			# the actual session-setup/relay failure. Fall back to repr/type.
			_exc_detail = str(e) or repr(e) or type(e).__name__
			await self.print('[ERR] %s' % _exc_detail)

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
		command = typing.cast(TREE_CONNECT_REQ, msg.command)

		reply = SMB2Message()
		reply.header = SMB2Header_SYNC()
		reply.header.Command = SMB2Command.TREE_CONNECT
		reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
		reply.header.SessionId = self.SessionId
		reply.header.CreditCharge = 0
		reply.header.CreditReq = 1
		reply.header.Status = NTStatus.SUCCESS
		reply.command = TREE_CONNECT_REPLY()

		if command.Path.endswith('IPC$'):
			reply.command.ShareType = ShareType.PIPE
		else:
			reply.command.ShareType = ShareType.DISK

		reply.command.ShareFlags = ShareFlags.SMB2_SHAREFLAG_MANUAL_CACHING
		reply.command.Capabilities = TreeCapabilities.SMB2_SHARE_CAP_NONE
		reply.command.MaximalAccess = FileAccessMask.GENERIC_ALL

		await self.sendSMB(reply)
	
		
	async def sendSMB(self, msg, ret_message = False, compression_cb = None):
		"""
		Sends an SMB message to teh remote endpoint.
		msg: SMB2Message or SMBMessage
		Returns: MessageId integer
		"""
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
			if ret_message is True:
				return message_id, msg
			return message_id
				
		if msg.header.Command is not SMB2Command.CANCEL:
			msg.header.MessageId = self.SequenceWindow
			self.SequenceWindow += 1
		
		msg.header.SessionId = self.SessionId
		
		if not msg.header.CreditCharge:
			msg.header.CreditCharge = 0

		
		
		if self.status != SMBConnectionStatus.SESSIONSETUP:
			msg.header.CreditReq = 127
		
		message_id = msg.header.MessageId
		#print(msg)

		#creating an event for outstanding response
		self.OutstandingResponsesEvent[message_id] = asyncio.Event()
		await self.connection.write(msg.to_bytes())
		
		if ret_message is True:
				return message_id, msg
		return message_id

	