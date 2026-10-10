
import enum
import ntpath
import asyncio
import copy

from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5 import rrp
from aiosmb import logger
from aiosmb.dcerpc.v5 import system_errors
from aiosmb.wintypes.dtyp.structures.filetime import FILETIME
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.ace import ACCESS_ALLOWED_ACE, AceFlags
from winacl.dtyp.sid import SID
from aiosmb.commons.exceptions import SMBException
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.wintypes.dtyp.constrcuted_security.security_information import SECURITY_INFORMATION
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE

from contextlib import asynccontextmanager

@asynccontextmanager
async def rrprpc_from_smb(connection, auth_level=None, open=True, perform_dummy=False):
    instance, err = await RRPRPC.from_smbconnection(connection, auth_level=auth_level, open=open, perform_dummy=perform_dummy)
    if err:
        # Handle or raise the error as appropriate
        raise err
    try:
        yield instance
    finally:
        await instance.close()

class HKEY(enum.Enum):
	CLASSES_ROOT = 0 #Registry entries subordinate to this key define types (or classes) of documents and the properties associated with those types. Shell and COM applications use the information stored under this key.
	CURRENT_USER = 1 #Registry entries subordinate to this key define the preferences of the current user. These preferences include the settings of environment variables, data about program groups, colors, printers, network connections, and application preferences.
	LOCAL_MACHINE = 2 #Registry entries subordinate to this key define the physical state of the computer, including data about the bus type, system memory, and installed hardware and software.
	USERS = 3 #Registry entries subordinate to this key define the default user configuration for new users on the local computer and the user configuration for the current user.
	PERFORMANCE_DATA = 4 #Registry entries subordinate to this key allow you to access performance data. The data is not actually stored in the registry; the registry functions cause the system to collect the data from its source.
	CURRENT_CONFIG = 5 #Contains information about the current hardware profile of the local computer system.
	DYN_DATA = 6 #This key is not used in versions of Windows after 98.

hkey_abbrev = {
	'HKEY_LOCAL_MACHINE' : HKEY.LOCAL_MACHINE,
	'HKLM' : HKEY.LOCAL_MACHINE,
	'HKEY_CURRENT_USER' : HKEY.CURRENT_USER,
	'HKCU' : HKEY.CURRENT_USER,
	'HKEY_CLASSES_ROOT' : HKEY.CLASSES_ROOT,
	'HKCR' : HKEY.CLASSES_ROOT,
	'HKEY_USERS' : HKEY.USERS,
	'HKU' : HKEY.USERS,
	'HKEY_PERFORMANCE_DATA' : HKEY.PERFORMANCE_DATA,
	'HKPD' : HKEY.PERFORMANCE_DATA,
	'HKEY_CURRENT_CONFIG' : HKEY.CURRENT_CONFIG,
	'HKCC' : HKEY.PERFORMANCE_DATA,
}

class REG_ACCESS_MASK(enum.IntFlag):
	GENERIC_READ            = 0x80000000
	GENERIC_WRITE           = 0x4000000
	GENERIC_EXECUTE         = 0x20000000
	GENERIC_ALL             = 0x10000000
	MAXIMUM_ALLOWED         = 0x02000000
	ACCESS_SYSTEM_SECURITY  = 0x01000000
	SYNCHRONIZE             = 0x00100000
	WRITE_OWNER             = 0x00080000
	WRITE_DACL              = 0x00040000
	READ_CONTROL            = 0x00020000
	DELETE                  = 0x00010000

class REG_VAL_TYPE(enum.Enum):
	BINARY              = 3
	DWORD               = 4
	DWORD_LITTLE_ENDIAN = 4
	DWORD_BIG_ENDIAN    = 5
	EXPAND_SZ           = 2
	LINK                = 6
	MULTI_SZ            = 7
	NONE                = 0
	QWORD               = 11
	QWORD_LITTLE_ENDIAN = 11
	SZ                  = 1 

def reg_decode_value(value_type, value_data):
	if value_type == REG_VAL_TYPE.SZ:
		return value_data.decode('utf-16-le')
	elif value_type in [REG_VAL_TYPE.DWORD, REG_VAL_TYPE.DWORD_LITTLE_ENDIAN]:
		return int.from_bytes(value_data, byteorder='little', signed = False)
	elif value_type == REG_VAL_TYPE.DWORD_BIG_ENDIAN:
		return int.from_bytes(value_data, byteorder='big', signed = False)
	elif value_type in [REG_VAL_TYPE.QWORD, REG_VAL_TYPE.QWORD_LITTLE_ENDIAN]:
		return int.from_bytes(value_data, byteorder='little', signed = False)
	
	return value_data

class RRPRPC:
	def __init__(self):
		self.service_pipename = r'\winreg'
		self.service_uuid = rrp.MSRPC_UUID_RRP
		self.dce = None
		self.handles = {}
		self.__current_handle_id = 0
	
	def __get_handle(self, hkey):
		hid = self.__current_handle_id
		self.__current_handle_id += 1
		self.handles[hid] = hkey
		return hid

	async def __get_rawhandle(self, key):
		if isinstance(key, HKEY):
			key, err = await self.ConnectRegistry(key)
			if err is not None:
				raise err
		
		return self.handles[key]

	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True, None

	async def close(self):
		try:
			for hkey in self.handles:
				await self.CloseKey(hkey)

			await self.dce.disconnect()
		except Exception as e:
			return False, e

	@staticmethod
	async def from_rpcconnection(connection:DCERPC5Connection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		try:
			service = RRPRPC()
			service.dce = connection
			
			service.dce.set_auth_level(auth_level)
			if auth_level is None:
				service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P 
			
			_, err = await service.dce.connect()
			if err is not None:
				if isinstance(err, SMBException):
					if err.ntstatus == NTStatus.PIPE_NOT_AVAILABLE:
						# this is a common problem for this specific pipe only.
						# usually this pipe is not aviailable on the first try, but after a few seconds windows automatically creates it after someone tries to connect to it.
						# so we will wait for a few seconds and try again.
						await asyncio.sleep(2)
						_, err = await service.dce.connect()
						if err is not None:
							raise err
					else:
						raise err
				else:
					raise err
			
			_, err = await service.dce.bind(service.service_uuid)
			if err is not None:
				raise err
			
			return service, None
		except Exception as e:
			return False, e
	
	@staticmethod
	async def from_smbconnection(connection:SMBConnection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		"""
		Creates the connection to the service using an established SMBConnection.
		This connection will use the given SMBConnection as transport layer.
		"""
		try:
			if auth_level is None:
				#for SMB connection no extra auth needed
				auth_level = RPC_C_AUTHN_LEVEL_NONE
			rpctransport = SMBDCEFactory(connection, filename=RRPRPC().service_pipename)		
			service, err = await RRPRPC.from_rpcconnection(rpctransport.get_dce_rpc(), auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e


	async def CloseKey(self, key):
		try:
			key = await self.__get_rawhandle(key)
			_, err = await rrp.hBaseRegCloseKey(self.dce, key)
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def ConnectRegistry(self, key, access = REG_ACCESS_MASK.MAXIMUM_ALLOWED):
		try:
			
			res = None
			err = None
			if key == HKEY.CLASSES_ROOT:
				res, err = await rrp.hOpenClassesRoot(self.dce, samDesired = access.value)

			elif key == HKEY.CURRENT_USER:
				res, err = await rrp.hOpenCurrentUser(self.dce, samDesired = access.value)
			
			elif key == HKEY.LOCAL_MACHINE:
				res, err = await rrp.hOpenLocalMachine(self.dce, samDesired = access.value)
			
			elif key == HKEY.USERS:
				res, err = await rrp.hOpenUsers(self.dce, samDesired = access.value)
			
			elif key == HKEY.PERFORMANCE_DATA:
				res, err = await rrp.hOpenPerformanceData(self.dce, samDesired = access.value)

			elif key == HKEY.CURRENT_CONFIG:
				res, err = await rrp.hOpenCurrentConfig(self.dce, samDesired = access.value)
			
			else:
				raise Exception('Not supported registry hive to open: %s' % key.name)
			
			if err is not None:
				return None, err

			return self.__get_handle(res['phKey']), None
		
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def CreateKey(self, key, sub_key, access=REG_ACCESS_MASK.MAXIMUM_ALLOWED):
		try:
			key = await self.__get_rawhandle(key)
			res, err = await rrp.hBaseRegCreateKey(self.dce, key, sub_key, samDesired = access.value)
			if err is not None:
				raise err

			return self.__get_handle(res['phkResult']), None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def DeleteKey(self, key, sub_key):
		try:
			key = await self.__get_rawhandle(key)
			
			res, err = await rrp.hBaseRegDeleteKey(self.dce, key, sub_key)
			if err is not None:
				raise err	
			return True, None

		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def DeleteValue(self, key, value):
		try:
			key = await self.__get_rawhandle(key)
			
			_, err = await rrp.hBaseRegDeleteValue(self.dce, key, value)
			if err is not None:
				raise err
			
			return True, None
		
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def EnumKey(self, key, index):
		try:
			key = await self.__get_rawhandle(key)
			res, err = await rrp.hBaseRegEnumKey(self.dce, key, index)
			if err is not None:
				raise err
			return res['lpNameOut'], None
		
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def EnumValue(self, key, index):
		try:
			key = await self.__get_rawhandle(key)
			res, err = await rrp.hBaseRegEnumValue(self.dce, key, index)
			if err is not None:
				raise err
			
			value_name = res['lpValueNameOut']
			value_type = REG_VAL_TYPE(res['lpType'])
			value_data = reg_decode_value(value_type ,b''.join(res['lpData']))
			return value_name, value_type, value_data, None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, None, None, e

	async def FlushKey(self, key):
		try:
			key = await self.__get_rawhandle(key)
			_, err = await rrp.hBaseRegFlushKey(self.dce, key)
			return True, err
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def LoadKey(self, key, sub_key, file_name):
		try:
			key = await self.__get_rawhandle(key)
			_, err = await rrp.hBaseRegLoadKey(self.dce, key, sub_key, file_name)
			if err is not None:
				raise err

			return True, None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def OpenKey(self, key, sub_key, reserved=0, access=REG_ACCESS_MASK.MAXIMUM_ALLOWED):
		try:
			key = await self.__get_rawhandle(key)
			res , err = await rrp.hBaseRegOpenKey(self.dce, key, sub_key, access.value)
			if err is not None:
				raise err
			return self.__get_handle(res['phkResult']), None
		
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def OpenKeyBackup(self, key, sub_key):
		# Open a key with dwOptions = REG_OPTION_BACKUP_RESTORE (0x4) |
		# REG_OPTION_OPEN_LINK (0x8) and samDesired = 0. The backup-restore
		# flag makes the server honour SeBackupPrivilege, which a local admin
		# AND a Backup Operator both hold, so the read bypasses the key ACL
		# WITHOUT modifying the DACL. samDesired=0 (not a KEY_READ bitmask)
		# mirrors impacket's own protected-data opens byte-for-byte
		# (examples/regsecrets.py retrieveSubKey/enumSubKey/enumValues all
		# pass samDesired=None, which serializes to 0) -- live-confirmed
		# 2026-10-07 against a CrowdStrike-protected host: that exact
		# dwOptions/samDesired pair round-trips the full SAM+LSA+DCC2+DPAPI
		# read cleanly there. BACKUP_RESTORE's privilege-based bypass is what
		# actually grants the effective access; the requested samDesired bits
		# are close to advisory under it, and requesting a NARROWER mask than
		# strictly necessary is the lower-footprint, closer-to-impacket choice.
		# Distinct from OpenKey() on purpose: OpenKey() currently passes the
		# access mask into the dwOptions slot (a latent bug tracked in
		# BACKLOG), and it is used by ~8 other consumers, so this low-footprint
		# path is a separate method rather than a change to the shared one.
		try:
			key = await self.__get_rawhandle(key)
			res, err = await rrp.hBaseRegOpenKey(self.dce, key, sub_key, 0x0000000C, 0x00000000)
			if err is not None:
				raise err
			return self.__get_handle(res['phkResult']), None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def OpenKeyPlain(self, key, sub_key):
		# A BARE hBaseRegOpenKey with NO dwOptions/samDesired override (vendor
		# defaults: dwOptions=0x00000001, samDesired=MAXIMUM_ALLOWED) -- i.e.
		# NOT a backup-privileged open. Mirrors impacket's own
		# examples/regsecrets.py getBootKey() EXACTLY, which never requests
		# backup semantics for the SYSTEM\CurrentControlSet\Control\Lsa\* class
		# reads the bootkey is derived from: an admin's (or Backup Operator's)
		# normal DACL grant already covers that key, unlike the actual
		# protected SAM/SECURITY secret data OpenKeyBackup serves.
		#
		# Why this exists, concretely (live finding 2026-10-07): a
		# CrowdStrike-protected host let impacket's plain bootkey open through
		# untouched while our OpenKeyBackup-for-every-open pattern broke the
		# \pipe\winreg pipe on that EXACT SAME semantic read. Requesting
		# elevated backup-restore semantics for data that doesn't need them is
		# an unusual, flaggable request pattern a real attacker's tooling
		# (impacket) deliberately avoids -- and ADscan must match the
		# lowest-footprint method a real attacker would use (CLAUDE.md §
		# OPSEC), not request more privilege than the read actually needs.
		try:
			key = await self.__get_rawhandle(key)
			res, err = await rrp.hBaseRegOpenKey(self.dce, key, sub_key)
			if err is not None:
				raise err
			return self.__get_handle(res['phkResult']), None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def QueryInfoKey(self, key):
		try:
			key = await self.__get_rawhandle(key)
			res , err = await rrp.hBaseRegQueryInfoKey(self.dce, key)
			if err is not None:
				raise err
			
			subkey_cnt = res['lpcSubKeys']
			values_cnt = res['lpcValues']
			lastwrite_time = FILETIME.from_dict(res['lpftLastWriteTime']).datetime
			
			return subkey_cnt, values_cnt, lastwrite_time, None

		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, None, None, e
	
	async def QueryInfoKeySpecial(self, key):
		# yes, it's special
		try:
			key = await self.__get_rawhandle(key)
			res , err = await rrp.hBaseRegQueryInfoKey(self.dce, key)
			if err is not None:
				raise err
			
			return res, None

		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e
		
		

	async def GetKeySecurity(self, key, securityInformation = SECURITY_INFORMATION.OWNER):
		try:
			key = await self.__get_rawhandle(key)
			res , err = await rrp.hBaseRegGetKeySecurity(self.dce, key, securityInformation = securityInformation)
			if err is not None:
				raise err
			return SECURITY_DESCRIPTOR.from_bytes(res), None
		
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e
	
	async def SetKeySecurity(self, key, security_descriptor, securityInformation = SECURITY_INFORMATION.OWNER):
		try:
			key = await self.__get_rawhandle(key)
			_, err = await rrp.hBaseRegSetKeySecurity(self.dce, key, security_descriptor.to_bytes(), securityInformation = securityInformation)
			if err is not None:
				raise err
			return True, None
		
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def QueryValue(self, key, value_name, unpack_vals = True):
		try:
			key = await self.__get_rawhandle(key)
			val_type, value , err = await rrp.hBaseRegQueryValue(self.dce, key, value_name, unpack_vals=unpack_vals)
			if err is not None:
				raise err
			return val_type, value, err
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, None, e

	async def SaveKey(self, key, file_name):
		try:
			key = await self.__get_rawhandle(key)
			res , err = await rrp.hBaseRegSaveKey(self.dce, key, file_name)
			if err is not None:
				raise err

			return res, None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def SetValue(self, key, sub_key, val_type, val_data):
		
		#the packing is done in the original layer, not sure if everything works but it seems so
		try:
			key = await self.__get_rawhandle(key)
			res, err =  await rrp.hBaseRegSetValue(self.dce, key, sub_key, val_type.value, val_data)
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, None, e

	async def OpenPerformanceText(self):
		try:
			res , err = await rrp.hOpenPerformanceText(self.dce)
			if err is not None:
				raise err
			return res['phKey'], None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, None, e

	async def OpenPerformanceNlsText(self):
		try:
			res , err = await rrp.hOpenPerformanceNlsText(self.dce)
			if err is not None:
				raise err
			return res['phKey'], None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, None, e

	async def OpenRegPath(self, fullpath, access = REG_ACCESS_MASK.MAXIMUM_ALLOWED):
		try:
			reg_root, key_path = fullpath.split('\\',1)
			root_key = hkey_abbrev[reg_root]

			key, err = await self.ConnectRegistry(root_key, access = access)
			if err is not None:
				return None, err
			return await self.OpenKey(key, key_path, access = access)
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def OpenRegPathBackup(self, fullpath):
		# OpenRegPath variant whose leaf subkey is opened via OpenKeyBackup
		# (SeBackupPrivilege, no DACL change). The root HKEY handle does not take
		# the backup flag; only the subkey open needs it.
		try:
			reg_root, key_path = fullpath.split('\\', 1)
			root_key = hkey_abbrev[reg_root]
			key, err = await self.ConnectRegistry(root_key, access=REG_ACCESS_MASK.MAXIMUM_ALLOWED)
			if err is not None:
				return None, err
			return await self.OpenKeyBackup(key, key_path)
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	######### custom methods

	async def ListUsers(self, users_handle = None):
		try:
			if users_handle is None:
				users_handle, err = await self.ConnectRegistry(HKEY.USERS)
				if err is not None:
					raise err
			
			users = []
			for i in range(255):
				res, err = await self.EnumKey(users_handle, i)
				if err is not None:
					if err.errno == 259: #no more data is available
						break
					raise err
				if res.startswith('S-1-5-') is True:
					users.append(res[:-1])
			return users, None
		except Exception as e:
			return None, e

	async def get_system_drive_letter(self):
		try:
			regpath = r'HKEY_LOCAL_MACHINE\SYSTEM\Setup'
			key_handle, err = await self.OpenRegPath(regpath, access = REG_ACCESS_MASK.GENERIC_READ)
			if err is not None:
				return None, err
			if key_handle is None:
				return None, OSError(err.errno, system_errors.ERROR_MESSAGES[err.errno][1])
			
			value_name = 'SystemDrive'
			val_type, val_data, err = await self.QueryValue(key_handle, value_name, unpack_vals=True)
			if err is not None:
				winpath, err = await self.get_windows_directory_path()
				if err is not None:
					return None, err
				return winpath[0], None
			return val_data.replace('\x00', ''), None
		except Exception as e:
			return None, e
	
	async def get_system_drive_path(self):
		try:
			drive_letter, err = await self.get_system_drive_letter()
			if err is not None:
				return None, err
			return f'{drive_letter}:\\', None
		except Exception as e:
			return None, e
	
	async def get_user_home_directory_base_path(self):
		try:
			regpath = f'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList'
			key_handle, err = await self.OpenRegPath(regpath, access = REG_ACCESS_MASK.GENERIC_READ)
			if err is not None:
				raise err
			
			value_name = 'ProfilesDirectory'
			val_type, val_data, err = await self.QueryValue(key_handle, value_name, unpack_vals=True)
			if err is not None:
				raise err
			basepath = val_data.replace('\x00', '')
			if basepath.find('%SystemDrive%') != -1:
				drive_letter, err = await self.get_system_drive_letter()
				if err is not None:
					return None, err
				basepath = basepath.replace('%SystemDrive%', '%s:' % drive_letter)
			return basepath, None
		except Exception as e:
			return None, e

	async def get_ntds_file_path(self):
		try:
			# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
			regpath = r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
			key_handle, err = await self.OpenRegPath(regpath, access = REG_ACCESS_MASK.GENERIC_READ)
			if err is not None:
				return None, err
			value_name = 'DSA Database file'
			val_type, val_data, err = await self.QueryValue(key_handle, value_name, unpack_vals=True)
			if err is not None:
				raise err
			return val_data.replace('\x00', ''), None
		except Exception as e:
			return None, e
	
	async def get_windows_directory_path(self):
		try:
			regpath = r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
			key_handle, err = await self.OpenRegPath(regpath, access = REG_ACCESS_MASK.GENERIC_READ)
			if err is not None:
				return None, err
			
			value_name = 'SystemRoot'
			val_type, val_data, err = await self.QueryValue(key_handle, value_name, unpack_vals=True)
			if err is not None:
				raise err
			return val_data.replace('\x00', ''), None

		except Exception as e:
			return None, e

def _rrp_err_is_access_denied(err) -> bool:
	"""Whether an OpenKey failure is an authorization denial.

	``OpenKeyPlain`` returns an ``OSError`` carrying the DCE/RPC code for a
	session error and the raw exception otherwise, so both shapes have to be
	recognised to decide whether the privilege bypass is worth one retry.
	"""
	for attr in ('errno', 'error_code', 'errorCode'):
		code = getattr(err, attr, None)
		if isinstance(code, int) and code == 5:
			return True
	text = str(err).lower()
	return 'access_denied' in text or 'access denied' in text


class SMBWinRegHive:
	"""
	Async version of the hive parser
	"""
	def __init__(self, rrprpc:RRPRPC, hive_path:str, target_sid:str = 'S-1-5-32-544', cache_enabled = True, print_cb = None, backup_mode = False, plain_mode = False):
		# target_sid assumes that the user is a member of the Administrators group.
		# backup_mode: open EVERY key in this hive via SeBackupPrivilege
		# (REG_OPTION_BACKUP_RESTORE) and skip the SetKeySecurity DACL dance —
		# no disk, no DACL change, works for a Backup Operator. Needed for a
		# hive whose protected secret data (SAM's F/V values, SECURITY's
		# Policy\Secrets\*/Cache) is denied to EVERY principal including a
		# Domain Admin without the privilege bypass — confirmed live
		# 2026-10-07 against a real DA account on a GOAD DC: QueryValue/
		# EnumKey/EnumValue on those keys return ERROR_ACCESS_DENIED even
		# though the plain OpenKey that produced the handle succeeded, so
		# there is no admin-vs-Backup-Operator distinction for THIS hive —
		# everyone needs the bypass.
		#
		# plain_mode: open every key via a genuinely PLAIN, non-privileged
		# OpenKeyPlain -- no backup flag, no DACL change, no fallback. For
		# a hive whose DACL is permissive enough that any admin/Backup-
		# Operator read already works unprivileged (SYSTEM's bootkey-class
		# reads were already proven plain-readable; this extends that to the
		# rest of the SYSTEM hive). Mutually exclusive with backup_mode;
		# plain_mode wins if both are set.
		self.backup_mode = backup_mode
		self.plain_mode = plain_mode
		self.print_cb = print_cb
		self.rrprpc = rrprpc
		self.hive_path = hive_path
		self.hive_handle = None
		self.target_sid = target_sid
		self.cache_enabled = cache_enabled

		self.original_sd = None
		self.__original_sd = {}
		self.__key_lookup = {}

		# caching values for performance, this will mess up if the registry is changed during the session
		self.__names_lookup = {}
		self.__classes_lookup = {}
		self.__values_lookup = {}
		self.__values_lookup_2 = {}
		
	async def close(self):
		for key in self.__original_sd:
			try:			
				_, err = await self.rrprpc.SetKeySecurity(key, self.__original_sd[key], securityInformation=SECURITY_INFORMATION.DACL)
				if err is not None:
					raise err
				#print('Restored security descriptor for %s' % key)
			except Exception as e:
				if self.print_cb is not None:
					self.print_cb('[!] Failed to restore security descriptor for %s Reason %s' % (key, e))
				continue

		for key in self.__key_lookup:
			await self.rrprpc.CloseKey(key)
		
		return
	
	
	async def add_access(self, key_handle):
		original_key_sd = await self.get_sd(key_handle)		
		secdata = copy.deepcopy(original_key_sd)
		ace = ACCESS_ALLOWED_ACE() # BUILTIN\Administrators get generic read
		ace.Sid = SID.from_string(self.target_sid)
		ace.Mask = 0x80000000 | 0x00000008 | 0x00000001
		ace.AceFlags = AceFlags.CONTAINER_INHERIT_ACE
		secdata.Dacl.aces.append(ace)
			
		_, err = await self.rrprpc.SetKeySecurity(key_handle, secdata, securityInformation=SECURITY_INFORMATION.DACL)
		if err is not None:
			raise err
		
		return original_key_sd

	async def setup(self):
		if self.plain_mode:
			self.hive_handle, err = await self.rrprpc.OpenRegPath(self.hive_path, access = REG_ACCESS_MASK.GENERIC_READ)
		elif self.backup_mode:
			self.hive_handle, err = await self.rrprpc.OpenRegPathBackup(self.hive_path)
		else:
			self.hive_handle, err = await self.rrprpc.OpenRegPath(self.hive_path, access = REG_ACCESS_MASK.GENERIC_READ)
		if err is not None:
			raise err
	
	async def find_subkey(self, parent, key_name):
		raise NotImplementedError()
		return None	
		
	async def find_key(self, key_path, throw = True):
		"""Find and return a key by its full path"""

		if key_path in self.__key_lookup:
			return self.__key_lookup[key_path]
		
		keynames = key_path.split('\\')

		# Plain mode: open the FULL relative path in ONE OpenKeyPlain call --
		# MS-RRP's BaseRegOpenKey accepts a backslash-delimited multi-component
		# lpSubKey, so there is no need to walk the path component-by-component
		# with a separate RPC open per segment. impacket's own regsecrets.py
		# does exactly this (one hBaseRegOpenKey for the whole path), and the
		# per-component walk was pure extra winreg-pipe traffic: it re-opened
		# every shared prefix (Policy, Secrets, ...) once per leaf, since only
		# the full path is memoized, not the intermediate handles. Collapsing
		# to a single open cuts the RRP operation count on the pipe by ~2-4x
		# for the LSA read (65 opens -> ~18 measured live 2026-10-07), matching
		# impacket's much lower winreg footprint -- the lower-footprint method
		# a real attacker's tooling uses (CLAUDE.md § OPSEC). No backup flag,
		# no DACL change, no fallback (see __init__'s plain_mode docstring).
		if self.plain_mode:
			key_handle, err = await self.rrprpc.OpenKeyPlain(self.hive_handle, key_path)
			if err is not None:
				raise err
			self.__key_lookup[key_path] = key_handle
			return key_handle

		# Backup mode: open the FULL relative path in ONE OpenKeyBackup call
		# via SeBackupPrivilege, skipping the SetKeySecurity DACL dance -- same
		# single-open rationale as plain_mode above (impacket opens
		# r'SECURITY\Policy\PolEKList' etc. in one backup-flagged call), and it
		# works for a Backup Operator (who cannot WriteDACL).
		if self.backup_mode:
			key_handle, err = await self.rrprpc.OpenKeyBackup(self.hive_handle, key_path)
			if err is not None:
				raise err
			self.__key_lookup[key_path] = key_handle
			return key_handle

		# opening the key first time
		key_handle = self.hive_handle
		for keyname in keynames:
			key_handle, err = await self.rrprpc.OpenKey(key_handle, keyname, access=REG_ACCESS_MASK.GENERIC_READ)
			if err is not None:
				raise err

		#adding access to the key
		original_sd = await self.add_access(key_handle)
		
		#closing the key to reopen it with the new access
		_, err = await self.rrprpc.CloseKey(key_handle)

		key_handle = self.hive_handle
		for keyname in keynames:
			key_handle, err = await self.rrprpc.OpenKey(key_handle, keyname, access=REG_ACCESS_MASK.GENERIC_READ)
			if err is not None:
				raise err

		# adding the key to the lookup table
		self.__key_lookup[key_path] = key_handle
		self.__original_sd[key_handle] = original_sd
		return key_handle
		
	async def enum_key(self, key_path, throw = True):
		"""Return a list of subkey names"""
		
		if key_path in self.__names_lookup:
			return self.__names_lookup[key_path]
			
		key_handle = await self.find_key(key_path, throw)
		if key_handle is None:
			return None
		
		names = {}
		for i in range(255):
			res, err = await self.rrprpc.EnumKey(key_handle, i)
			if err is not None:
				if err.errno == 259: #no more data is available
					break
				if throw is True:
					raise err
				return []
			names[res.replace('\x00', '')] = None
		
		if self.cache_enabled is True:
			self.__names_lookup[key_path] = list(names.keys())
		
		return list(names.keys())
		
		
	async def list_values(self, key):
		"""Return a list of value names"""
		if key in self.__values_lookup_2:
			return self.__values_lookup_2[key]
		
		values = []
		for i in range(255):
			value_name, value_type, value_data, err = await self.rrprpc.EnumValue(key, i)
			if err is not None:
				if isinstance(err, OSError) and err.errno == 259:
					break
				if isinstance(err, DCERPCException) and err.error_code == 259:
					break
				raise err
			values.append(value_name.replace('\x00', '').encode())
		
		if self.cache_enabled is True:
			self.__values_lookup_2[key] = values

		return values
	
		
	async def get_value(self, value_path, throw = True, key = None):
		"""Return a value by its full path"""

		if value_path in self.__values_lookup:
			return self.__values_lookup[value_path]
			
		keynames = value_path.split('\\')
		value_name = keynames[-1]
		if value_name == 'default':
			value_name = ''
			key_path = '\\'.join(keynames[:-1])
		else:
			key_path = '\\'.join(keynames[:-1])

		key_handle = await self.find_key(key_path, throw)
		
		val_type, val_data, err = await self.rrprpc.QueryValue(key_handle, value_name, unpack_vals=True)
		if err is not None:
			if throw is True:
				raise err
			return None, None, err

		if self.cache_enabled is True:
			self.__values_lookup[value_path] = (val_type, val_data, None)

		return val_type, val_data, None
		
	async def get_class(self, key_path, throw = True):
		"""Return the class value of a key.

		ALWAYS a plain open, never the backup-privileged route (regardless of
		self.backup_mode) -- this never routes through find_key(). Mirrors
		impacket's getBootKey() exactly: the only caller of get_class() is
		pypykatz's bootkey derivation (SYSTEM\\CurrentControlSet\\Control\\
		Lsa\\{JD,Skew1,GBG,Data}), and that read needs no elevated backup
		semantics -- a normal admin/Backup-Operator DACL grant already covers
		it. Requesting BACKUP_RESTORE there anyway was found live (2026-10-07,
		against a CrowdStrike-protected host) to break the \\pipe\\winreg pipe
		on exactly this call, while impacket's plain-open equivalent for the
		SAME semantic read sails through untouched. See OpenKeyPlain's
		docstring for the full rationale.
		"""
		if key_path in self.__classes_lookup:
			return self.__classes_lookup[key_path]

		# Open the FULL relative path in ONE OpenKeyPlain call (BaseRegOpenKey
		# takes a backslash-delimited multi-component lpSubKey) rather than one
		# RPC open per path segment -- same single-open, lower-winreg-footprint
		# rationale as find_key() above, and exactly how impacket's getBootKey()
		# opens SYSTEM\CurrentControlSet\Control\Lsa\<key> (one call each).
		key_handle, err = await self.rrprpc.OpenKeyPlain(self.hive_handle, key_path)
		if err is not None and self.backup_mode and _rrp_err_is_access_denied(err):
			# The plain open is right for a principal whose DACL grant covers
			# this key, and it is the open that keeps the pipe intact on an
			# EDR-protected host, so it stays FIRST and unchanged. It is not
			# universal: a Backup Operators member is denied here, because its
			# access to these four class fields comes from SeBackupPrivilege
			# and not from the DACL, and hardcoding the plain open left that
			# role no way to read the bootkey at all -- the hive-to-disk export
			# was the only remaining route, which is the louder one.
			#
			# Retrying THIS ONE open with the bypass cannot reintroduce the
			# broken-pipe finding that made the plain open the default: that
			# failure killed the pipe before any answer came back, while this
			# retry only ever runs after the server has answered, with a
			# denial. The standard tooling's own Backup Operators module opens
			# these same four reads with BACKUP_RESTORE|OPEN_LINK from the
			# start, so the bypass is the documented way to read them.
			key_handle, err = await self.rrprpc.OpenKeyBackup(
				self.hive_handle, key_path
			)
		if err is not None:
			if throw is True:
				raise err
			self.__classes_lookup[key_path] = None
			return None

		data, err = await self.rrprpc.QueryInfoKeySpecial(key_handle)
		if err is not None:
			if throw is True:
				raise err
			return None

		result = data['lpClassOut'].replace('\x00', '')
		if self.cache_enabled is True:
			self.__classes_lookup[key_path] = result
		return result

	async def get_sd(self, key_handle):
		"""Return the security descriptor of a key"""
		sd, err = await self.rrprpc.GetKeySecurity(key_handle, securityInformation=SECURITY_INFORMATION.DACL|SECURITY_INFORMATION.OWNER|SECURITY_INFORMATION.GROUP)
		if err is not None:
			raise err
		return sd

	async def walk(self, path, depth = -1):
		"""Walk the registry tree"""
		raise NotImplementedError()
	
	async def search(self, pattern, in_keys = True, in_valuenames = True, in_values = True):
		"""Search the registry tree for a pattern"""
		raise NotImplementedError()
	
	
	
################## CUT HERE
class PERF_OBJECT_TYPE:
	def __init__(self):
		self.TotalByteLength = None
		self.DefinitionLength = None
		self.HeaderLength = None
		self.ObjectNameTitleIndex = None
		self.ObjectNameTitle = None
		self.ObjectHelpTitleIndex = None
		self.ObjectHelpTitle = None
		self.DetailLevel = None
		self.NumCounters = None
		self.DefaultCounter = None
		self.NumInstances = None
		self.CodePage = None
		self.PerfTime = None
		self.PerfFreq = None
		self.TotalByteLength = None
		self.TotalByteLength = None
		self.TotalByteLength = None

async def preftest(rs):
	pref_handle, err = await rs.ConnectRegistry(HKEY.PERFORMANCE_DATA)
	if err is not None:
		print('users error! %s' % err)
		return

	val_type, val_data, err = await rs.QueryValue(pref_handle, 'Counter 009', unpack_vals=False)
	if err is not None:
		print(traceback.format_tb(err.__traceback__))
		print('users error! %s' % err)
		return

	print(val_data[:100])

	return

async def OpenRegPathTest(rs):
	hk, err = await rs.OpenRegPath(r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion')
	print(err)

	res, err = await rs.QueryInfoKey(hk)
	print(res.dump())

	for i in range(200):
		value_name, value_type, value_data, err = await rs.EnumValue(hk, i)
		if err is not None:
			if err.errno == 259: #no more data is available
				break
			print(traceback.format_tb(err.__traceback__))
		print(value_data)

	return

async def ConnectRegistryTest(rs):
	import traceback
	users_handle, err = await rs.ConnectRegistry(HKEY.USERS)
	if err is not None:
		print('users error! %s' % err)
		return
	print('user handle: %s' % users_handle)
	for i in range(10):
		res, err = await rs.EnumKey(users_handle, i)
		if err is not None:
			if err.errno == 259: #no more data is available
				break
			print(err)
			print(traceback.format_tb(err.__traceback__))
		print(res)
	
	res, err = await rs.OpenKey(users_handle, "S-1-5-21-3448413973-1765323015-1500960949-500")
	if err is not None:
		print('openkey failed! %s' % err)
	
	print(res)
	
	for i in range(10):
		value_name, value_type, value_data, err = await rs.EnumValue(res, i)
		if err is not None:
			if err.errno == 259: #no more data is available
				break
			print(err)
			print(traceback.format_tb(err.__traceback__))
		print(value_data)

async def amain():
	from aiosmb.commons.connection.factory import SMBConnectionFactory
	from aiosmb.connection import SMBConnection
	import traceback

	url = 'smb2+ntlm-password://TEST\\Administrator:Passw0rd!1@10.10.10.2'
	su = SMBConnectionFactory.from_url(url)
	conn = su.get_connection()

	_, err = await conn.login()
	if err is not None:
		print(err)
		return
	else:
		print('SMB Connected!')
	rs = RRP(conn)
	_, err = await rs.connect()
	if err is not None:
		print(err)
		return
	print('RRP Connected!')

	users_handle, err = await rs.ConnectRegistry(HKEY.USERS)
	if err is not None:
		print('users error! %s' % err)
		return

	print('users_handle %s' % users_handle)
	for i in range(10):
		res, err = await rs.EnumKey(users_handle, i)
		if err is not None:
			if err.errno == 259: #no more data is available
				break
			print(err)
			print(traceback.format_tb(err.__traceback__))
		print(res)

	"""
	
	await ConnectRegistryTest(rs)


	res, err = await rs.OpenRegPath(r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')
	if err is not None:
		print(err)
	
	subkey_cnt, values_cnt, lastwrite_time, err = await rs.QueryInfoKey(res)
	if err is not None:
		print(err)
	print(subkey_cnt)
	print(values_cnt)
	print(lastwrite_time)

	print(22222222222222222222222222222)
	sd, err = await rs.GetKeySecurity(res, securityInformation=SECURITY_INFORMATION.OWNER|SECURITY_INFORMATION.DACL)
	if err is not None:
		print(err)
	print(sd)

	rx = res
	res2, err = await rs.CreateKey(res, "TEST")
	if err is not None:
		print(err)
	print(res)

	res, err = await rs.SetValue(res2, "TEST", REG_VAL_TYPE.SZ, "TESTING")
	if err is not None:
		print(err)
	print(res)


	#res, err = await rs.DeleteValue(res2, "TEST")
	#if err is not None:
	#	print(err)
	#print(res)

	res, err = await rs.DeleteKey(rx, "TEST")
	if err is not None:
		print(err)
	print(res)
	

	res, err = await rs.CloseKey(res)
	if err is not None:
		print(err)
	print(res)
	"""

if __name__ == '__main__':
	asyncio.run(amain())
