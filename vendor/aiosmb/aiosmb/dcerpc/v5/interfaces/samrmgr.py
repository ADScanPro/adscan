from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5 import samr
from aiosmb.dcerpc.v5.dtypes import RPC_SID, DACL_SECURITY_INFORMATION
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb import logger
import traceback
from aiosmb.commons.utils.extb import pprint_exc
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE

from contextlib import asynccontextmanager

@asynccontextmanager
async def samrrpc_from_smb(connection, auth_level=None, open=True, perform_dummy=False):
    instance, err = await SAMRRPC.from_smbconnection(connection, auth_level=auth_level, open=open, perform_dummy=perform_dummy)
    if err:
        # Handle or raise the error as appropriate
        raise err
    try:
        yield instance
    finally:
        await instance.close()

class SAMRRPC:
	def __init__(self):
		self.service_pipename = r'\samr'
		self.service_uuid = samr.MSRPC_UUID_SAMR
		self.dce = None
		self.handle = None
		
		self.domain_ids = {} #sid to RPC_SID
		self.domain_handles = {} #handle to sid
		
		self.user_handles = {} #handle to domain-sid
		self.alias_handles = {} #handle to domain-sid
		self.group_handles = {}
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None
	
	@staticmethod
	async def from_rpcconnection(connection:DCERPC5Connection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		try:
			service = SAMRRPC()
			service.dce = connection
			
			service.dce.set_auth_level(auth_level)
			if auth_level is None:
				service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P 
			
			_, err = await service.dce.connect()
			if err is not None:
				raise err
			
			_, err = await service.dce.bind(service.service_uuid)
			if err is not None:
				raise err
			
			if open is True:
				_, err = await service.open()
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
			rpctransport = SMBDCEFactory(connection, filename=SAMRRPC().service_pipename)		
			service, err = await SAMRRPC.from_rpcconnection(rpctransport.get_dce_rpc(), auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e
	
	async def open(self):
		if not self.dce:
			_, err = await self.connect()
			if err is not None:
				raise err

		ans, err = await samr.hSamrConnect(self.dce)
		if err is not None:
			raise err

		self.handle = ans['ServerHandle']

		return True,None
	
	async def close(self):
		if self.dce:
			for dhandle in self.domain_handles:
				try:
					await self.close_handle(dhandle)
				except:
					pass
					
			for uhandle in self.user_handles:
				try:
					await self.close_handle(uhandle)
				except:
					pass

			for uhandle in self.group_handles:
				try:
					await self.close_handle(uhandle)
				except:
					pass

			for uhandle in self.alias_handles:
				try:
					await self.close_handle(uhandle)
				except:
					pass
			
			try:
				await self.close_handle(self.handle)
			except:
				pass
				
			try:
				await self.dce.disconnect()
			except:
				pass
		
		return True,None
		
	async def close_handle(self, handle):
		resp, err = await samr.hSamrCloseHandle(self.dce, handle)
		if err is not None:
			return None, err
		return resp, None
	
	async def get_info(self, domain_handle, domainInformationClass = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2):
		resp, err = await samr.hSamrQueryInformationDomain(self.dce, domain_handle, domainInformationClass = domainInformationClass)
		if err is not None:
			return None, err
		return resp, None
	
	async def get_user_rid_by_name(self, domain_handle, username):
		resp, err = await samr.hSamrLookupNamesInDomain(self.dce, domain_handle, [username])
		if err is not None:
			return None, err
		
		rids = []
		for ridraw in resp['RelativeIds']['Element']:
			rids.append(ridraw['Data'])
		return rids[0], err
	
	async def list_domains(self):
		try:
			status = NTStatus.MORE_ENTRIES
			enumerationContext = 0
			while status == NTStatus.MORE_ENTRIES:
				resp, err = await samr.hSamrEnumerateDomainsInSamServer(self.dce, self.handle, enumerationContext = enumerationContext)
				if err is not None:
					if err.error_code != NTStatus.MORE_ENTRIES.value:
						raise err
					resp = err.get_packet()
				
				for domain in resp['Buffer']['Buffer']:
					yield domain['Name'], None
				
				enumerationContext = resp['EnumerationContext']
				status = NTStatus(resp['ErrorCode'])
		except Exception as e:
			yield None, e

	async def list_domains_raw(self):
		try:
			status = NTStatus.MORE_ENTRIES
			enumerationContext = 0
			while status == NTStatus.MORE_ENTRIES:
				resp, err = await samr.hSamrEnumerateDomainsInSamServer(self.dce, self.handle, enumerationContext = enumerationContext)
				if err is not None:
					if err.error_code != NTStatus.MORE_ENTRIES.value:
						raise err
					resp = err.get_packet()
				
				for domain in resp['Buffer']['Buffer']:
					yield domain, None
				
				enumerationContext = resp['EnumerationContext']
				status = NTStatus(resp['ErrorCode'])
		except Exception as e:
			yield None, e
	
	async def get_domain_sid(self, domain_name):
		try:
			resp, err = await samr.hSamrLookupDomainInSamServer(self.dce, self.handle, domain_name)
			if err is not None:
				raise err

			self.domain_ids[resp['DomainId'].formatCanonical()] = resp['DomainId']
			return resp['DomainId'].formatCanonical(), None
		except Exception as e:
			return None, e

	async def refresh_domains(self):
		try:
			async for domain, err in self.list_domains():
				if err is not None:
					continue
				await self.get_domain_sid(domain)
				return True, None
		except Exception as e:
			return None, e

	
	async def open_domain(self, domain_sid, access_level = samr.MAXIMUM_ALLOWED):
		try:
			if len(self.domain_ids) == 0:
				await self.refresh_domains()
			
			if domain_sid not in self.domain_ids:
				raise Exception('Unknown domain "%s"' % domain_sid)
			
			resp, err = await samr.hSamrOpenDomain(self.dce, self.handle, domainId = self.domain_ids[domain_sid], desiredAccess = access_level)
			if err is not None:
				raise err
			self.domain_handles[resp['DomainHandle']] = domain_sid
			return resp['DomainHandle'], None
		except Exception as e:
			return None, e
	
	async def open_domain_by_name(self, domain_name:str, access_level=samr.MAXIMUM_ALLOWED):
		try:
			foundname = None
			async for domainname, err in self.list_domains():
				if err is not None:
					raise err
				if domainname == domain_name:
					foundname = domainname
					break
			if foundname is None:
				raise Exception('Domain not found! %s' % domain_name)

			resp, err = await samr.hSamrLookupDomainInSamServer(self.dce, self.handle, foundname)
			if err is not None:
				raise err
			domain_id = resp['DomainId']
			resp, err = await samr.hSamrOpenDomain(self.dce, self.handle, domainId=domain_id, desiredAccess=access_level)
			if err is not None:
				raise err
			
			self.domain_handles[resp['DomainHandle']] = domain_id.formatCanonical()
			self.domain_ids[domain_id.formatCanonical()] = domain_id
			return resp['DomainHandle'], None

		except Exception as e:
			return None, e


	async def list_domain_users(self, domain_handle):
		try:
			user_type = samr.USER_NORMAL_ACCOUNT
			status = NTStatus.MORE_ENTRIES
			enumerationContext = 0
			while status == NTStatus.MORE_ENTRIES:
				resp, err = await samr.hSamrEnumerateUsersInDomain(self.dce, domain_handle, user_type, enumerationContext=enumerationContext)
				if err is not None:
					if err.error_code != NTStatus.MORE_ENTRIES.value:
						raise err
						return
					resp = err.get_packet()

				for user in resp['Buffer']['Buffer']:
					user_sid = '%s-%s' % (self.domain_handles[domain_handle], user['RelativeId'])
					yield user['Name'], user_sid, None

				enumerationContext = resp['EnumerationContext']
				status = NTStatus(resp['ErrorCode'])
		except Exception as e:
			yield None, None, e

	async def list_domain_all_principals(self, domain_handle):
		"""Enumerate ALL account types in the domain, not just normal user accounts.

		``list_domain_users`` filters on ``USER_NORMAL_ACCOUNT`` (0x10) and so
		EXCLUDES machine accounts (workstations, DCs) and trust accounts. That is
		correct for user-enumeration surfaces, but WRONG for a DCSync full
		replication walk, which must replicate machine-account and trust-account
		keys too (a downstream step needing a machine-account key — S4U2Self,
		RBCD, silver, shadow-creds, cross-org TGT delegation — otherwise has no
		key to work with). This mirrors impacket's secretsdump DRSUAPI dump, which
		enumerates with the combined mask NORMAL | WORKSTATION_TRUST |
		SERVER_TRUST | INTERDOMAIN_TRUST.
		"""
		try:
			user_type = (
				samr.USER_NORMAL_ACCOUNT
				| samr.USER_WORKSTATION_TRUST_ACCOUNT
				| samr.USER_SERVER_TRUST_ACCOUNT
				| samr.USER_INTERDOMAIN_TRUST_ACCOUNT
			)
			status = NTStatus.MORE_ENTRIES
			enumerationContext = 0
			while status == NTStatus.MORE_ENTRIES:
				resp, err = await samr.hSamrEnumerateUsersInDomain(self.dce, domain_handle, user_type, enumerationContext=enumerationContext)
				if err is not None:
					if err.error_code != NTStatus.MORE_ENTRIES.value:
						raise err
						return
					resp = err.get_packet()

				for user in resp['Buffer']['Buffer']:
					user_sid = '%s-%s' % (self.domain_handles[domain_handle], user['RelativeId'])
					yield user['Name'], user_sid, None

				enumerationContext = resp['EnumerationContext']
				status = NTStatus(resp['ErrorCode'])
		except Exception as e:
			yield None, None, e

	async def list_domain_groups(self, domain_handle):
		try:
			status = NTStatus.MORE_ENTRIES
			enumerationContext = 0
			while status == NTStatus.MORE_ENTRIES:
				resp, err = await samr.hSamrEnumerateGroupsInDomain(self.dce, domain_handle, enumerationContext=enumerationContext)
				if err is not None:
					if err.error_code != NTStatus.MORE_ENTRIES.value:
						raise err
					resp = err.get_packet()

				for group in resp['Buffer']['Buffer']:
					group_sid = '%s-%s' % (self.domain_handles[domain_handle], group['RelativeId'])
					yield group['Name'], group_sid, None
				enumerationContext = resp['EnumerationContext'] 
				status = NTStatus(resp['ErrorCode'])
		except Exception as e:
			yield None, None, e
	
	async def add_member_to_alias(self, alias_handle, sid):
		try:
			resp, err = await samr.hSamrAddMemberToAlias(self.dce, alias_handle, sid)
			if err is not None:
				if err.error_code != NTStatus.MORE_ENTRIES.value:
					raise err
				resp = err.get_packet()
			status = NTStatus(resp['ErrorCode'])
			result = status == NTStatus.SUCCESS
			return result, None
		except Exception as e:
			return None, e

	async def enumerate_users(self, domain_handle):
		try:
			status = NTStatus.MORE_ENTRIES
			enumerationContext = 0
			while status == NTStatus.MORE_ENTRIES:
				resp, err = await samr.hSamrEnumerateUsersInDomain(self.dce, domain_handle,  enumerationContext=enumerationContext)
				if err is not None:
					if err.error_code != NTStatus.MORE_ENTRIES.value:
						raise err
					resp = err.get_packet()

				for user in resp['Buffer']['Buffer']:
					user_sid = '%s-%s' % (self.domain_handles[domain_handle], user['RelativeId'])
					yield user['Name'], user_sid, None
				enumerationContext = resp['EnumerationContext'] 
				status = NTStatus(resp['ErrorCode'])
		except Exception as e:
			yield None, None, e

	async def open_user(self, domain_handle, user_id, access_level = samr.MAXIMUM_ALLOWED):
		try:
			user_id = int(user_id)
			resp, err = await samr.hSamrOpenUser(self.dce, domain_handle, userId=user_id, desiredAccess = access_level)
			if err is not None:
				raise err
			self.user_handles[resp['UserHandle']] = self.domain_handles[domain_handle]
			return resp['UserHandle'], None
		except Exception as e:
			return None, e
	
	async def get_user_info(self, user_handle, userInformationClass = samr.USER_INFORMATION_CLASS.UserGeneralInformation):
		try:
			resp, err = await samr.hSamrQueryInformationUser(self.dce, user_handle, userInformationClass = userInformationClass)
			if err is not None:
				raise err
			

			print(resp.dump())
			return resp, None
		except Exception as e:
			return None, e
	
	async def get_user_info_all(self, user_handle:int):
		try:
			user_handle = int(user_handle)
			resp, err = await samr.hSamrQueryInformationUser(self.dce, user_handle, userInformationClass = samr.USER_INFORMATION_CLASS.UserGeneralInformation)
			if err is not None:
				raise err
			

			print(resp.dump())
			return resp, None
		except Exception as e:
			return None, e

	async def get_user_username(self, user_handle:int):
		try:
			resp, err = await samr.hSamrQueryInformationUser(self.dce, user_handle, userInformationClass = samr.USER_INFORMATION_CLASS.UserGeneralInformation)
			if err is not None:
				raise err
			
			username = resp['Buffer']['General']['UserName']
			return username, None
		except Exception as e:
			return None, e
	
	async def get_user_group_memberships(self, user_handle):
		try:
			resp, err = await samr.hSamrGetGroupsForUser(self.dce, user_handle)
			if err is not None:
				raise err
			
			for group in resp['Groups']['Groups']:
				yield '%s-%s' % (self.user_handles[user_handle], group['RelativeId']) , None
		except Exception as e:
			yield None, e

	async def list_aliases(self, domain_handle):
		try:
			status = NTStatus.MORE_ENTRIES
			enumerationContext = 0
			while status == NTStatus.MORE_ENTRIES:
				resp, err = await samr.hSamrEnumerateAliasesInDomain(self.dce, domain_handle, enumerationContext=enumerationContext)
				if err is not None:
					if err.error_code != NTStatus.MORE_ENTRIES.value:
						raise err
					resp = err.get_packet()

				for alias in resp['Buffer']['Buffer']:
					yield alias['Name'] , alias['RelativeId'], None
				
				enumerationContext = resp['EnumerationContext'] 
				status = NTStatus(resp['ErrorCode'])
		except Exception as e:
			yield None, None, e

	async def open_alias(self, domain_handle, alias_id, access_level=samr.MAXIMUM_ALLOWED):
		try:
			resp, err = await samr.hSamrOpenAlias(self.dce, domain_handle, aliasId=alias_id, desiredAccess=access_level)
			if err is not None:
				raise err
			self.alias_handles[resp['AliasHandle']] = self.domain_handles[domain_handle]
			return resp['AliasHandle'], None
		except Exception as e:
			return None, e
	
	async def list_alias_members(self, alias_handle):
		try:
			resp, err = await samr.hSamrGetMembersInAlias(self.dce, alias_handle)
			if err is not None:
				raise err
			
			for sidr in resp['Members']['Sids']:
				yield sidr['SidPointer'].formatCanonical(), None
		except Exception as e:
			yield None, e

	async def open_group(self, domain_handle, group_id, access_level=samr.MAXIMUM_ALLOWED):
		try:
			resp, err = await samr.hSamrOpenGroup(self.dce, domain_handle, aliasId=group_id, desiredAccess=access_level)
			if err is not None:
				raise err
			self.group_handles[resp['GroupHandle']] = self.domain_handles[domain_handle]
			return resp['GroupHandle'], None
		except Exception as e:
			return None, e

	async def list_group_members(self, group_handle):
		try:
			resp, err = await samr.hSamrGetMembersInGroup(self.dce, group_handle)
			if err is not None:
				raise err
			
			for sidr in resp['Members']['Sids']:
				yield sidr['SidPointer'].formatCanonical(), None
		except Exception as e:
			yield None, e
	
	async def get_security_info(self, handle, securityInformation = DACL_SECURITY_INFORMATION):
		try:
			resp, err = await samr.hSamrQuerySecurityObject(self.dce, handle, securityInformation)
			if err is not None:
				raise err
			return resp, None
		except Exception as e:
			return None, e

	async def openBuiltinDomain(self, access_level=samr.MAXIMUM_ALLOWED):
		try:
			resp, err = await samr.hSamrEnumerateDomainsInSamServer(self.dce, self.handle)
			if resp is None:
				raise err
			
			domain_name = resp['Buffer']['Buffer'][1]['Name'] #change it back to 0
			resp, err = await samr.hSamrLookupDomainInSamServer(self.dce, self.handle, domain_name)
			if err is not None:
				raise err
			domain_id = resp['DomainId']
			resp, err = await samr.hSamrOpenDomain(self.dce, self.handle, domainId=domain_id, desiredAccess=access_level)
			if err is not None:
				raise err
			self.domain_handles[resp['DomainHandle']] = domain_id
			return resp['DomainHandle'], None
			
		except Exception as e:
			return None, e

	async def create_user(self, dhandle, username:str, password:str, account_type=samr.USER_NORMAL_ACCOUNT):
		try:
			res, err = await samr.hSamrCreateUser2InDomain(self.dce, dhandle, username, accountType=account_type, desiredAccess=samr.USER_ALL_ACCESS)
			if err is not None:
				raise err
			
			user_handle = res['UserHandle']
			try:
				_, err = await samr.hSamrSetNTInternal1(self.dce, user_handle, password, '')
				if err is not None:
					raise err
			except samr.DCERPCSessionError as e:
				samr.hSamrDeleteUser(self.dce, user_handle)
				raise
			
			return await self.enable_account(user_handle)
		
		except Exception as e:
			return None, e

	async def enable_account(self, uhandle):
		try:
			res, err = await samr.hSamrQueryInformationUser2(self.dce, uhandle, samr.USER_INFORMATION_CLASS.UserAllInformation)
			if err is not None:
				raise err
			uac = res['Buffer']['All']['UserAccountControl']
			buffer = samr.SAMPR_USER_INFO_BUFFER()
			buffer['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
			# Idempotent clear of USER_ACCOUNT_DISABLED.  The original code
			# used XOR, which is a toggle: if the disabled bit was already
			# cleared by Windows (e.g. after hSamrSetNTInternal1 on Server
			# 2019+ for some account types), XOR re-disables the account.
			# AND NOT always leaves the bit cleared regardless of input
			# state, matching the well-known impacket addcomputer.py flow
			# that explicitly overwrites UAC after create.
			buffer['Control']['UserAccountControl'] = uac & ~samr.USER_ACCOUNT_DISABLED
			res, err = await samr.hSamrSetInformationUser2(self.dce, uhandle, buffer)
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			return None, e

	async def disable_account(self, uhandle):
		try:
			res, err = await samr.hSamrQueryInformationUser2(self.dce, uhandle, samr.USER_INFORMATION_CLASS.UserAllInformation)
			if err is not None:
				raise err
			uac = res['Buffer']['All']['UserAccountControl']
			buffer = samr.SAMPR_USER_INFO_BUFFER()
			buffer['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
			buffer['Control']['UserAccountControl'] = samr.USER_ACCOUNT_DISABLED | uac
			_, err = await samr.hSamrSetInformationUser2(self.dce, uhandle, buffer)
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			return None, e

	async def delete_account(self, uhandle):
		return await samr.hSamrDeleteUser(self.dce, uhandle)

	async def change_account_password(self, uhandle, oldpw, newpw):
		return await samr.hSamrChangePasswordUser(self.dce, uhandle, oldpw, newpw)

	async def change_account_password_nt(self, uhandle, oldpwNT, newpw):
		return await samr.hSamrChangePasswordUser_hash(self.dce, uhandle, oldpwNT, newpw)
	
	async def change_account_password_4(self, uhandle, newpw):
		return await samr.hSamrSetPasswordInternal4New(self.dce, uhandle, newpw)
	
	async def change_account_password_internal(self, uhandle, newpw):
		return await samr.hSamrSetNTInternal1(self.dce, uhandle, newpw)

	async def unroll_group(self, dhandle, grid, all_grids = None, grids_seen = None):
		ghandle = None
		if grids_seen is None:
			grids_seen = {}
		try:
			if all_grids is None:
				all_grids = {}
				async for gname, tg, err in self.list_domain_groups(dhandle):
					if err is not None:
						raise err
					all_grids[tg] = 1

			ghandle, err = await self.open_group(dhandle, grid)
			if err is not None:
				raise err
			
			async for sid, err in self.list_group_members(ghandle):
				if err is not None:
					raise err
				rid = int(str(sid).split('-')[-1])
				if rid in all_grids:
					# okay this is a group
					if rid not in grids_seen:
						grids_seen[rid] = 1
						async for sid, err in self.unroll_group(dhandle, rid, all_grids = all_grids, grids_seen = grids_seen):
							if err is not None:
								break
							yield sid, None
				else:
					# this is a user
					yield sid, None
		except Exception as e:
			traceback.print_exc()
			yield None, e
		finally:
			if ghandle is not None:
				await self.close_handle(ghandle)
				del self.group_handles[ghandle]

	async def unroll_alias(self, dhandle, grid, all_arids = None, arids_seen = None):
		ghandle = None
		if arids_seen is None:
			arids_seen = {}
		try:
			if all_arids is None:
				all_arids = {}
				async for gname, tg, err in self.list_aliases(dhandle):
					if err is not None:
						raise err
					all_arids[tg] = 1

			ghandle, err = await self.open_alias(dhandle, grid)
			if err is not None:
				raise err
			
			async for sid, err in self.list_alias_members(ghandle):
				if err is not None:
					raise err
				rid = int(str(sid).split('-')[-1])
				if rid in all_arids:
					# okay this is a group
					if rid not in arids_seen:
						arids_seen[rid] = 1
						async for sid, err in self.unroll_alias(dhandle, rid, all_arids = all_arids, arids_seen = arids_seen):
							if err is not None:
								break
							yield sid, None
				else:
					# this is a user
					yield sid, None
		except Exception as e:
			traceback.print_exc()
			yield None, e
		finally:
			if ghandle is not None:
				await self.close_handle(ghandle)
				del self.alias_handles[ghandle]
	


	async def list_users_allowed_to_replicate(self, domain_name):
		try:
			alias_rids = {}
			group_rids = {}
			denied_rids = {
				500 : 1,
				501 : 1,
				502 : 1,
				503 : 1
			}
			async with self.get_domain_handle(domain_name) as dhandle:
				async for aname, arid, err in self.list_aliases(dhandle):
					if err is not None:
						raise err
					alias_rids[arid] = 1

				async for gname, grid, err in self.list_domain_groups(dhandle):
					if err is not None:
						raise err
					group_rids[grid] = 1
				
				# Denied Password Replication
				async with self.get_alias_handle(domain_name, 572) as ahandle:
					async for sid, err in self.list_alias_members(ahandle):
						rid = str(sid).split('-')[-1]
						denied_rids[int(rid)] = 1
				
				# Unroll groups in denied list

				denied_groups = {}
				denied_aliases = {}
				for drid in denied_rids:
					if drid in group_rids:
						denied_groups[drid] = 1
					elif drid in alias_rids:
						denied_aliases[drid] = 1
				
				for grid in denied_groups:
					async for sid, err in self.unroll_group(dhandle, grid, all_grids=group_rids):
						if err is not None:
							break
						urid = int(str(sid).split('-')[-1])
						denied_rids[urid] = 1
				
				for grid in denied_aliases:
					async for sid, err in self.unroll_alias(dhandle, grid, all_arids=alias_rids):
						if err is not None:
							break
						urid = int(str(sid).split('-')[-1])
						denied_rids[urid] = 1
				
				async for name, sid, err in self.list_domain_users(dhandle):
					if err is not None:
						raise err
					rid = int(str(sid).split('-')[-1])
					if rid in denied_rids:
						continue

					yield name, sid, rid, None
		except Exception as e:
			traceback.print_exc()
			yield None, None, None, e			


	@asynccontextmanager
	async def get_domain_handle(self, domain_name, access_level = samr.MAXIMUM_ALLOWED):
		try:
			if domain_name is None or domain_name == '' or domain_name == 'Builtin':
				dhandle, err = await self.openBuiltinDomain(access_level=access_level)
			else:
				dhandle, err = await self.open_domain_by_name(domain_name, access_level=access_level)
			if err is not None:
				raise err
			
			yield dhandle
		finally:
			if dhandle is not None:
				await self.close_handle(dhandle)
				del self.domain_handles[dhandle]


	@asynccontextmanager
	async def get_alias_handle(self, domain_name, alias_rid, domain_access_level = samr.MAXIMUM_ALLOWED, alias_access_level = samr.MAXIMUM_ALLOWED):
		alias_handle = None
		try:
			async with self.get_domain_handle(domain_name, access_level=domain_access_level) as dhandle:
				alias_handle, err = await self.open_alias(dhandle, alias_rid, access_level = alias_access_level)
				if err is not None:
					raise err
				yield alias_handle
			
		finally:
			if alias_handle is not None:
				await self.close_handle(alias_handle)
				del self.alias_handles[alias_handle]

	@asynccontextmanager
	async def get_group_handle(self, domain_name, group_rid, domain_access_level = samr.MAXIMUM_ALLOWED, group_access_level = samr.MAXIMUM_ALLOWED):
		group_handle = None
		try:
			async with self.get_domain_handle(domain_name, access_level=domain_access_level) as dhandle:
				group_handle, err = await self.open_group(self, dhandle, group_rid, access_level = group_access_level)
				if err is not None:
					raise err
				yield group_handle
			
		finally:
			if group_handle is not None:
				await self.close_handle(group_handle)
				del self.group_handles[group_handle]


	@asynccontextmanager
	async def get_user_handle(self, domain_name, user_name, domain_access_level = samr.MAXIMUM_ALLOWED, user_access_level = samr.MAXIMUM_ALLOWED):
		uhandle = None
		try:
			async with self.get_domain_handle(domain_name, access_level=domain_access_level) as dhandle:
				user_rid, err = await self.get_user_rid_by_name(dhandle, user_name)
				if err is not None:
					raise err
						
				uhandle, err = await self.open_user(dhandle, user_rid, access_level = user_access_level)
				if err is not None:
					raise err

				yield uhandle
		finally:
			if uhandle is not None:
				await self.close_handle(uhandle)
				del self.user_handles[uhandle]
