import enum
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.interfaces.directory import SMBDirectory
from aiosmb.commons.connection.target import SMBTarget, SMBConnectionDialect
from aiosmb.connection import SMBConnection
import ipaddress
import copy
from typing import List

from badauth.common.credentials import UniCredential
from badauth.common.constants import asyauthSecret
from badauth.common.credentials.spnego import SPNEGOCredential

class SMBConnectionFactory:
	def __init__(self, credential:UniCredential = None, target:SMBTarget = None):
		self.credential = credential
		self.target = target
		self.proxies= None
	
	@staticmethod
	def create_dummy(authtype='NTLM', proxies = None):
		"""Creates a new SMBConnectionFactory object with a dummy target and credential"""
		"""User for scanners that don't need to authenticate to the target, and when the target will be set later."""
		target = SMBTarget.create_dummy(proxies)
		if authtype == 'NTLM':
			from badauth.common.credentials.ntlm import NTLMCredential
			credential = NTLMCredential.create_guest()
		else:
			raise Exception('Unknown authtype: %s' % authtype)
		return SMBConnectionFactory(credential, target)
	
	@staticmethod
	def from_url(connection_url):
		"""Creates SMBConnectionFactory from url string"""
		target = SMBTarget.from_url(connection_url)
		credential = UniCredential.from_url(connection_url)
		return SMBConnectionFactory(credential, target)
	
	@staticmethod
	def from_smbconnection(smbconnection:SMBConnection):
		"""Creates a new SMBConnectionFactory object from an existing SMBConnection object"""
		"""This is useful when you have a connection object, but you need to create a new connection with the same credentials"""
		return SMBConnectionFactory(smbconnection.gssapi.get_copy(), copy.deepcopy(smbconnection.target))

	def get_connection(self, nosign:bool=False):
		"""Creates a new SMBConnection object"""
		spneg = self.get_credential()
		target = self.get_target()
		if nosign is None:
			nosign = False
		
		return SMBConnection(spneg, target, nosign=nosign)

	def create_connection_newtarget(self, ip_or_hostname):
		"""Creates a new SMBConnection object with a new target. 
		Credentials are copied from the original connection factory
		Target parameters will remain the same as the original, 
		but is set to the ip_or_hostname parameter"""
		spneg = self.get_credential()
		#credential.target = ip_or_hostname
		target = self.get_target()

		try:
			ipaddress.ip_address(ip_or_hostname)
			target.ip = ip_or_hostname
			target.hostname = None
		except:
			target.hostname = ip_or_hostname
			target.ip = ip_or_hostname
		
		return SMBConnection(spneg, target)

	def get_file(self):
		"""Creates a new SMBFile object using the path from the URL string, or the Target object"""
		return SMBFile.from_smbtarget(self.get_target())
	
	def get_directory(self):
		"""Creates a new SMBDirectory object using the path from the URL string, or the Target object"""
		return SMBDirectory.from_smbtarget(self.get_target())

	def get_proxies(self):
		"""Returns a copy of proxies from the target object"""
		return copy.deepcopy(self.target.proxies)

	def get_target(self):
		"""Returns a copy of the target object"""
		return copy.deepcopy(self.target)

	def get_credential(self):
		"""Returns a new SPNEGOCredential object with the credential from the factory"""
		return SPNEGOCredential([copy.deepcopy(self.credential)]).build_context()
	
	async def test_connection(self):
		ntlm_data = None
		try:
			connection = self.get_connection()
			async with connection:
				_, err = await connection.login()
				ntlm_data = connection.get_extra_info()
				if err is not None:
					raise err

				return True, ntlm_data, None
		except Exception as e:
			return False, ntlm_data, e

	@staticmethod
	def from_components(ip_or_hostname:str, username:str, secret:str, secrettype:str = 'password', 
							domain:str = None, port:str = 445, dialect:str = 'smb', dcip:str = None, proxies = None, authproto:str = 'ntlm',
							altname:str = None, altdomain:str = None, etype:List[int]=[23,17,18], certdata:str= None, keydata:str=None):
		"""Builds a new SMBConnectionFactory object from scratch.
		This doesn't support all features of the SMBTarget and SMBCredential objects, but it's a quick way to build a connection factory."""
		import ipaddress
		if username.count('\\') == 1:
			domain, username = username.split('\\')
		if domain is not None:
			domain = domain.upper()
		
		ip = None
		hostname = None
		try:
			ipaddress.ip_address(ip_or_hostname)
			ip = ip_or_hostname
			hostname = None
		except:
			ip = None
			hostname = ip_or_hostname
		
		# build a target
		target = SMBTarget(ip, port, hostname, dc_ip=dcip, domain=domain, proxies=copy.deepcopy(proxies))
		target.update_dialect(SMBConnectionDialect(dialect.upper()))


		authproto = authproto.upper()
		secrettype = asyauthSecret(secrettype.upper())
		if authproto == 'NTLM':
			from badauth.common.credentials.ntlm import NTLMCredential
			credential = NTLMCredential(
				secret,
				username, 
				domain, 
				secrettype, 
			)
		elif authproto == 'KERBEROS':
			from badauth.common.credentials.kerberos import KerberosCredential
			credential = KerberosCredential(
				secret,
				username,
				domain,
				secrettype,
				target = target,
				altname=altname,
				altdomain=altdomain,
				etypes=[23,17,18],
				certdata=certdata,
				keydata=keydata,
			)
		
		else:
			raise Exception('Unknown authproto: %s' % authproto)

		return SMBConnectionFactory(credential, target)
	
	def __str__(self):
		t = '==== SMBConnectionFactory ====\r\n'
		for k in self.__dict__:
			val = self.__dict__[k]
			if isinstance(val, enum.IntFlag):
				val = val
			elif isinstance(val, enum.Enum):
				val = val.name
			
			t += '%s: %s\r\n' % (k, str(val))
			
		return t
			
if __name__ == '__main__':
	user = 'TEST\\victim'
	password = 'Passw0rd!1'
	domain = 'TEST'
	ip = '10.10.10.2'
	port = 445
	dialect = 'smb'
	secrettype = 'password'
	authproto = 'ntlm'

	factory = SMBConnectionFactory.from_components(
		ip,
		user,
		password,
		secrettype,
		domain,
		port,
		dialect		
	)

	from aiosmb.commons.interfaces.file import SMBFile
	url_tests = [
		'smb://10.10.10.2',
		'smb://10.10.10.2:9000',
		'smb3://10.10.10.2:9000',
		'smb-tcp://10.10.10.2',
		'smb-tcp://10.10.10.2:9000',
		'smb-udp://10.10.10.2:138',
		'smb+ntlm-password://domain\\user@10.10.10.2',
		'smb-tcp+ntlm-password://domain\\user:password@10.10.10.2',
		'smb-tcp+ntlm-password://domain\\user:password@10.10.10.2:10000',
		'smb-tcp+ntlm-nt://domain\\user:alma@10.10.10.2',
		'smb+ntlm-nt://domain\\user:alma@10.10.10.2',
		'smb+ntlm-nt://domain\\user:alma@10.10.10.2',
		'smb-tcp+kerberos-password://domain\\alma:password@10.10.10.10.2',
		'smb-tcp+kerberos-aes://domain\\alma:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.10.10.10.2',
		'smb-tcp+kerberos-aes://domain\\alma:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.10.10.10.2',
		'smb-tcp+kerberos-nt://domain\\alma:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.10.10.10.2',
		'smb-tcp+kerberos-rc4://domain\\alma:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.10.10.10.2',
		#'smb+sspi://10.10.10.10.2',
		'smb+sspi-ntlm://10.10.10.10.2',
		'smb+sspi-kerberos://10.10.10.10.2',
		'smb://10.10.10.2/?timeout=10',
		'smb://10.10.10.2/?timeout=10&dc=10.10.10.2',
		'smb://10.10.10.2/?timeout=10&dc=10.10.10.2&proxytype=socks5',
		'smb://10.10.10.2/?timeout=10&dc=10.10.10.2&proxytype=socks5&proxyhost=127.0.0.1',
		'smb://10.10.10.2/?timeout=10&dc=10.10.10.2&proxytype=socks5&proxyhost=127.0.0.1&proxyuser=admin&proxypass=alma',
		'smb://10.10.10.2/?timeout=10&dc=10.10.10.2&proxytype=socks5&proxyhost=127.0.0.1&proxyuser=admin&proxypass=alma&dc=10.10.10.2&dns=8.8.8.8',
		'smb://10.10.10.2/?timeout=10&dc=10.10.10.2&proxytype=socks5s&proxyhost=127.0.0.1&proxyuser=admin&proxypass=alma&dc=10.10.10.2&dns=8.8.8.8',
	]
	for url in url_tests:
		print('===========================================================================')
		print(url)
		try:
			dec = SMBConnectionFactory.from_url(url)
			creds = dec.get_credential()
			target = dec.get_target()
			smbfile = dec.get_file()
			print(smbfile)
		except Exception as e:
			import traceback
			traceback.print_exc()
			print('ERROR! Reason: %s' % e)
			input()
		else:
			print(str(creds))
			print(str(target))
			input()
			
			
