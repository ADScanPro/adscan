
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from os import stat
from sqlite3 import connect
from asysocks.unicomm.common.target import UniTarget, UniProto
from urllib.parse import urlparse, parse_qs, unquote
from asysocks.unicomm.utils.paramprocessor import str_one, int_one, bool_one

def float_one(x):
	# ADscan: the inter-page sleep (``rate``) is seconds as a FLOAT, so a pacing
	# level can ask for 0.2 s between pages. ``int_one`` truncated it to whole
	# seconds (0.2 -> ValueError, 1.5 -> ValueError). Locked by
	# tests/unit/vendor/test_badldap_rate_float_url_param.py.
	return float(x[0])

msldaptarget_url_params = {
	'pagesize' : int_one,
	'rate' : float_one,
}


class MSLDAPTarget(UniTarget):
	"""
	Describes the connection to the server.
	
	:param host: IP address or hostname of the server
	:type host: str
	:param port: port of the LDAP service running on the server
	:type port: int
	:param proto: Connection protocol to be used
	:type proto: :class:`UniProto`
	:param tree: The tree to connect to
	:type tree: str
	:param proxies: specifies what kind of proxy to be used
	:type proxies: :class:`List[UniProxyTarget]`
	:param timeout: connection timeout in seconds
	:type timeout: int
	:param ldap_query_page_size: Maximum number of elements to fetch in each paged_query call.
	:type ldap_query_page_size: int
	:param ldap_query_ratelimit: rate limit of paged queries. This will cause a sleep (in seconds) between fetching of each page of the query
	:type ldap_query_ratelimit: float
	:param dc_ip: Ip address of the kerberos server (if kerberos is used)
	:type dc_ip: str
	"""
	def __init__(self, ip, port = 389, protocol = UniProto.CLIENT_TCP, tree = None, proxies = None, timeout = 10, ldap_query_page_size = 1000, ldap_query_ratelimit = 0, dns:str=None, dc_ip:str = None, domain:str = None, hostname:str = None, ssl_ctx = None):
		UniTarget.__init__(self, ip, port, protocol, timeout, hostname = hostname, ssl_ctx= ssl_ctx, proxies = proxies, domain = domain, dc_ip = dc_ip, dns=dns)
		self.tree = tree
		self.ldap_query_page_size = ldap_query_page_size
		self.ldap_query_ratelimit = ldap_query_ratelimit
	
	def to_target_string(self):
		return 'ldap/%s@%s' % (self.get_hostname_or_ip(), self.domain)  #ldap/WIN2019AD.test.corp @ TEST.CORP

	def get_host(self):
		if self.protocol == UniProto.CLIENT_SSL_TCP:
			proto = 'ldaps'
		elif self.protocol == UniProto.CLIENT_TCP:
			proto = 'ldap'
		return '%s://%s:%s' % (proto, self.get_hostname_or_ip(), self.port)

	def is_ssl(self):
		return self.protocol == UniProto.CLIENT_SSL_TCP
	
	@staticmethod
	def from_url(connection_url):
		url_e = urlparse(connection_url)
		url_dict = url_e._asdict()
		for prop, val in url_dict.items():
			if type(val) is str:
				url_dict[prop] = unquote(val)
		url_e = url_e._replace(**url_dict)
		schemes = []
		for item in url_e.scheme.upper().split('+'):
			schemes.append(item.replace('-','_'))
		if schemes[0] == 'LDAP':
			protocol = UniProto.CLIENT_TCP
			port = 389
		elif schemes[0] == 'LDAPS':
			protocol = UniProto.CLIENT_SSL_TCP
			port = 636
		elif schemes[0] == 'LDAP_SSL':
			protocol = UniProto.CLIENT_SSL_TCP
			port = 636
		elif schemes[0] == 'LDAP_TCP':
			protocol = UniProto.CLIENT_TCP
			port= 389
		elif schemes[0] == 'LDAP_UDP':
			raise NotImplementedError()
			protocol = UniProto.CLIENT_UDP
			port = 389
		elif schemes[0] == 'GC':
			protocol = UniProto.CLIENT_TCP
			port = 3268
		elif schemes[0] == 'GC_SSL':
			protocol = UniProto.CLIENT_SSL_TCP
			port = 3269
		else:
			raise Exception('Unknown protocol! %s' % schemes[0])
		
		if url_e.port:
			port = url_e.port
		if port is None:
			raise Exception('Port must be provided!')
		
		path = None
		if url_e.path not in ['/', '', None]:
			path = url_e.path
		
		unitarget, extraparams = UniTarget.from_url(connection_url, protocol, port, msldaptarget_url_params)
		pagesize = extraparams['pagesize'] if extraparams['pagesize'] is not None else 1000
		rate = extraparams['rate'] if extraparams['rate'] is not None else 0

		target = MSLDAPTarget(
			unitarget.ip, 
			port = unitarget.port, 
			protocol = unitarget.protocol, 
			tree = path, 
			proxies = unitarget.proxies, 
			timeout = unitarget.timeout, 
			ldap_query_page_size = pagesize, 
			ldap_query_ratelimit = rate,
			dns = unitarget.dns, 
			dc_ip = unitarget.dc_ip, 
			domain = unitarget.domain, 
			hostname = unitarget.hostname,
			ssl_ctx = unitarget.ssl_ctx,
		)
		return target

	
	def __str__(self):
		t = '==== MSLDAPTarget ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
