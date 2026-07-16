

class KerberosSPN:
	def __init__(self):
		self.username = None
		self.service  = None #the service we are trying to get a ticket for (eg. cifs/mssql...)
		self.domain   = None #the kerberos realm
		self.port     = None #the port the service is running on
		
	# https://docs.microsoft.com/en-us/windows/desktop/ad/name-formats-for-unique-spns
	#def from_spn(self):

	@staticmethod
	def from_user_email(s):
		#please dont use this anymore
		return KerberosSPN.from_upn(s)

	@staticmethod
	def from_upn(s, default_realm:str = None):
		"""Converts UserPrincipalName to SPN"""
		kt = KerberosSPN()
		if s.find('@') == -1:
			if not default_realm:
				raise Exception('Incorrect format, @ sign is missing!')
			
			kt.domain = default_realm
			kt.username = s
		else:
			kt.username, kt.domain = s.split('@')
		return kt

	@staticmethod
	def from_spn(s, override_realm:str = None, default_realm:str = None):
		"""
		Converts ServicePrincipalName to SPN
		service/host@domain
		or
		host@domain
		"""
		kt = KerberosSPN()
		
		if s.find('/') != -1:
			# A 3-part SPN (serviceclass/host/servicename) is valid and is exactly
			# what msDS-AllowedToDelegateTo stores; an unbounded split('/') then
			# yields >2 elements and the 2-way unpack raises
			# "too many values to unpack". Bound the split so the service class is
			# taken and the remainder (host[/servicename][@domain][:port]) flows on
			# to the '@'/':' parsing below unchanged.
			kt.service, s = s.split('/', 1)
		if s.find('@') != -1:
			kt.username, kt.domain = s.rsplit('@', 1)
		else:
			kt.username = s
			if not override_realm and not default_realm:
				raise Exception('The following SPN is incorrect without additionally setting the realm: %s' % s)
		if override_realm is not None:
			kt.domain = override_realm
		elif not kt.domain:
			kt.domain = default_realm
		if kt.domain.find(':') != -1:
			kt.domain, kt.port = kt.domain.split(':', 1)
		return kt

	def get_principalname(self):
		if self.service:
			if self.port:
				return [self.service, '%s:%s' % (self.username, self.port)]
			return [self.service, self.username]
		return [self.username]

	def get_formatted_pname(self):
		if self.service:
			if self.port:
				return '%s/%s:%s@%s' % (self.service, self.username, self.port, self.domain)
			else:
				return '%s/%s@%s' % (self.service, self.username, self.domain)
		return '%s@%s' % (self.username, self.domain)
	
	def __str__(self):
		return self.get_formatted_pname()
	
	@staticmethod
	def from_file(fpath:str, override_realm:str = None):
		res = []
		with open(fpath, 'r') as f:
			for line in f:
				line = line.strip()
				if line == '':
					continue
				spn = KerberosSPN.from_spn(line, override_realm)
				res.append(spn)
		return res