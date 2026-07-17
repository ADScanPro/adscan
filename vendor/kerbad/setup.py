from setuptools import setup, find_packages
import re

VERSIONFILE="kerbad/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

setup(
	# Application name:
	name="kerbad",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsec.com",
    
	# Maintainer details:
	maintainer="Baptiste Crépin",
	maintainer_email="baptiste@cravaterouge.com",

	# Packages
	packages=find_packages(exclude=["tests*"]),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/CravateRouge/kerbad",

	zip_safe=True,
	#
	# license="LICENSE.txt",
	description="Kerberos manipulation library in pure Python",

	# long_description=open("README.txt").read(),
	python_requires='>=3.6',
	classifiers=[
		"Programming Language :: Python :: 3.6",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	],
	install_requires=[
		'asn1crypto>=1.5.1',
		# Floor kept at 42.0.8 (NOT the "latest-at-vendor-split" 44.0.2): kerbad only
		# uses stable cryptography APIs (x509/pkcs12/hashes/padding/serialization/dh)
		# present since <=42, and certipy-ad (a NetExec tool-venv dep) pins
		# cryptography~=42.0.8 (<43). A 44.x floor made <43 ∩ >=44.2 empty ->
		# ResolutionImpossible on the NetExec arm64 leg (where our vendor
		# aardwolf->badauth->kerbad chain is the only installable aardwolf, unlike
		# amd64 which silently uses the upstream asyauth-based wheel). Locked by
		# tests/unit/vendor/test_kerbad_cryptography_floor.py.
		'cryptography>=42.0.8',
		'asysocks>=0.2.18',
		'unicrypto>=0.0.12',
		'tqdm',
        'six',
        'dnspython>=2.7.0'
	],

	entry_points={
		'console_scripts': [
			'badccacheedit   = kerbad.examples.ccache_editor:main',
			'badkirbi2ccache = kerbad.examples.kirbi2ccache:main',
			'badccache2kirbi = kerbad.examples.ccache2kirbi:main',
			'badccacheroast  = kerbad.examples.ccacheroast:main',
			'badTGT       = kerbad.examples.getTGT:main',
			'badTGS       = kerbad.examples.getTGS:main',
			'badS4U2proxy = kerbad.examples.getS4U2proxy:main',
			'badS4U2self  = kerbad.examples.getS4U2self:main',
			'badNTPKInit  = kerbad.examples.getNT:main',
			'badcve202233647 = kerbad.examples.CVE_2022_33647:main',
			'badcve202233679 = kerbad.examples.CVE_2022_33679:main',
			'badkerb23hashdecrypt = kerbad.examples.kerb23hashdecrypt:main',
			'badkerberoast   = kerbad.examples.spnroast:main',
            'badasreproast   = kerbad.examples.asreproast:main',
            'badchangepw   = kerbad.examples.changepassword:main',
            'badkeylist = kerbad.examples.keylist:main',
		],
	}
)
