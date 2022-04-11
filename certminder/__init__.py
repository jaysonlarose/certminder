#!/usr/bin/env python3

"""
Certificate Minder
by Jayson Larose

Library Dependencies:
* ssl (to run get_system_ca_certs())
* cryptography

Binary Dependencies:
* openssl

"""

# On Certificate Verificaton
#
# In the eyes of OpenSSL, a certificate is considered verified if:
# * the time is between the certificate's "not before" and "not after" dates
# * validation of the certificate signature using the issuing certificate's
#     public key succeeds
# * the issuing certificate is verified
#
#
#
# Certificate retrieval precedence
#
# When trying to find an issuing certificate, there are two places that
#   OpenSSL will look: the "system trust store" and the "additional untrusted
#   certificates". The system trust store is For all intents and purposes relevant to us, 
# When looking up an issuing certificate, OpenSSL's preference seems to be
#   to check the system trust store first, falling back to the 
# the chain is followed until one of the following occurs:
# * the certificate issuer is the same as the current certificate
#     (in other words, the top certificate is self-signed)
# * I stopped writing here. Oops.

import argparse, collections, datetime, locale, os, pytz.reference, sys
import cryptography.x509
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.serialization.pkcs7
import cryptography.hazmat.primitives.serialization.pkcs12

from ._version import __version__

# Whitespace definitions{{{
whitespace_unicode = [
	"0020", # SPACE
	"00a0", # NO-BREAK SPACE
	"1680", # OGHAM SPACE MARK
	"180e", # MONGOLIAN VOWEL SEPARATOR
	"2000", # EN QUAD
	"2001", # EM QUAD
	"2002", # EN SPACE
	"2003", # EM SPACE
	"2004", # THREE-PER-EM SPACE
	"2005", # FOUR-PER-EM SPACE
	"2006", # SIX-PER-EM SPACE
	"2007", # FIGURE SPACE
	"2008", # PUNCTUATION SPACE
	"2009", # THIN SPACE
	"2060", # WORD JOINER
	"200a", # HAIR SPACE
	"200b", # ZERO WIDTH SPACE
	"202f", # NARROW NO-BREAK SPACE
	"205f", # MEDIUM MATHEMATICAL SPACE
	"3000", # IDEOGRAPHIC SPACE
	"feff", # ZERO WIDTH NO-BREAK SPACE
	"0008", # BACKSPACE
	"0009", # TAB
	"000a", # LINE FEED
	"000b", # VERTICAL TAB
	"000c", # FORM FEED
	"000d", # CARRIAGE RETURN
	"007f", # DELETE
]
whitespace = ''.join([ chr(int(x, 16)) for x in whitespace_unicode ])
# }}}

# Helper functions; most of which come from
# <https://github.com/jaysonlarose/jlib>, but transplanted here to cut down on
# unnecessary dependencies.
def splitlen_array_remainder(data, length):# {{{
	
	import math
	return [ data[x:x+length] for x in [ x * length for x in range(math.ceil(len(data) / length)) ] ]
# }}}
def timedelta_to_DHMS(dur, weeks=True, precision=0): # {{{
	# doc{{{
	"""
	Given a timedelta object, outputs a string representing said duration.
	For example: 


	>>> print(jlib.timedelta_to_DHMS(datetime.timedelta(days=5, hours=2, minutes=25)))
	5d 02h 25m 00s

	>>> print(jlib.timedelta_to_DHMS(datetime.timedelta(days=5, hours=2, minutes=25, microseconds=123), precision=4))
	5d 02h 25m 00.0001s
	"""
	# }}}
	ts = abs(dur.total_seconds())
	micros = int(ts * int(1e6)) - (int(ts) * int(1e6))
	secs = int(ts)
	if weeks:
		wks=0
		if secs >= 604800:
			wks = secs / 604800
			secs = secs % 604800

	days = 0
	if secs >= 86400:
		days = secs / 86400
		secs = secs % 86400
	hours = 0
	if secs >= 3600:
		hours = secs / 3600
		secs = secs % 3600
	mins = 0
	if secs >= 60:
		mins = secs / 60
		secs = secs % 60

	strout = ''
	if dur.total_seconds() < 0:
		strout += '-'
	if weeks and wks > 0:
		strout += '%dw ' % wks
	if days > 0 or weeks and wks > 0:
		strout += '%dd ' % days
	strout += "%02dh %02dm %02d" % (hours, mins, secs)
	if precision > 0:
		if precision > 6:
			precision = 6
		strout += '.' + str(micros).rjust(6, '0')[:precision]
	strout += 's'
	return strout
# }}}
def DHMS_to_timedelta(dhms):# {{{
	# Lifted and adapted from https://gist.github.com/Ayehavgunne/ac6108fa8740c325892b
	import datetime
	dhms = dhms.lower()
	prev_num = []
	timedelta_kwargs = {}
	for character in dhms:
		if character.isalpha():
			if prev_num:
				num_str = ''.join(prev_num)
				if '.' in num_str:
					num = float(num_str)
				else:
					num = int(num_str)
				if character == 'w':
					key = 'weeks'
				elif character == 'd':
					key = 'days'
				elif character == 'h':
					key = 'hours'
				elif character == 'm':
					key = 'minutes'
				elif character == 's':
					key = 'seconds'
				else:
					raise ValueError("Unknown DHMS predicate: {}".format(character))
				timedelta_kwargs[key] = num
				prev_num = []
		elif character.isnumeric() or character == '.':
			prev_num.append(character)
	if prev_num:
		raise ValueError("Dangling quantity: {}".format(''.join(prev_num)))
	return datetime.timedelta(**timedelta_kwargs)
# }}}
def lstripn(text, count, chars=None):# {{{
	"""
	Strip up to `count` leading characters of whitespace from a string.

	As with the builtin `str.lstrip()` method, if `chars` is specified,
	those characters will be stripped instead.
	"""
	if chars is None:
		import string
		chars = whitespace
	for i in range(count):
		if len(text) == 0:
			break
		if text[0] in chars:
			text = text[1:]
		else:
			break
	return text
# }}}
def colorize(hexcolor, text, force=False):# {{{
	"""
	Very basic function for colorizing output.

	It only knows how to output 24-bit terminal colors. If you want something more
	sophisticated, check out the `fabulous` package.
	"""
	hexcolor = hexcolor.lstrip("#")
	if len(hexcolor) == 3:
		rgb = [ int(x, 16) * 17 for x in hexcolor ]
	elif len(hexcolor) == 6:
		rgb = [ int(x, 16) for x in splitlen_array_remainder(hexcolor, 2) ]
	rgbstr = ';'.join([ str(x) for x in rgb ])
	if sys.stdout.isatty() or force:
		return f"\x1b[38;2;{rgbstr}m{text}\x1b[39m"
	else:
		return text
# }}}



# PEM parsers
class PasswordRequiredError(TypeError):# {{{
	pass
# }}}
def parse_pemheader(bytedata):# {{{
	"""
	Looks through a bytes() blob, which is intented to be a single line
	of data (cr/lf characters at the end are ignored).

	If it looks like the start or end of a PEM block, as in it looks
	like b"-----BEGIN HIMOM-----" or b"-----END HIMOM-----", it will
	return a tuple containing ('BEGIN', 'HIMOM') or ('END', 'HIMOM'),
	respectively.

	If it doesn't look like the start or end of a PEM block, returns
	None.
	"""
	sdata = bytedata.strip(whitespace.encode())
	if sdata.startswith(b"-----BEGIN ") and sdata.endswith(b"-----"):
		return ("BEGIN", sdata[len(b"-----BEGIN "):-len(b"-----")].decode())
	elif sdata.startswith(b"-----END ") and sdata.endswith(b"-----"):
		return ("END", sdata[len(b"-----END "):-len(b"-----")].decode())
	return None
# }}}
def extract_pemblocks(bytedata):# {{{
	"""
	Looks through a blob of bytes() data and extracts the individual
	PEM objects contained therein.

	It will return a list of bytes() objects, each consisting of a
	b'-----BEGIN ' block and b'-----END ' block, as well as everything
	between the two.

	This function is "dumb" in that it's just looking for lines that
	start with "-----BEGIN " and "-----END ".
	"""
	ret = []
	processing = None
	buf = []
	lines = bytedata.splitlines(keepends=True)
	for line in lines:
		if processing is None:
			parsed = parse_pemheader(line)
			if parsed is not None and parsed[0] == 'BEGIN':
				processing = parsed[1]
				buf = [line.strip(whitespace.encode())]
			# Falling out into the ignore hole
		else:
			# We're processing, this data gets stuck in the buffer.
			buf.append(line.strip(whitespace.encode()))
			parsed = parse_pemheader(line)
			if parsed is not None and parsed[0] == 'END':
				if parsed[1] == processing:
					# Additionally, if this is an end block and it lines up with
					# what we're processing, finish processing and add the buffer
					# to ret.
					ret.append(b"\n".join(buf) + b"\n")
					buf = []
					processing = None
	# Unfinished blocks? Don't care about 'em. Garbage in, garbage out.
	return ret
# }}}
def parse_pemblock(bytedata, password=None, extradata=False):# {{{
	"""
	Given a bytes() blob that represents a PEM object (ie, a chunk of
	ASCII text that starts with "-----BEGIN xxx-----" and ends with
	"-----END xxx-----", attempts to parse it into a usable object.

	Returns a 2-tuple, the first element being the text that the
	block BEGINs with, the second being the parsed object (or None
	if we don't know what to do with it).

	Things we're aware of the existence of:
	* CERTIFICATE
	* CERTIFICATE REQUEST
	* PRIVATE KEY
	* RSA PRIVATE KEY
	* RSA PUBLIC KEY
	* PGP PUBLIC KEY BLOCK

	Things we currently work on:
	* CERIFICATE
	* PRIVATE KEY
	"""
	blocktype = parse_pemheader(bytedata.splitlines()[0])[1]
	parsed = None
	if blocktype == 'CERTIFICATE':
		parsed = cryptography.x509.load_pem_x509_certificate(bytedata, cryptography.hazmat.backends.default_backend())
	elif blocktype == 'PRIVATE KEY':
		try:
			parsed = cryptography.hazmat.primitives.serialization.load_pem_private_key(bytedata, password=password)
		except TypeError as e:
			if e.args[0] == 'Password was not given but private key is encrypted':
				raise PasswordRequiredError(*e.args)
	elif blocktype == 'RSA PRIVATE KEY':
		try:
			parsed = cryptography.hazmat.primitives.serialization.load_pem_private_key(bytedata, password=password)
		except TypeError as e:
			if e.args[0] == 'Password was not given but private key is encrypted':
				raise PasswordRequiredError(*e.args)
	elif blocktype == 'CERTIFICATE REQUEST':
		parsed = cryptography.x509.load_pem_x509_csr(bytedata)
	elif blocktype in ['PUBLIC KEY', 'RSA PUBLIC KEY']:
		parsed = cryptography.hazmat.primitives.serialization.load_pem_public_key(bytedata)


	return (blocktype, parsed)
# }}}

def get_system_ca_certs():# {{{
	"""
	This function attempts to replicate the sort of stuff that
	OpenSSL does at startup when it reads the system CA store.

	It calls ssl.get_default_verify_paths() to query the system
	for where it gets data from, and then acts on that.

	"""
	import ssl
	p = ssl.get_default_verify_paths()
	cafile = None
	capath = None
	if p.openssl_cafile_env is not None:
		k = p.openssl_cafile_env
		if k in os.environ:
			cafile = os.environ[k]
	if cafile is None:
		cafile = p.cafile
	
	if p.openssl_capath_env is not None:
		k = p.openssl_capath_env
		if k in os.environ:
			capath = os.environ[k]
	if capath is None:
		capath = p.capath

	ret = {}
	if cafile is not None and os.path.exists(cafile):
		ret.update(import_cacert_file(cafile))
	elif capath is not None and os.path.exists(capath):
		ret.update(import_cacert_dir(capath))
	return ret
# }}}
def get_certificate_chain_from_tls(host, port, extradata=False):# {{{
	"""
	Given a hostname and a port, uses `openssl s_client` to attempt to retrieve the
	entire certificate chain it presents via TLS.

	Returns a list of cryptography X509 objects.
	"""
	import subprocess
	procargs = ['openssl', 's_client', '-host', host, '-port', f"{port}", '-showcerts']

	proc = subprocess.run(procargs, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	if proc.returncode != 0:
		raise subprocess.CalledProcessError(proc.returncode, procargs)

	ret = [ parse_pemblock(x) for x in extract_pemblocks(proc.stdout) ]
	ret = [ x for x in ret if x[1] is not None ]
	if not extradata:
		return [ x[1] for x in ret ]
	return ret
# }}}
def get_certificates_from_pem(bytedata, extradata=False, password=None):# {{{
	"""
	Extracts certificates and keys from a bytes() object representing
	PEM data.
	"""
	pem_frags = extract_pemblocks(bytedata)
	ret = [ parse_pemblock(x, password=password) for x in pem_frags ]
	ret = [ x for x in ret if x[1] is not None ]
	if not extradata:
		return [ x[1] for x in ret ]
	return ret
# }}}
# PKCS#12
# * can contain multiple certificates
# * can contain private keys
def get_certificates_from_pkcs12(pkcs12_data, password=None):# {{{
	"""
	Given a bytes() blob representing a PKCS#12 file, returns a list containing:
	* The primary certificate contained in the data, if present.
	* The private key for this certificate, if present.
	* Any additional certificates, if they exist.

	You can pull just certificates out of this mess by doing something like:

	[ x for x in mess if isinstance(x, cryptography.x509.Certificate) ]
	"""
	ret = []
	pk = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(pkcs12_data, password=password)
	if pk[1] is not None:
		ret.append(pk[1])
	if pk[0] is not None:
		ret.append(pk[0])
	if pk[2] is not None:
		ret.extend(pk[2])
	return ret
# }}}

# PKCS#7
# * can contain multiple certificates
# * can contain a revocation list
# * cannot contain private keys
def get_certificates_from_pkcs7(pkcs7_data, extradata=False):# {{{
	"""
	Given PKCS#7 data in either PEM (.p7b) or DER (.p7s) format, returns a list of
	cryptography.x509.Certificate objects contained therein.

	If parameter "extradata" is true, you'll get a tuple, the first element of which
	indicating wheter PEM or DER data was parsed, the second being the cert list.
	"""
	try:
		certs = cryptography.hazmat.primitives.serialization.pkcs7.load_pem_pkcs7_certificates(pkcs7_data)
		encoding = cryptography.hazmat.primitives.serialization.Encoding.PEM
	except ValueError:
		certs = cryptography.hazmat.primitives.serialization.pkcs7.load_der_pkcs7_certificates(pkcs7_data)
		encoding = cryptography.hazmat.primitives.serialization.Encoding.DER
	
	if extradata:
		return (encoding, certs)
	else:
		return certs
# }}}

# OpenSSH keys
# cryptography.hazmat.primitives.serialization.ssh.load_ssh_public_key(bytes)
# cryptography.hazmat.primitives.serialization.load_ssh_public_key(open(bytes))
# pubkey_obj.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.OpenSSH, format=cryptography.hazmat.primitives.serialization.PublicFormat.OpenSSH)
# pubkey_obj.__class__.__module__.split('.')[-1]

# cryptography.hazmat.primitives.serialization.load_ssh_public_key(open(bytes))
def try_everything(bytedata, password=None):# {{{
	"""
	Makes best effort go get stuff out of things.
	"""
	# Try loading a DER certificate
	try:
		cert = cryptography.x509.load_der_x509_certificate(bytedata)
		#print("der cert")
		return [cert]
	except ValueError:
		pass
	# Try loading a DER private key
	try:
		key = cryptography.hazmat.primitives.serialization.load_der_private_key(bytedata, password=password)
		#print("der key")
		return [key]
	except ValueError:
		pass
	# Try loading PKCS#7
	try:
		certs = get_certificates_from_pkcs7(bytedata)
		#print("pkcs7")
		return certs
	except ValueError:
		pass
	# Try loading PKCS#12
	try:
		certs = get_certificates_from_pkcs12(bytedata, password=password)
		#print("pkcs12")
		return certs
	except ValueError:
		pass
	# Try loading DER hexdumps
	certs = get_certificates_from_derhex(bytedata)
	if len(certs) > 0:
		return certs
	# Try PEM stuff.
	certs = get_certificates_from_pem(bytedata, password=password)
	return certs
# }}}
class TemporalError(Exception):# {{{
	pass
# }}}
class PrematureBirthError(TemporalError):# {{{
	pass
# }}}
class ExpiredError(TemporalError):# {{{
	pass
# }}}
def verify_cert_freshness(cert, timestamp=datetime.datetime.utcnow().replace(tzinfo=pytz.reference.UTC)):# {{{
	"""
	Verifies that the suppliced cryptography.x509 certificate is neither born too early nor too late.

	Returns None if it's OK, raises PrematureBirthError or ExpiredError if it's not.
	"""
	start = cert.not_valid_before.replace(tzinfo=pytz.reference.UTC)
	end   = cert.not_valid_after.replace(tzinfo=pytz.reference.UTC)
	if timestamp < start:
		raise PrematureBirthError
	if timestamp > end:
		raise ExpiredError
# }}}
def verify_cert_signature(cert, issuer_cert):# {{{
	"""
	Parameters:
	cert - cryptography.x509 cert to try and verify
	issuer_cert - cryptography.x509 cert of the issuer that allegedly signed the first cert

	cert's signature is verified using issuer_cert's public key.
	"""
	try:
		issuer_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(), cert.signature_hash_algorithm)
		return True
	except Exception:
		return False
# }}}
def import_cacert_file(path):# {{{
	"""
	Loads certificates from a file.

	Returns it as something you can update() into a dict, suitable for building a CA registry.
	"""
	ret = {}
	certs = try_everything(open(path, "rb").read())
	for cert in certs:
		if not isinstance(cert, cryptography.x509.Certificate):
			continue
		try:
			verify_cert_freshness(cert)
		except TemporalError:
			continue
		ret[cert.subject] = {'certificate': cert, 'origin': path}
	return ret
# }}}
def import_cacert_dir(path, recursive=False, max_filesize=1024*1024*1024):# {{{
	"""
	Loads certificates from a directory.

	Returns all certificates encountered as something you can update() into a dict, suitable for building a CA registry.

	If multiple certificates exist for a given subject, only one is returned, with the certificates that have the latest expiration date taking priority.

	Parameters:
	recursive — if set to True, traverse into subdirectories.
	max_filesize — files larger than this size will be omitted from processing.
	    This is needed because we lack a reliable way of identifying certain binary
		file types (like PKCS#12) aside from trying to parse them.
	"""
	if not recursive:
		flist = [ x for x in [ os.path.join(path, x) for x in os.listdir(path) ] if os.path.isfile(x) ]
	else:
		flist = []
		for root, dirs, files in os.walk(path):
			#print([ os.path.join(root, x) for x in files ])
			flist.extend([ os.path.join(root, x) for x in files ])
	flist = [ x for x in flist if os.stat(x).st_size < max_filesize ]
	ret = {}
	for path in flist:
		certs = try_everything(open(path, "rb").read())
		for cert in certs:
			if not isinstance(cert, cryptography.x509.Certificate):
				continue
			try:
				verify_cert_freshness(cert)
			except TemporalError:
				continue
			if cert.subject not in ret:
				ret[cert.subject] = {'certificate': cert, 'origin': path}
			else:
				if cert.not_valid_after > ret[cert.subject]['certificate'].not_valid_after:
					ret[cert.subject] = {'certificate': cert, 'origin': path}
	return ret
# }}}
# Cert fingerprinting
# cert.fingerprint(cryptography.hazmat.primitives.hashes.SHA512())
# cert.fingerprint(cryptography.hazmat.primitives.hashes.MD5())

# Data export functions
def certificate_to_pem(cryptography_x509_certificate):# {{{
	import cryptography.hazmat.primitives.serialization
	pem_bytes = cryptography_x509_certificate.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM)
	return pem_bytes
# }}}
def certificate_to_der(cryptography_x509_certificate):# {{{
	import cryptography.hazmat.primitives.serialization
	der_bytes = cryptography_x509_certificate.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.DER)
	return der_bytes
# }}}

def render_certificate(cert):# {{{
	"""
	Converts the supplied cryptography.x509 certificate to PEM data,
	then calls the `openssl` binary to parse it into something informative.
	"""
	import subprocess
	cert_text = certificate_to_pem(cert)
	procargs = ['openssl', 'x509', '-in', '-', '-text', '-noout']
	proc = subprocess.Popen(procargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	out, err = proc.communicate(cert_text)
	return out.decode()
# }}}
def parse_cisco_derhex_line(bytedata):# {{{
	"""
	Returns appropriate bytes() data if the supplied line (binary) looks like a
	Cisco DER hex dump.

	Otherwise, it returns None.
	"""
	import binascii
	frags = bytedata.strip().split(b" ")
	if max([ len(x) for x in frags ]) > 8:
		return None
	if len(frags) > 1:
		if [ len(x) for x in frags[:-1] ] != [ 8 for x in range(len(frags) - 1) ]:
			return None
	try:
		return b''.join([ binascii.unhexlify(x) for x in frags ])
	except binascii.Error:
		return None
# }}}
def get_certificates_from_derhex(bytedata):# {{{
	"""
	Given a blob of bytes() data, attempts to parse out any Cisco DER hexdumps
	contained therein.
	Anything that doesn't look like a Cisco DER hexdump gets ignored.
	Anything that doesn't parse out to a valid certificate gets ignored.
	Each DER hex dump must have at least one line of non-hexdump text separating
	it from its siblings, which shouldn't be a problem if you're parsing a
	running config dump.

	Returns a list of cryptography.x509.Certificate objects.
	"""
	ret = []
	lines = bytedata.splitlines(keepends=True)
	processing = None
	buf = b''
	for line in lines:
		data = parse_cisco_derhex_line(line)
		if processing:
			if data is not None:
				buf += data
			else:
				processing = False
				try:
					ret.append(cryptography.x509.load_der_x509_certificate(buf))
				except ValueError:
					pass
				buf = b''
		else:
			if data is not None:
				buf = data
				processing = True
	
	return ret
# }}}

# catcert rendering classes
def get_cryptothing(obj):# {{{
	if isinstance(obj, cryptography.x509.Certificate):
		return CertificateCryptoThing(obj)
	elif isinstance(obj, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
		return RSAPrivateCryptoThing(obj)
	elif isinstance(obj, cryptography.hazmat.backends.openssl.x509._CertificateSigningRequest):
		return CSRCryptoThing(obj)
	elif isinstance(obj, cryptography.hazmat.backends.openssl.rsa._RSAPublicKey):
		return RSAPublicCryptoThing(obj)
	else:
		return UnknownCryptoThing(obj)
# }}}
class CryptoThing:# {{{
	def __init__(self, obj):
		self.obj = obj
	def indent(self, size=4):
		return("\n".join([ (" " * size) + x for x in self.render().splitlines() ]) + "\n")
# }}}
class UnknownCryptoThing(CryptoThing):# {{{
	type = "Unknown"
	color = "#888"
	@property
	def description(self):
		return str(type(self.obj))
	def render(self):
		return "I don't know how to display this!"
# }}}
class CertificateCryptoThing(CryptoThing):# {{{
	type = "Certificate"
	color = "#aaf"
	@property
	def description(self):
		return self.obj.subject.rfc4514_string()
	def render(self):
		return render_certificate(self.obj)
# }}}
class RSAPrivateCryptoThing(CryptoThing):# {{{
	type = "RSA Private Key"
	color = "#ff0"
	@property
	def description(self):
		return f"{self.obj.key_size} bit"
	def render(self):
		import subprocess
		pem_text = self.obj.private_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM, format=cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8, encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption())
		procargs = ['openssl', 'rsa', '-in', '-', '-text', '-noout']
		proc = subprocess.Popen(procargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		out, err = proc.communicate(pem_text)
		return out.decode()
# }}}
class RSAPublicCryptoThing(CryptoThing):# {{{
	type = "RSA Public Key"
	color = "#f0f"
	@property
	def description(self):
		return f"{self.obj.key_size} bit"
	def render(self):
		import subprocess
		pem_text = self.obj.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM, format=cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo)
		procargs = ['openssl', 'rsa', '-in', '-', '-text', '-noout', '-pubin']
		proc = subprocess.Popen(procargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		out, err = proc.communicate(pem_text)
		return out.decode()
# }}}
class CSRCryptoThing(CryptoThing):# {{{
	type = "Certificate Signing Request"
	color = "#aa0"
	@property
	def description(self):
		return self.obj.subject.rfc4514_string()
	def render(self):
		import subprocess
		pem_text = self.obj.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM)
		procargs = ['openssl', 'req', '-in', '-', '-text', '-noout']
		proc = subprocess.Popen(procargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		out, err = proc.communicate(pem_text)
		return out.decode()
# }}}

# Everything above here is library stuff.
# This is where the primary logic resides.
class cli_certminder:# {{{
	"""
	Reads a YAML configuration file that describes a list of certificates to
	check for freshness.
	
	Example:

	- include: /etc/certminder.d
	- certificate: /etc/ssl/certs/mycert.pem
	  compare:     myhostname.com:443
	  privkey:     /etc/ssl/private/mycert.key
	  threshold: 2w
	  fetchcmds:
	    - salt-call tls.renew
	  reloadcmds:
	    - systemctl restart nginx
	- certificate: /etc/ssl/certs/myothercert.pem
	  threshold: 2w
	  fetchcmds: salt-call tls.renew
	  reloadcmds: systemctl restart dovecot
	  
	Top-level directives:
	
	include: 
		Specifies one (or more) directories to check for additional configuration files.
		Todo: allow specifying a glob in addition to a directory name
		Todo: add "recursive" modifier?
		Note: `include` directives will only be honored for a directly-specified
		  configuration file. `include` directives in included configurations will be ignored.

	certificate:
		Specifies the path to a certificate file to check.
		If the certificate is expired, or is less than the `threshold` duration away from
		  expiration, the commands in the `fetchcmds` modifier will be run. If they succeed,
		  then the commands in the `reloadcmds` modifier will be run.
		Modifiers:

		fetch_if_missing: adding this directive and setting it `true` will cause a missing
		  certificate or key file to be treated as "fetch needed" instead of an error.
		compare: the certificate found at this path (or this host:port combination) will
		  be compared against this certificate. If there's a mismatch, commands in the
		  `reloadcmds` modifier will be run.
		privkey: the private key found at this path will be checked to see if it works for
		  this certificate. If it doesn't, `fetchcmds` will be run, followed by `reloadcmds`
		threshold: if the certificate is set to expire any time before this threshold,
		  `fetchcmds` will be run, followed by `reloadcmds`. Specified in a format like:
		  `12w 10d 4h 2m 1s` translating to "12 weeks, 10 days, 4 hours, 2 minutes, 1 second".
		fetchcmds: command (or list of commands) to run to refresh the certificate.
		  If this command succeeds, the commands in the `reloadcmds` directive are usually
		  run afterwards.
		  If a list of commands is specified, they will be executed in order, as long as the
		  last run command has an exit status of 0.  Any non-zero exit code will be considered
		  failure, and further commands will not be run.
		reloadcmds: command (or list of commands) to run to reload service(s) dependent on this
		  certificate. Unlike `fetchcmds`, all commands in this list will be run, regardless of
		  exit status of the command before it.
	
	About running commands:
	
	Standard python string formatting is used for replacement. Currently the only
	tokens used for replacement are:

	    path - the path to the certificate being tested
		subject - the RFC4514 subject name for the certificate. This can be
		    used to differentiate between certificates if a path or network
			location contains a certificate chain.

	"""
	@classmethod
	def parser_setup(cls, parser):
		parser.set_defaults(cert_files=[], cert_dirs=[])
		parser.add_argument("config_file")
		parser.add_argument("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Omit printing out progress chatter")
	@classmethod
	def run(cls, args):
		config_fn = args.config_file
		import yaml, shlex, subprocess
		if not args.quiet:
			print(f"Reading {config_fn}")

		# Read in the yaml specified on the commmand-line, separate it into
		# a list of include directives and certificate directives.
		conf = yaml.load(open(config_fn, "r").read(), Loader=yaml.Loader)
		include_directives = [ x for x in conf if 'include' in x ]
		cert_directives    = [ x for x in conf if 'certificate' in x ]


		# Parse `include` directives into a list.
		includes = []
		if len(include_directives) > 0:
			for directive in include_directives:
				if isinstance(directive['include'], str):
					includes.append(directive['include'])
				elif isinstance(directive['include'], list):
					includes.extend(directive['include'])

		# Resolve the list of includes into a list of individual files
		# to be included. (If an include points to a directory, treat
		# that as if it means "all files inside this directory")
		include_files = []
		for include_dir in includes:
			if os.path.isfile(include_dir):
				include_files.append(include_dir)
			else:
				for fn in os.listdir(include_dir):
					path = os.path.join(include_dir, fn)
					if not os.path.isfile(path):
						continue
					include_files.append(path)

		# Load each included file and add its `certificate` directives to the
		# cert_directives list.
		for path in include_files:
			conf = yaml.load(open(path, "r").read(), Loader=yaml.Loader)
			cert_directives.extend([ x for x in conf if 'certificate' in x ])

		# We're starting to work on certificates, get our baseline time for
		# doing expiration checks.
		nao = datetime.datetime.utcnow().replace(tzinfo=pytz.reference.UTC)

		for cert_directive in cert_directives:
			namespace = {}
			perform_fetch = False
			perform_reload = False
			certpath = cert_directive['certificate']
			namespace['certpath'] = certpath
			if not os.path.exists(certpath):
				print(f"Certificate {certpath} does not exist!", file=sys.stderr)
				if 'fetch_if_missing' in cert_directive and cert_directive['fetch_if_missing']:
					perform_fetch = True
				else:
					continue
			if not perform_fetch:
				certs = try_everything(open(certpath, "rb").read())
				certsonly = [ x for x in certs if isinstance(x, cryptography.x509.Certificate) ]
				if len(certsonly) < 1:
					print(f"No certificates found in {certpath}!", file=sys.stderr)
					if 'fetch_if_missing' in cert_directive and cert_directive['fetch_if_missing']:
						perform_fetch = True
					else:
						continue
			if not perform_fetch:
				if 'threshold' in cert_directive:
					threshold = DHMS_to_timedelta(cert_directive['threshold'])
				for certno, cert in enumerate(certsonly):
					if certno == 0:
						namespace['subject'] = cert.subject.rfc4514_string()
					if not args.quiet:
						print(f"Checking {certpath} certificate {cert.subject.rfc4514_string()}")
					try:
						verify_cert_freshness(cert, nao)
						end = cert.not_valid_after.replace(tzinfo=pytz.reference.UTC)
						if not args.quiet:
							print(f"  expires in {timedelta_to_DHMS(end - nao)}")
						if end - nao < threshold:
							perform_fetch = True
					except PrematureBirthError:
						perform_fetch = True
					except ExpiredError:
						perform_fetch = True

			class FallOut(Exception):
				pass

			if not perform_fetch and 'compare' in cert_directive:
				if not args.quiet:
					print(f"  `compare` directive found")
				try:
					frags = cert_directive['compare'].split(':', 1)
					if len(frags) != 2:
						print(f"Invalid `compare` modifier for {certpath}: {cert_directive['compare']}!", file=sys.stderr)
						raise FallOut
					try:
						portno = int(frags[1])
					except ValueError:
						print(f"Invalid port number for `compare` modifier for {certpath}: {portno}!", file=sys.stderr)
						raise FallOut
					try:
						comparecerts = get_certificate_chain_from_tls(frags[0], portno, extradata=False)
					except subprocess.CalledProcessError:
						print(f"Couldn't get TLS certificates for {certpath} from {cert_directive['compare']}!", file=sys.stderr)
						raise FallOut
					if comparecerts[0] != certsonly[0]:
						if not args.quiet:
							print(f"  compare FAILED against {cert_directive['compare']}, setting perform_reload")
							perform_reload = True
					elif not args.quiet:
						print(f"  compare OK against {cert_directive['compare']}")
				except FallOut:
					print("  Fell out of compare!")
					pass
				if threshold_exceeded:
					perform_fetch = True

			if not perform_fetch and 'privkey' in cert_directive:
				if not args.quiet:
					print(f"  `privkey` directive found")
				keypath = cert_directive['privkey']
				if not os.path.exists(keypath):
					print(f"Private key {keypath} does not exist!", file=sys.stderr)
					if 'fetch_if_missing' in cert_directive and cert_directive['fetch_if_missing']:
						perform_fetch = True
					else:
						continue
				if not perform_fetch:
					things = try_everything(open(keypath, "rb").read())
					keysonly = [ x for x in things if isinstance(x, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey) ]
					if len(keysonly) < 1:
						print(f"No private keys found in {certpath}!", file=sys.stderr)
						if 'fetch_if_missing' in cert_directive and cert_directive['fetch_if_missing']:
							perform_fetch = True
						else:
							continue
					key = keysonly[0]
					if certsonly[0].public_key().public_numbers().n != key.public_key().public_numbers().n:
						print(f"Private key in {keypath} does not belong to certificate {certpath}!", file=sys.stderr)
						perform_fetch = True
					else:
						print(f"  Private key modulo in {keypath} matches public key.")

			if perform_fetch:
				fetch_commands = []
				if not args.quiet:
					print("  fetch desired")
				if 'fetchcmds' in cert_directive:
					if isinstance(cert_directive['fetchcmds'], str):
						fetch_commands.append(cert_directive['fetchcmds'])
					elif isinstance(cert_directive['fetchcmds'], list):
						fetch_commands.extend(cert_directive['fetchcmds'])
				for command in fetch_commands:
					procargs = [ x.format(**namespace) for x in shlex.split(command) ]
					if not args.quiet:
						print(f"  running {procargs}")
					proc = subprocess.run(procargs, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
					if proc.returncode != 0:
						print(f"Process {procargs} returned error code {proc.returncode}!", file=sys.stderr)
						print(f"Process stdout:", file=sys.stderr)
						print(proc.stdout.decode(), file=sys.stderr)
						print(f"Process stderr:", file=sys.stderr)
						print(proc.stderr.decode(), file=sys.stderr)
						print(f"(setting perform_reload to False)", file=sys.stderr)
						perform_reload = False
						break
				perform_reload = True

			if perform_reload:
				reload_commands = []
				if not args.quiet:
					print(f"  reload desired")
				if 'reloadcmds' in cert_directive:
					if isinstance(cert_directive['reloadcmds'], str):
						reload_commands.append(cert_directive['reloadcmds'])
					elif isinstance(cert_directive['reloadcmds'], list):
						reload_commands.extend(cert_directive['reloadcmds'])
				for command in reload_commands:
					procargs = [ x.format(**namespace) for x in shlex.split(command) ]
					if not args.quiet:
						print(f"  running {procargs}")
					proc = subprocess.run(procargs, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
					if proc.returncode != 0:
						print(f"Process {procargs} returned error code {proc.returncode}!", file=sys.stderr)
						print(f"Process stdout:", file=sys.stderr)
						print(proc.stdout.decode(), file=sys.stderr)
						print(f"Process stderr:", file=sys.stderr)
						print(proc.stderr.decode(), file=sys.stderr)

						


		
		#nao = datetime.datetime.utcnow().replace(tzinfo=pytz.reference.UTC)
		#for section in conf.sections():
		#	certpath = conf[section]['certificate']
		#	if not args.quiet:
		#		print(f"Inspecting {certpath}")
		#	frags = certpath.split(":", 1)
		#	if len(frags) > 1:
		#		host = frags[0]
		#		port = int(frags[1])
		#		certs = get_certificate_chain_from_tls(host, port, extradata=False)
		#	else:
		#		if not os.path.exists(certpath):
		#			print(f"Certificate in section {section} ({certpath}) does not exist!")
		#			sys.exit(1)
		#		certs = try_everything(open(certpath, "rb").read())
		#	certsonly = [ x for x in certs if isinstance(x, cryptography.x509.Certificate) ]
		#	if len(certsonly) < 1:
		#		print(f"No certificates found for section {section} in {certpath}!")
		#		sys.exit(1)
		#	threshold = DHMS_to_timedelta(conf[section]['threshold'])
		#	threshold_exceeded = False
		#	namespace = {}
		#	namespace['path'] = certpath
		#	for cert in certsonly:
		#		if not args.quiet:
		#			print(f"Checking certificate {cert.subject.rfc4514_string()}")
		#		try:
		#			verify_cert_freshness(cert, nao)
		#			end = cert.not_valid_after.replace(tzinfo=pytz.reference.UTC)
		#			if end - nao < threshold:
		#				threshold_exceeded = True
		#		except PrematureBirthError:
		#			threshold_exceeded = True
		#		except ExpiredError:
		#			threshold_exceeded = True

		#		if threshold_exceeded:
		#			namespace['subject'] = cert.subject.rfc4514_string()
		#			break

		#	if threshold_exceeded:
		#		if not args.quiet:
		#			print("Threshold exceeded!")
		#		procargs = [ x.format(**namespace) for x in shlex.split(conf[section]['run']) ]
		#		if not args.quiet:
		#			print(f"Running {procargs}")
		#		subprocess.run(procargs, stdin=subprocess.DEVNULL)
# }}}
class cli_catcert:# {{{
	"""
	Reads a certificate off the filesystem or from a network address, and returns information
	about it.

	--verify can be used to perform additional verification steps to ensure that the
	    certificate(s) check out. Note that oftentimes the last certificate or two in a
		chain may fail due to... reasons.  The easiest way to explain this is that
		verification is considered to be a success if the signing tree can be traced back
		to the system CA store.  The last certificate in a chain is often self-signed,
		and thus even though it may itself exist in the store, it's not traced BACK to the
		store. Don't worry about this too much.

	--no-system and a combination of --add-file and --add-dir directives can be used to
	    verify against a custom CA store, if you don't want to use the system CA store.

	--quiet omits the certificate details dump, which is useful when you're more interested in
	    certificate validity than contents.

	--extra will dump non-certificate items as well.
	"""
	@classmethod
	def parser_setup(cls, parser):
		parser.set_defaults(cert_files=[], cert_dirs=[], dump_mode="certs")
		parser.add_argument("file_or_host")
		parser.add_argument("-v", "--verify", action="store_true", dest="verify", default=False, help="Attempt to verify certificate chain of authority")
		parser.add_argument("-n", "--no-system", action="store_false", dest="import_system_certs", default=True, help="When verifying, do not import system certificates")
		parser.add_argument("-f", "--add-file", action="append", dest="cert_files", help="Add file to CA registry")
		parser.add_argument("-d", "--add-dir", action="append", dest="cert_dirs", help="Add directory to CA registry")
		group = parser.add_mutually_exclusive_group()
		group.add_argument("-q", "--quiet", action="store_const", const="none", dest="dump_mode", help="Omit certificate dump")
		group.add_argument("-x", "--extra", action="store_const", const="extra", dest="dump_mode", help="Dump non-certificate items as well")
		parser.add_argument("--force-color", action="store_true", dest="force_color", default=False, help="Force color output even if STDOUT is not a TTY")
		parser.add_argument("--absolute-expiry", action="store_true", dest="absolute_expiry", default=False, help="Print absolute certificate expiration dates instead of relative ones.")
	@classmethod
	def run(cls, args):
		c = args.file_or_host
		frags = c.split(":", 1)
		if len(frags) > 1:
			host = frags[0]
			port = int(frags[1])
			certs = get_certificate_chain_from_tls(host, port, extradata=False)
		elif c == '-':
			certs = try_everything(sys.stdin.read().encode())
		else:
			if not os.path.exists(c):
				print(f"{c} does not exist!", file=sys.stderr)
				sys.exit(1)
			try:
				certs = try_everything(open(c, "rb").read())
			except PasswordRequiredError:
				failed = True
				if sys.stdin.isatty():
					import getpass
					password = getpass.getpass("Private key password: ")
					try:
						certs = try_everything(open(c, "rb").read(), password=password.encode())
						failed = False
					except ValueError:
						print("Bad password!", file=sys.stderr)
						sys.exit(1)
					except PasswordRequiredError:
						pass
				if failed:
					print(f"Password required for private key!", file=sys.stderr)
					sys.exit(1)
		certsonly = [ x for x in certs if isinstance(x, cryptography.x509.Certificate) ]
		otheritems = [ x for x in certs if not isinstance(x, cryptography.x509.Certificate) ]
		print(f"Found {len(certsonly):n} cert(s):")
		if args.verify:
			ca_store = {}
			if args.import_system_certs:
				ca_store.update(get_system_ca_certs())
			for path in args.cert_files:
				ca_store.update(import_cacert_file(path))
			for path in args.cert_dirs:
				ca_store.update(import_cacert_dir(path))

		nao = datetime.datetime.utcnow().replace(tzinfo=pytz.reference.UTC)
		for cert in certsonly:
			valid = True
			reasons = []
			start = cert.not_valid_before.replace(tzinfo=pytz.reference.UTC)
			end = cert.not_valid_after.replace(tzinfo=pytz.reference.UTC)
			try:
				verify_cert_freshness(cert, nao)
				if args.absolute_expiry:
					expiry_text = colorize("#888", "Expires {}".format(end.strftime("%F %T %Z")), force=args.force_color)
				else:
					expiry_text = colorize("#888", "Expires in {}".format(timedelta_to_DHMS(end - nao)), force=args.force_color)
			except PrematureBirthError:
				valid = False
				reasons.append("Not yet valid")
				if args.absolute_expiry:
					expiry_text = colorize("#f00", "Not valid until {}".format(start.strftime("%F %T %Z")), force=args.force_color)
				else:
					expiry_text = colorize("#f00", "Premature birth", force=args.force_color)
			except ExpiredError:
				valid = False
				reasons.append("Certificate expired")
				if args.absolute_expiry:
					expiry_text = colorize("#f00", "Expired at {}".format(end.strftime("%F %T %Z")), force=args.force_color)
				else:
					expiry_text = colorize("#f00", "Expired!", force=args.force_color)
			print("  * {} ({})".format(cert.subject.rfc4514_string(), expiry_text))
			if args.verify:
				vcert = cert
				auth  = False
				expiry = False
				while vcert is not None:
					# tcert - "this cert".  Copy of current certificate, because we
					# re-set vcert before printing time.
					info = []
					tcert = vcert
					if vcert.issuer == vcert.subject:
						vcert = None
					elif vcert.issuer in ca_store:
						vcert = ca_store[vcert.issuer]['certificate']
						otext = "CA store"
						iauth = True
					elif vcert.issuer in [ x.subject for x in certsonly ]:
						vcert = [ x for x in certsonly if x.subject == vcert.issuer ][0]
						otext = "certificate chain"
						iauth = False
					else:
						vcert = None

					if tcert.subject != cert.subject:
						try:
							verify_cert_freshness(tcert, nao)
						except PrematureBirthError:
							expiry = True
							info.append("not yet valid")
						except ExpiredError:
							expiry = True
							info.append("expired")

					subject = tcert.subject.rfc4514_string()
					if tcert.issuer == tcert.subject:
						info.append("(self-signed)")
					if vcert is not None:
						v = verify_cert_signature(tcert, vcert)
						info.append("signed by {} (origin: {})".format(vcert.subject.rfc4514_string(), otext))
						if v:
							info.append("signature verified")
							if iauth:
								auth = True
						else:
							info.append("signature invalid")
					print("      {} - {}".format(subject, ", ".join(info)))
				if auth and not expiry:
					print(colorize("#0f0", "      Verification OK", force=args.force_color))
				else:
					print(colorize("#f00", "      Verification FAILED", force=args.force_color))
		if len(otheritems) > 0:
			print(f"Found {len(otheritems):n} other item(s):")
			for item in otheritems:
				thing = get_cryptothing(item)
				print("  *  {} ({})".format(thing.type, thing.description))

		if args.dump_mode != "none":
			print()

		if args.dump_mode in ['certs', 'extra']:
			for item in certsonly:
				thing = get_cryptothing(item)
				print("Detail for {} ({})".format(thing.type, thing.description))
				print(colorize(thing.color, thing.indent(), force=args.force_color))
		if len(otheritems) > 0 and args.dump_mode == 'extra':
			for item in otheritems:
				thing = get_cryptothing(item)
				print("Detail for {} ({})".format(thing.type, thing.description))
				print(colorize(thing.color, thing.indent(), force=args.force_color))
# }}}

def build_argparser():# {{{
	"""
	Helper function.  Builds argparse subparsers based on classes
	that start with the magic prefix "cli_".
	"""
	cmdprefix = "cli_"
	protoparser = argparse.ArgumentParser()
	subparsers = protoparser.add_subparsers()
	subparser_elements = []
	for cmd in [ x[len(cmdprefix):] for x in globals() if x.startswith(cmdprefix) ]:
		cmdclass = globals()[f"{cmdprefix}{cmd}"]
		parser_kwargs = {}
		parser_kwargs['formatter_class'] = argparse.RawDescriptionHelpFormatter
		if cmdclass.__doc__ is not None:
			parser_kwargs['description'] = "".join([ lstripn(x, 1, "\t") for x in cmdclass.__doc__.splitlines(keepends=True) ])
		parser = subparsers.add_parser(cmd, **parser_kwargs)
		cmdclass.parser_setup(parser)
		parser.set_defaults(cmd=cmdclass.run)
		subparser_elements.append((parser, parser_kwargs))
	return protoparser, subparser_elements
# }}}
def do_standalone(cmdclass):# {{{
	"""
	Helper function.  Allows the use of a "cli_" class as a
	standalone command.
	"""
	locale.setlocale(locale.LC_ALL, locale.getdefaultlocale())
	parser = argparse.ArgumentParser()
	parser_kwargs = {}
	parser_kwargs['formatter_class'] = argparse.RawDescriptionHelpFormatter
	if cmdclass.__doc__ is not None:
		parser_kwargs['description'] = "".join([ lstripn(x, 1, "\t") for x in cmdclass.__doc__.splitlines(keepends=True) ])
	parser = argparse.ArgumentParser(**parser_kwargs)
	cmdclass.parser_setup(parser)
	args = parser.parse_args()
	return cmdclass.run(args)
# }}}
def certminder_main():# {{{
	"""
	Entry point for `certminder`.
	"""
	sys.exit(do_standalone(cli_certminder))
# }}}
def catcert_main():# {{{
	"""
	Entry point for `catcert`.
	"""
	sys.exit(do_standalone(cli_catcert))
# }}}
def main():# {{{
	#If we're symlinked to the magic names `certminder` or `catcert`,
	#behave like the standalone app.
	#Otherwise, invoke the subparser logic.
	scriptbase = os.path.basename(sys.argv[0])
	if scriptbase == 'catcert':
		catcert_main()
	elif scriptbase == 'certminder':
		certminder_main()
	else:
		locale.setlocale(locale.LC_ALL, locale.getdefaultlocale())
		protoparser, subparser_elements = build_argparser()
		args = protoparser.parse_args()
		if not hasattr(args, "cmd"):
			protoparser.print_help()
			sys.exit(1)
		sys.exit(args.cmd(args))
# }}}
if __name__ == '__main__':
	main()
