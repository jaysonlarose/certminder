# Certminder — scripts for inspecting and managing SSL/TLS certificates.

It's one part convenience library, two parts handy script.

# catcert — eats up certificates and spits out knowledge.

Feed a certificate to catcert — any format — and it'll tell you what it's for and whether or not it's expired. Give catcert a hostname:port pair for something running TLS, and it'll even pull the certificate off the server and tell you about it. It'll even verify the signature chain and tell you where things fell apart if you want it to.

# certminder — react to expiring certificates.

Sometimes acme.sh, certbot, or whatever other of your best-laid plans don't cut it. certminder gives you a really simple way to specify a certificate, an expiration threshold, and what command you want run if part A is about to run headlong into part B.

Just like with catcert, any format you want, even on a remote server.

# Installation

I haven't gotten this added to [PyPI](https://pypi.org/) yet — mainly because I'm kind of lazy — but that doesn't mean you have to bother with manual installation. Just run this from the command-line:

```bash
sudo pip3 install git+https://github.com/jaysonlarose/certminder
```

, and you're off to the races!

# Philosophy

* Minimal dependencies
* Do the most common tasks 

# Formats understood by certminder

* X.509 PEM (.pem)
* X.509 DER (.crt)
* PKCS#7 PEM (.p7b)
* PKCS#7 DER (.p7s)
* PKCS#12 (.p12, .pfx)
* Cisco X.509 DER hex dump (ie, `show running-config` on a Cisco ASA)

# certminder config file format

Configuration files are in YAML format. An example looks like this:

```yaml
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
```


## Directives:

```
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

```
