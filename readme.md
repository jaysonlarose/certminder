# Certminder — scripts for inspecting and managing SSL/TLS certificates.

It's one part convenience library, two parts handy script.

# catcert — eats up certificates and spits out knowledge.

Feed a certificate to catcert — any format — and it'll tell you what it's for and whether or not it's expired. Give catcert a hostname:port pair for something running TLS, and it'll even pull the certificate off the server and tell you about it. It'll even verify the signature chain and tell you where things fell apart if you want it to.

# certminder — react to expiring certificates.

Sometimes acme.sh, certbot, or whatever other of your best-laid plans don't cut it. certminder gives you a really simple way to specify a certificate, an expiration threshold, and what command you want run if part A is about to run headlong into part B.

Just like with catcert, any format you want, even on a remote server.

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

# cerminder config file format

Configuration files are in ConfigParser format. Each section describes a certificate to inspect, its action threshold, and what command to run if it fails the freshness test.

Example:

```
[my local certificate]
certificate = /etc/pki/mycert.pem
threshold   = 2w
run         = /usr/bin/notify-send "certificate {path} is expiring!"

[my remote certificate]
certificate = google.com:443
threshold   = 90d
run         = /usr/bin/notify-send "certificate {path} is expiring!"
```


## Directives:

`certificate` — path to the certificate file to test. Use `hostname:port` to check a TLS certificate over the network.
	
`threshold` —  activity will be triggered if the certificate is set to expire anytime before this threshold. Specified in a format like: `12w 10d 4h 2m 1s` translating to "10 weeks, 10 days, 4 hours, 2 minutes, 1 second".

`run` — this command will be run if activity is triggered. Standard python string formatting is used for replacement. Currently the only tokens used for replacement are:

* `path` — the path or hostname:port to the certificate being tested
* `subject` — the RFC4514 subject name for the certificate. This can be used to differentiate between certificates if a path or network location contains a certificate chain.
