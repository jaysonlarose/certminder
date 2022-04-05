#!/usr/bin/env python

import setuptools

_locals = {}
with open("certminder/_version.py", "r") as fp:
	exec(fp.read(), None, _locals)
version = _locals["__version__"]

setuptools.setup(
	name         = "certminder",
	version      = version,
	author       = "Jayson Larose",
	author_email = "jayson@interlaced.org",
	url          = "https://github.com/jaysonlarose/certminder",
	description  = "Certificate Minder",
	download_url = f"https://github.com/jaysonlarose/certminder/releases/download/{version}/certminder-{version}.tar.gz",
	packages     = ['certminder'],
	install_requires = [
		'cryptography',
		'pyOpenSSL',
		'pytz',
	],
	entry_points = {
		'console_scripts': [
			'certminder=certminder:certminder_main',
			'catcert=certminder:catcert_main',
		],
	},
)
