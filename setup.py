#!/usr/bin/env python

import setuptools

version = __import__("certminder").__version__
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
	],
	entry_points = {
		'console_scripts': [
			'certminder=certminder:certminder_main',
			'catcert=certminder:catcert_main',
		],
	},
)
