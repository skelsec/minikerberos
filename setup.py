from setuptools import setup, find_packages

setup(
	# Application name:
	name="minikerberos",

	# Version number (initial):
	version="0.0.11",

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsec.com",

	# Packages
	packages=find_packages(),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/skelsec/minikerberos",

	zip_safe = True,
	#
	# license="LICENSE.txt",
	description="Kerberos manipulation library in pure Python",

	# long_description=open("README.txt").read(),
	python_requires='>=3.6',
	classifiers=(
		"Programming Language :: Python :: 3.6",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	),
	install_requires=[
		'asn1crypto',
	],

	entry_points={
		'console_scripts': [
			'ccacheedit = minikerberos.examples.ccache_editor:main',
			'kirbi2ccache = minikerberos.examples.kirbi2ccache:main',
			'ccache2kirbi = minikerberos.examples.ccache2kirbi:main',
			'ccacheroast = minikerberos.examples.ccacheroast:main',
			'getTGT = minikerberos.examples.getTGT:main',
			'getTGS = minikerberos.examples.getTGS:main',
		],
	}
)
