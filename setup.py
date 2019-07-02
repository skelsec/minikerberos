import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.md'), encoding='utf-8') as readme_file:
    long_description = readme_file.read()

setup(
    name="minikerberos",
    version="0.0.9",
    author="Tamas Jos",
    author_email="info@skelsec.com",
    packages=find_packages(),
    include_package_data=True,
    test_suite="tests",
    url="https://github.com/skelsec/minikerberos",
    download_url='https://github.com/skelsec/minikerberos/releases',
    zip_safe=True,
    license="MIT",
    description="Kerberos manipulation library in pure Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    python_requires=">=3.6",
    classifiers=(
        "Programming Language :: Python :: 3.6",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
    install_requires=[
        "asn1crypto",
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
