![Supported Python versions](https://img.shields.io/badge/python-3.6+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/skelsec?label=skelsec&style=social)](https://twitter.com/intent/follow?screen_name=skelsec)

:triangular_flag_on_post: This is the public repository of minikerberos, for latest version and updates please consider supporting us through https://porchetta.industries/

# minikerberos
Kerberos manipulation library in pure Python.

## :triangular_flag_on_post: Sponsors

If you want to sponsors this project and have the latest updates on this project, latest issues fixed, latest features, please support us on https://porchetta.industries/

## Official Discord Channel

Come hang out on Discord!

[![Porchetta Industries](https://discordapp.com/api/guilds/736724457258745996/widget.png?style=banner3)](https://discord.gg/ycGXUxy)


## Prerequisites

- Python >= 3.6  
- `asn1crypto`: the best Python lib to parse/modify/construct ASN1 data. It is
  also written in pure Python, so no need to compile anything, just install
  and use.
- `oscrypto`: For certificate operations
- `asysocks`: Provides built-in SOCKS/HTTP/etc proxy capability

## Usage
This is a library so the main intention is to use it in your code, however
the "examples" folder contain a few useful examples to show what this lib is
capable of.  

- `ccache2kirbi.py` converts CCACHE - kerberos cache - file to kirbi files.
   Kirbi file is supported by mimikatz to perform pass the ticket attacks.  
  
- `kirbi2ccache.py` converts a kirbi file, or a directory full of kirbi files
  into one CCACHE file. This helps users who prefer to use impacket to perform
  Kerberos ticket related attacks  
  
- `getTGT.py` polls a Kerberos server for a TGT given that you have some user
  secrets at your disposal. The TGT will be saved in a CCACHE file. The minimum
  required "user secret" is either a password OR and NT hash of the user OR
  the Kerberos AES key of the user.
  
- `getTGS.py` same as `getTGT.py` but also gets a TGS ticket for a given
  service from the domain controller.

- `getS4U2proxy.py` to be used for getting a TGS ticket on behalf of another user. Basically it performs a kerberos constrained delegation process.

- `getS4U2self.py` yes.
  
## Installation

Install it via either cloning it from GitHub and using  

```bash
$ git clone https://github.com/skelsec/minikerberos.git
$ cd minikerberos
$ python3 setup.py install
```  
  
or with `pip` from the Python Package Index (PyPI).
  
```bash
$ pip install minikerberos --user
```

Consider to use a Python virtual environment.
