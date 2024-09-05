![Supported Python versions](https://img.shields.io/badge/python-3.7+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/skelsec?label=skelsec&style=social)](https://twitter.com/intent/follow?screen_name=skelsec)

## :triangular_flag_on_post: Sponsors

If you like this project, consider purchasing licenses of [OctoPwn](https://octopwn.com/), our full pentesting suite that runs in your browser!  
For notifications on new builds/releases and other info, hop on to our [Discord](https://discord.gg/PM8utcNxMS)


# minikerberos
`minikerberos` is a kerberos client library written in `Python>=3.6` it is the kerberos library used in other tools suchs as `pypykatz`, `aiosmb` and `msldap`. It also comes with multiple useful examples for pentesters who wish to perform security audits on the kerberos protocol.  

## :triangular_flag_on_post: Runs in the browser

This project, alongside with many other pentester tools runs in the browser with the power of OctoPwn!  
Check out the community version at [OctoPwn - Live](https://live.octopwn.com/)

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

## Information for developers
`minikerberos` library contains both asynchronous and blocking versions of the kerberos client with the same API. Besides the usual password/aes/rc4 LTK authentication methods it also supports PKINIT using `pfx` or `pem` formatted certificates as well as certificates stored in windows certificate store. 

## Information for pentesters
`minikerberos` comes with examples which can be used to perform the usual pentest activities out-of-the-box without additional coding required.

# Examples AKA the pentest tools
Installing `minikerberos` module via pip will automatically place all examples in the `Scripts` directory by the `setuptools` build environment. All tools named in the following way `minikerberos-<toolname>`

## minikerberos-getTGT
Fetches a TGT for the given kerberos credential. The kredential must be in a standard `kerberos URL` format.

## minikerberos-getTGS
Fetches an TGS ticket (TGSREP) for the given cerberos credential and SPN record.  
SPN must be in `service/hostname@FQDN` format.

## minikerberos-kerberoast
Also known as SPNRoast, this tool performs a kerberoast attack against one or multiple users, using the provided kerberos credential.

## minikerberos-getNTPKInit
This tool recovers the NT hash for the user specified by the kerberos credential. This only works if PKINIT (cert based auth) is used.

## minikerberos-kerb23hashdecrypt
This tool attempts to recover the user's NT hash for a list of kerberoast hashes.  
When you performed a kerberoast attack against one or multiple users, and have a huge list of NT hashes (no password needed) this tool will check each NT hash if it can decrypt the ticket in the kerberoasted hashes.  
Full disclosure, those are not hashes and it hurt me writing the previous sentence.  

## minikerberos-getS4U2self
This tool is used when you have credentials to a machine account and would like to impersonate other users on the same machine. Machine account credential should be supplied in the `kerberos URL` format, while the user to be impersonated should be in the usual UserPrincialName format eg `username@FQDN`

## minikerberos-getS4U2proxy
This tool is used when you have a machine account which has the permission to perform Kerberos Resource-based Constrained Delegation (RBCD). With this, you can impersonate users. For this to work, the machine account must be allowed to delegate on all protocols, not kerberos-only!

## minikerberos-ccacheroast
Performs "Kerberoast" attack on a CCACHE file. You get back the "hashes" for all TGS tickets stored in the CCACHE file.

## minikerberos-ccache2kirbi
Converts a CCACHE file to a list of `.kirbi` files.


## minikerberos-kirbi2ccache
Converts one or more `.kirbi` files into one CCACHE file

## minikerberos-ccacheedit
Command-line CCACHE file editor. It can list/delete credentials in a CCACHE file.

