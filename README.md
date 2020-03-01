# minikerberos

Kerberos manipulation library in pure Python.

# WARNING
The library underwent some considerable restructuring from 0.1.X to 0.2.X and above.
These changes will 100% likely to break your existing code, so either fix the version in your requirements or update your scripts.  
  
Sorry for the inconveinence, however I deemed it important to make these changes for a better API and usability. From version 0.2.0 and above the code will more focusing on asynchronous operation. Backport of additional features will happen to the blocking IO based classes, but expect some delays.


## Prerequisites

- Python >= 3.6  
- `asn1crypto`: the best Python lib to parse/modify/construct ASN1 data. It is
  also written in pure Python, so no need to compile anything, just install
  and use.

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
