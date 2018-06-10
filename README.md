# minikerberos
Kerberos manipulation library in pure Python

## Prerequisites
python>=3.6 - as always  
asn1crypto - the best python lib to parse/modify/construct ASN1 data. It is also written in pure python, so no need to compile anything, just install and use.

## Usage
This is a library so the main intention is to use it in your code, however the "examples" folder contain a few useful examples to show what this lib is capable of.  
```ccache2kirbi.py``` converts CCACHE -kerberos cache- file to kirbi files. Kirbi file is supported by mimikatz to perform pass the ticket attacks  
  
```kirbi2ccache.py``` convers a kirbi file, or a directory full of kirbi files into one CCACHE file. This helps users who prefer to use impacket to perform kerberos ticket related attacks  
  
```getTGT.py``` polls a kerberos server for a TGT given that you have some user secrets at your disposal. The TGT will be saved in a CCACHE file. The minimum required "user secret" is either a password OR and NT hash of the user OR the kerberos AES key of the user 
  
```getTGS.py``` Same as ```getTGT.py``` but also gets a TGS ticket for a given service from the domain controller.

  
## Installation
Install it via either cloning it from github and using  
```setup.py install```  
  
or via pip  
```pip install minikerberos```

