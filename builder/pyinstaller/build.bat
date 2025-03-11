@echo off
set projectname=minikerberos
set hiddenimports= --hidden-import cryptography --hidden-import cffi --hidden-import cryptography.hazmat.backends.openssl --hidden-import cryptography.hazmat.bindings._openssl --hidden-import unicrypto --hidden-import unicrypto.backends.pycryptodome.DES --hidden-import  unicrypto.backends.pycryptodome.TDES --hidden-import unicrypto.backends.pycryptodome.AES --hidden-import unicrypto.backends.pycryptodome.RC4 --hidden-import unicrypto.backends.pure.DES --hidden-import  unicrypto.backends.pure.TDES --hidden-import unicrypto.backends.pure.AES --hidden-import unicrypto.backends.pure.RC4 --hidden-import unicrypto.backends.cryptography.DES --hidden-import  unicrypto.backends.cryptography.TDES --hidden-import unicrypto.backends.cryptography.AES --hidden-import unicrypto.backends.cryptography.RC4 --hidden-import unicrypto.backends.pycryptodomex.DES --hidden-import  unicrypto.backends.pycryptodomex.TDES --hidden-import unicrypto.backends.pycryptodomex.AES --hidden-import unicrypto.backends.pycryptodomex.RC4
set root=%~dp0
set repo=%root%..\..\%projectname%
IF NOT DEFINED __BUILDALL_VENV__ (GOTO :CREATEVENV)
GOTO :BUILD

:CREATEVENV
python -m venv %root%\env
CALL %root%\env\Scripts\activate.bat
pip install pyinstaller
GOTO :BUILD

:BUILD
cd %repo%\..\
pip install .
cd %repo%\examples
pyinstaller -F ccache_editor.py -n minikerberos-ccacheedit %hiddenimports%
pyinstaller -F ccache2kirbi.py -n minikerberos-ccache2kirbi %hiddenimports%
pyinstaller -F ccacheroast.py -n minikerberos-ccacheroast %hiddenimports%
pyinstaller -F CVE_2022_33647.py -n minikerberos-cve202233647 %hiddenimports%
pyinstaller -F CVE_2022_33679.py -n minikerberos-cve202233679 %hiddenimports%
pyinstaller -F getNT.py -n minikerberos-getNTPKInit %hiddenimports%
pyinstaller -F getS4U2proxy.py -n minikerberos-getS4U2proxy %hiddenimports%
pyinstaller -F getS4U2self.py -n minikerberos-getS4U2self %hiddenimports%
pyinstaller -F getTGS.py -n minikerberos-getTGS %hiddenimports%
pyinstaller -F getTGT.py -n minikerberos-getTGT %hiddenimports%
pyinstaller -F kerb23hashdecrypt.py -n minikerberos-kerb23hashdecrypt %hiddenimports%
pyinstaller -F kirbi2ccache.py -n minikerberos-kirbi2ccache %hiddenimports%
pyinstaller -F spnroast.py -n minikerberos-kerberoast %hiddenimports%
pyinstaller -F asreproast.py -n minikerberos-asreproast %hiddenimports%
pyinstaller -F changepassword.py -n minikerberos-changepw %hiddenimports%
cd %repo%\examples\dist & copy *.exe %root%\
GOTO :CLEANUP

:CLEANUP
IF NOT DEFINED __BUILDALL_VENV__ (deactivate)
cd %root%
EXIT /B
