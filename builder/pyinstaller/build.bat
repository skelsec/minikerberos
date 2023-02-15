@echo off
set hiddenimports= --hidden-import cryptography --hidden-import cffi --hidden-import cryptography.hazmat.backends.openssl --hidden-import cryptography.hazmat.bindings._openssl --hidden-import unicrypto --hidden-import unicrypto.backends.pycryptodome.DES --hidden-import  unicrypto.backends.pycryptodome.TDES --hidden-import unicrypto.backends.pycryptodome.AES --hidden-import unicrypto.backends.pycryptodome.RC4 --hidden-import unicrypto.backends.pure.DES --hidden-import  unicrypto.backends.pure.TDES --hidden-import unicrypto.backends.pure.AES --hidden-import unicrypto.backends.pure.RC4 --hidden-import unicrypto.backends.cryptography.DES --hidden-import  unicrypto.backends.cryptography.TDES --hidden-import unicrypto.backends.cryptography.AES --hidden-import unicrypto.backends.cryptography.RC4 --hidden-import unicrypto.backends.pycryptodomex.DES --hidden-import  unicrypto.backends.pycryptodomex.TDES --hidden-import unicrypto.backends.pycryptodomex.AES --hidden-import unicrypto.backends.pycryptodomex.RC4
set root=%~dp0
set projectname=minikerberos
set pyenv=%root%\env
set repo=%root%..\..\%projectname%
python -m venv %pyenv%
%pyenv%\Scripts\activate.bat &^
pip install pyinstaller &^
cd %repo%\..\ &^
pip install . &^
cd %repo%\examples &^
pyinstaller -F ccache_editor.py %hiddenimports% &^
pyinstaller -F ccache2kirbi.py %hiddenimports% &^
pyinstaller -F ccacheroast.py %hiddenimports% &^
pyinstaller -F CVE_2022_33647.py %hiddenimports% &^
pyinstaller -F CVE_2022_33679.py %hiddenimports% &^
pyinstaller -F getNT.py %hiddenimports% &^
pyinstaller -F getS4U2proxy.py %hiddenimports% &^
pyinstaller -F getS4U2self.py %hiddenimports% &^
pyinstaller -F getTGS.py %hiddenimports% &^
pyinstaller -F getTGT.py %hiddenimports% &^
pyinstaller -F kerb23hashdecrypt.py %hiddenimports% &^
pyinstaller -F kirbi2ccache.py %hiddenimports% &^
pyinstaller -F spnroast.py %hiddenimports% &^
cd %repo%\dist & copy *.exe %root%\