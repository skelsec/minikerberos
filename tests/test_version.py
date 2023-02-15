from minikerberos._version import __version__, __banner__

def test_version():
    assert __version__.count('.') == 2

def test_banner():
    assert __banner__.find('@skelsec') != -1