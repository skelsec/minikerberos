
from minikerberos.protocol.encryption import Key, Enctype, encrypt, decrypt, verify_checksum, Cksumtype, string_to_key, cf2, _zeropad, prf
from binascii import unhexlify as h

def test_encdec_aes():
	# AES128 encrypt and decrypt
	kb = h('9062430C8CDA3388922E6D6A509F5B7A')
	conf = h('94B491F481485B9A0678CD3C4EA386AD')
	keyusage = 2
	plain = '9 bytesss'.encode()
	ctxt = h('68FB9679601F45C78857B2BF820FD6E53ECA8D42FD4B1D7024A09205ABB7CD2E'
			 'C26C355D2F')
	k = Key(Enctype.AES128, kb)
	assert(encrypt(k, keyusage, plain, conf) == ctxt)
	assert(decrypt(k, keyusage, ctxt) == plain)

def test_encdec_aes256():
	# AES256 encrypt and decrypt
	kb = h('F1C795E9248A09338D82C3F8D5B567040B0110736845041347235B1404231398')
	conf = h('E45CA518B42E266AD98E165E706FFB60')
	keyusage = 4
	plain = '30 bytes bytes bytes bytes byt'.encode()
	ctxt = h('D1137A4D634CFECE924DBC3BF6790648BD5CFF7DE0E7B99460211D0DAEF3D79A'
			 '295C688858F3B34B9CBD6EEBAE81DAF6B734D4D498B6714F1C1D')
	k = Key(Enctype.AES256, kb)
	assert(encrypt(k, keyusage, plain, conf) == ctxt)
	assert(decrypt(k, keyusage, ctxt) == plain)

def test_aes128_checksum():
	# AES128 checksum
	kb = h('9062430C8CDA3388922E6D6A509F5B7A')
	keyusage = 3
	plain = 'eight nine ten eleven twelve thirteen'.encode()
	cksum = h('01A4B088D45628F6946614E3')
	k = Key(Enctype.AES128, kb)
	verify_checksum(Cksumtype.SHA1_AES128, k, keyusage, plain, cksum)

def test_aes256_checksum():
	# AES256 checksum
	kb = h('B1AE4CD8462AFF1677053CC9279AAC30B796FB81CE21474DD3DDBCFEA4EC76D7')
	keyusage = 4
	plain = 'fourteen'.encode()
	cksum = h('E08739E3279E2903EC8E3836')
	k = Key(Enctype.AES256, kb)
	verify_checksum(Cksumtype.SHA1_AES256, k, keyusage, plain, cksum)

def test_aes128_string_to_key():
	# AES128 string-to-key
	string = 'password'.encode()
	salt = 'ATHENA.MIT.EDUraeburn'.encode()
	params = h('00000002')
	kb = h('C651BF29E2300AC27FA469D693BDDA13')
	k = string_to_key(Enctype.AES128, string, salt, params)
	assert(k.contents == kb)

def test_aes256_string_to_key():
	# AES256 string-to-key
	string = b'X' * 64
	salt = 'pass phrase equals block size'.encode()
	params = h('000004B0')
	kb = h('89ADEE3608DB8BC71F1BFBFE459486B05618B70CBAE22092534E56C553BA4B34')
	k = string_to_key(Enctype.AES256, string, salt, params)
	assert(k.contents == kb)

def test_aes128_prf():
	# AES128 prf
	kb = h('77B39A37A868920F2A51F9DD150C5717')
	k = string_to_key(Enctype.AES128, 'key1'.encode(), 'key1'.encode())
	assert(prf(k, b'\x01\x61') == kb)

def test_aes256_prf():
	# AES256 prf
	kb = h('0D674DD0F9A6806525A4D92E828BD15A')
	k = string_to_key(Enctype.AES256, 'key2'.encode(), 'key2'.encode())
	assert(prf(k, b'\x02\x62') == kb)

def test_aes128_cf2():
	# AES128 cf2
	kb = h('97DF97E4B798B29EB31ED7280287A92A')
	k1 = string_to_key(Enctype.AES128, 'key1'.encode(), 'key1'.encode())
	k2 = string_to_key(Enctype.AES128, 'key2'.encode(), 'key2'.encode())
	k = cf2(Enctype.AES128, k1, k2, b'a', b'b')
	assert(k.contents == kb)

def test_aes256_cf2():
	# AES256 cf2
	kb = h('4D6CA4E629785C1F01BAF55E2E548566B9617AE3A96868C337CB93B5E72B1C7B')
	k1 = string_to_key(Enctype.AES256, 'key1'.encode(), 'key1'.encode())
	k2 = string_to_key(Enctype.AES256, 'key2'.encode(), 'key2'.encode())
	k = cf2(Enctype.AES256, k1, k2, b'a', b'b')
	assert(k.contents == kb)

def test_des3_encrypt_decrypt():
	# DES3 encrypt and decrypt
	kb = h('0DD52094E0F41CECCB5BE510A764B35176E3981332F1E598')
	conf = h('94690A17B2DA3C9B')
	keyusage = 3
	plain = b'13 bytes byte'
	ctxt = h('839A17081ECBAFBCDC91B88C6955DD3C4514023CF177B77BF0D0177A16F705E8'
			 '49CB7781D76A316B193F8D30')
	k = Key(Enctype.DES3, kb)
	assert(encrypt(k, keyusage, plain, conf) == ctxt)
	assert(decrypt(k, keyusage, ctxt) == _zeropad(plain, 8))

def test_des3_string_to_key():
	# DES3 string-to-key
	string = 'password'.encode()
	salt = 'ATHENA.MIT.EDUraeburn'.encode()
	kb = h('850BB51358548CD05E86768C313E3BFEF7511937DCF72C3E')
	k = string_to_key(Enctype.DES3, string, salt)
	assert(k.contents == kb)

def test_des3_checksum():
	# DES3 checksum
	kb = h('7A25DF8992296DCEDA0E135BC4046E2375B3C14C98FBC162')
	keyusage = 2
	plain = 'six seven'.encode()
	cksum = h('0EEFC9C3E049AABC1BA5C401677D9AB699082BB4')
	k = Key(Enctype.DES3, kb)
	verify_checksum(Cksumtype.SHA1_DES3, k, keyusage, plain, cksum)

def test_des3_cf2():
	# DES3 cf2
	kb = h('E58F9EB643862C13AD38E529313462A7F73E62834FE54A01')
	k1 = string_to_key(Enctype.DES3, 'key1'.encode(), 'key1'.encode())
	k2 = string_to_key(Enctype.DES3, 'key2'.encode(), 'key2'.encode())
	k = cf2(Enctype.DES3, k1, k2, b'a', b'b')
	assert(k.contents == kb)

def test_rc4_encrypt_decrypt():
	# RC4 encrypt and decrypt
	kb = h('68F263DB3FCE15D031C9EAB02D67107A')
	conf = h('37245E73A45FBF72')
	keyusage = 4
	plain = b'30 bytes bytes bytes bytes byt'
	ctxt = h('95F9047C3AD75891C2E9B04B16566DC8B6EB9CE4231AFB2542EF87A7B5A0F260'
			 'A99F0460508DE0CECC632D07C354124E46C5D2234EB8')
	k = Key(Enctype.RC4, kb)
	assert(encrypt(k, keyusage, plain, conf) == ctxt)
	assert(decrypt(k, keyusage, ctxt) == plain)

def test_rc4_string_to_key():
	# RC4 string-to-key
	string = 'foo'.encode()
	kb = h('AC8E657F83DF82BEEA5D43BDAF7800CC')
	k = string_to_key(Enctype.RC4, string, None)
	assert(k.contents == kb)

def test_rc4_checksum():
	# RC4 checksum
	kb = h('F7D3A155AF5E238A0B7A871A96BA2AB2')
	keyusage = 6
	plain = 'seventeen eighteen nineteen twenty'.encode()
	cksum = h('EB38CC97E2230F59DA4117DC5859D7EC')
	k = Key(Enctype.RC4, kb)
	verify_checksum(Cksumtype.HMAC_MD5, k, keyusage, plain, cksum)

def test_rc4_cf2():
	# RC4 cf2
	kb = h('24D7F6B6BAE4E5C00D2082C5EBAB3672')
	k1 = string_to_key(Enctype.RC4, 'key1'.encode(), 'key1'.encode())
	k2 = string_to_key(Enctype.RC4, 'key2'.encode(), 'key2'.encode())
	k = cf2(Enctype.RC4, k1, k2, b'a', b'b')
	assert(k.contents == kb)

def test_des_string_to_key():
	# DES string-to-key
	string = 'password'.encode()
	salt = 'ATHENA.MIT.EDUraeburn'.encode()
	kb = h('cbc22fae235298e3')
	k = string_to_key(Enctype.DES_MD5, string, salt)
	assert(k.contents == kb)

def test_des_string_to_key():
	# DES string-to-key
	string = 'potatoe'.encode()
	salt = 'WHITEHOUSE.GOVdanny'.encode()
	kb = h('df3d32a74fd92a01')
	k = string_to_key(Enctype.DES_MD5, string, salt)
	assert(k.contents == kb)
	print('all tests passed!')
	
	
