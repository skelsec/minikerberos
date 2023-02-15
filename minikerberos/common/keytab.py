#
#
# Initial commit and structure: Tamas Jos (@skelsec)
# Main contributor to this file: Philip Alexiev https://github.com/philip-alexiev


# https://web.mit.edu/kerberos/krb5-1.12/doc/formats/keytab_file_format.html
#
# Be careful using this parser/writer! The specifications in the MIT Kerberos's official page doesnt match with the file Windows server generates!!
# Thus this script is to support Windows generated keytabs, not sure about MIT's
from __future__ import annotations
import io
from typing import List


class KeytabPrincipal:
    def __init__(self):
        self.num_components:int = None
        self.name_type:int = None
        self.realm:KeytabOctetString = None
        self.components:List[KeytabOctetString] = []

    @staticmethod
    def from_asn1(principal, realm):
        """Returns a principal from asn1 and realm"""
        p = KeytabPrincipal()
        p.name_type = principal['name-type']
        p.num_components = len(principal['name-string'])
        p.realm = KeytabOctetString.from_string(realm)
        for comp in principal['name-string']:
            p.components.append(KeytabOctetString.from_asn1(comp))

        return p

    @staticmethod
    def empty():
        """Returns a dummy principal"""
        p = KeytabPrincipal()
        p.name_type = 1
        p.num_components = 1
        p.realm = KeytabOctetString.from_string('kerbi.corp')
        for _ in range(1):
            p.components.append(KeytabOctetString.from_string('kerbi'))

        return p

    def to_string(self):
        """Returns the principal as a string"""
        return '-'.join([c.to_string() for c in self.components])
    
    def to_pname(self):
        """Returns the principal as a string in pname format"""
        return '/'.join(list(map(lambda c: c.to_string(), self.components)))

    def to_asn1(self):
        """Returns the principal as a tuple of asn1 and realm"""
        t = {'name-type': self.name_type, 'name-string': [name.to_string() for name in self.components]}
        return t, self.realm.to_string()

    @staticmethod
    def from_buffer(buffer):
        """Parses the principal from the buffer"""
        p = KeytabPrincipal()
        p.num_components = int.from_bytes(buffer.read(2), byteorder='big', signed=False)
        p.realm = KeytabOctetString.parse(buffer)
        for _ in range(p.num_components):
            p.components.append(KeytabOctetString.parse(buffer))
        p.name_type = int.from_bytes(buffer.read(4), byteorder='big', signed=False)
        return p

    def to_bytes(self):
        """Returns the principal as a byte array"""
        t = len(self.components).to_bytes(2, byteorder='big', signed=False)
        t += self.realm.to_bytes()
        for com in self.components:
            t += com.to_bytes()
        t += self.name_type.to_bytes(4, byteorder='big', signed=False)
        return t


class KeytabOctetString:
    def __init__(self):
        self.length:int = None
        self.data:bytes = None

    @staticmethod
    def empty() -> KeytabOctetString:
        """Creates an empty octet string"""
        o = KeytabOctetString()
        o.length = 0
        o.data = b''
        return o

    def to_asn1(self) -> bytes:
        """Returns the octet string as a byte array"""
        return self.data

    def to_string(self) -> str:
        """Returns the octet string as a string"""
        return self.data.decode()
    
    @staticmethod
    def from_string(data) -> KeytabOctetString:
        """Creates an octet string from a string"""
        o = KeytabOctetString()
        o.data = data.encode()
        o.length = len(o.data)
        return o

    @staticmethod
    def from_asn1(data) -> KeytabOctetString:
        """Creates an octet string from an asn1 object"""
        o = KeytabOctetString()
        o.length = len(data)
        if isinstance(data, str):
            o.data = data.encode()
        else:
            o.data = data
        return o

    @staticmethod
    def parse(reader: io.BytesIO) -> KeytabOctetString:
        """Parses the octet string from the reader"""
        o = KeytabOctetString()
        o.length = int.from_bytes(reader.read(2), byteorder='big', signed=False)
        o.data = reader.read(o.length)
        return o

    def to_bytes(self) -> bytes:
        """Returns the octet string as a byte array"""
        if isinstance(self.data, str):
            self.data = self.data.encode()
            self.length = len(self.data)
        t = len(self.data).to_bytes(2, byteorder='big', signed=False)
        t += self.data
        return t


class KeytabEntry:
    def __init__(self):
        self.principal:KeytabPrincipal = None
        self.timestamp:int = None
        self.key_version:int = None
        self.enctype:int = None
        self.key_length:int = None
        self.key_contents:bytes = None

    def to_bytes(self) -> bytes:
        """Returns the entry as a byte array"""
        t = self.principal.to_bytes()
        t += self.timestamp.to_bytes(4, 'big', signed=False)
        t += self.key_version.to_bytes(1, 'big', signed=False)
        t += self.enctype.to_bytes(2, 'big', signed=False)
        t += self.key_length.to_bytes(2, 'big', signed=False)
        t += self.key_contents
        return t
    
    def to_pname(self):
        """Returns the principal name of the entry"""
        return self.principal.to_pname()

    @staticmethod
    def from_bytes(data) -> KeytabEntry:
        """Reads a KeytabEntry from a byte array"""
        return KeytabEntry.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buffer:io.BytesIO) -> KeytabEntry:
        """Reads a KeytabEntry from a buffer"""
        ke = KeytabEntry()
        ke.principal = KeytabPrincipal.from_buffer(buffer)
        ke.timestamp = int.from_bytes(buffer.read(4), byteorder='big', signed=False)
        ke.key_version = int.from_bytes(buffer.read(1), 'big', signed=False)
        ke.enctype = int.from_bytes(buffer.read(2), 'big', signed=False)
        ke.key_length = int.from_bytes(buffer.read(2), 'big', signed=False)
        ke.key_contents = buffer.read(ke.key_length)
        return ke

    def __repr__(self):
        t = '=== KeytabEntry ===\r\n'
        t += 'Principal : %s\r\n' % self.principal.to_string()
        t += 'timestamp : %s\r\n' % self.timestamp
        t += 'key_version : %s\r\n' % self.key_version
        t += 'enctype : %s\r\n' % self.enctype
        t += 'key_length : %s\r\n' % self.key_length
        t += 'key_contents : %s\r\n' % self.key_contents.hex()

        return t


class Keytab:
    def __init__(self):
        self.krb5:int = 5
        self.version:int = 2
        self.entries:List[KeytabEntry] = []

    def to_bytes(self) -> bytes:
        """Returns the keytab as a byte array"""
        t = self.krb5.to_bytes(1, 'big', signed=False)
        t += self.version.to_bytes(1, 'big', signed=False)
        for e in self.entries:
            data = e.to_bytes()
            t += len(data).to_bytes(4, 'big', signed=False)
            t += data

        return t
    
    def get_pnames(self):
        """Returns all princial names available in the kaytab"""
        return [e.principal.to_pname() for e in self.entries]

    @staticmethod
    def from_bytes(data:bytes):
        """Reads a keytab from a byte array"""
        return Keytab.from_buffer(io.BytesIO(data))
    
    @staticmethod
    def from_file(filename:str):
        """Reads a keytab from a file"""
        with open(filename, 'rb') as f:
            return Keytab.from_buffer(f)

    @staticmethod
    def from_buffer(buffer:io.BytesIO) -> Keytab:
        """Reads a keytab from a buffer"""
        pos = buffer.tell()
        buffer.seek(0, 2)
        buffer_size = buffer.tell() - pos
        buffer.seek(pos, 0)

        k = Keytab()
        k.krb5 = int.from_bytes(buffer.read(1), 'big', signed=False)
        k.version = int.from_bytes(buffer.read(1), 'big', signed=False)
        i = 0
        while i < buffer_size:
            entry_size = int.from_bytes(buffer.read(4), 'big', signed=True)
            if entry_size == 0:
                break

            if entry_size < 0:
                # this is a hole
                i += entry_size * -1
                continue

            else:
                k.entries.append(KeytabEntry.from_bytes(buffer.read(entry_size)))
                i += entry_size

        return k

    def to_file(self, filename:str):
        """Writes the keytab to a file"""
        with open(filename, 'wb') as f:
            f.write(self.to_bytes())

    def __repr__(self):
        t = '=== Keytab ===\r\n'
        t += 'Version : %s\r\n' % self.version
        for e in self.entries:
            t += repr(e)

        return t
