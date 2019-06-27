# Copyright (C) 2019 ellipticSecure
# See the accompanying file LICENCE
# Author: Kobus Grobler

import ctypes
from ctypes import *
from .constants import *
import base58

P_ULONG = POINTER(c_ulong)

XPUB_HEADERS = {
    'standard': 0x0488b21e,
    'p2wpkh-p2sh': 0x049d7cb2,
    'p2wsh-p2sh': 0x0295b43f,
    'p2wpkh': 0x04b24746,
    'p2wsh': 0x02aa7ed3,
}

class CKVersion(Structure):
    _fields_ = [("major", c_byte),
                ("minor", c_byte),
                ]


class CKTokenInfo(Structure):

    _fields_ = [("label", c_char * 32),
                ("manufacturerID", c_char * 32),
                ("model", c_char * 16),
                ("serialNumber", c_char * 16),
                ("flags", c_ulong),
                ("ulMaxSessionCount", c_ulong),
                ("ulSessionCount", c_ulong),
                ("ulMaxRwSessionCount", c_ulong),
                ("ulRwSessionCount", c_ulong),
                ("ulMaxPinLen", c_ulong),
                ("ulMinPinLen", c_ulong),
                ("ulTotalPublicMemory", c_ulong),
                ("ulFreePublicMemory", c_ulong),
                ("ulTotalPrivateMemory", c_ulong),
                ("ulFreePrivateMemory", c_ulong),
                ("hardwareVersion", CKVersion),
                ("firmwareVersion", CKVersion),
                ("utcTime", c_char * 16),
                ]


def load_ehsm(libname=None):
    if libname is None:
        library_paths = (
            'libehsm.so',
            'libehsm.dylib',
            'ehsm.dll'
        )

        for lib in library_paths:
            try:
                ehsmlib = ctypes.cdll.LoadLibrary(lib)
                break
            except OSError:
                pass
        else:
            error = "Unable to load any of the following libraries:{}" \
                .format(' '.join(library_paths))
            raise RuntimeError(error)
    else:
        ehsmlib = ctypes.cdll.LoadLibrary(libname)

    ehsmlib.C_Initialize.argtypes = [c_voidp]
    ehsmlib.C_Initialize.restype = c_ulong

    ehsmlib.C_Finalize.argtypes = [c_voidp]
    ehsmlib.C_Finalize.restype = c_ulong

    ehsmlib.C_GetSlotList.argtypes = [c_bool, c_void_p, P_ULONG]
    ehsmlib.C_GetSlotList.restype = c_ulong

    ehsmlib.C_OpenSession.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p, P_ULONG]
    ehsmlib.C_OpenSession.restype = c_ulong

    ehsmlib.C_CloseSession.argtypes = [c_ulong]
    ehsmlib.C_CloseSession.restype = c_ulong

    ehsmlib.C_Login.argtypes = [c_ulong, c_ulong, POINTER(c_char), c_ulong]
    ehsmlib.C_Login.restype = c_ulong

    ehsmlib.C_InitToken.argtypes = [c_ulong, POINTER(c_char), c_ulong, c_char_p]
    ehsmlib.C_InitToken.restype = c_ulong

    ehsmlib.C_InitPIN.argtypes = [c_ulong, POINTER(c_char), c_ulong]
    ehsmlib.C_InitPIN.restype = c_ulong

    ehsmlib.C_GetTokenInfo.argtypes = [c_ulong, POINTER(CKTokenInfo)]
    ehsmlib.C_GetTokenInfo.restype = c_ulong

    ehsmlib.C_DestroyObject.argtypes = [c_ulong, c_ulong]
    ehsmlib.C_DestroyObject.restype = c_ulong

    ehsmlib.u32FactoryReset.argtypes = [ctypes.c_ulong]
    ehsmlib.u32FactoryReset.restype = c_uint32

    # session, seed, seedLen
    ehsmlib.u32ImportBitcoinKey.argtypes = [c_ulong, POINTER(c_char), c_size_t]
    ehsmlib.u32ImportBitcoinKey.restype = c_uint32

    ehsmlib.u32HasBitcoinKey.argtypes = [c_ulong, P_ULONG]
    ehsmlib.u32HasBitcoinKey.restype = c_uint32

    ehsmlib.u32GetBitcoinPub.argtypes = [c_ulong, POINTER(c_uint32), c_size_t, POINTER(c_char), POINTER(c_size_t)]
    ehsmlib.u32GetBitcoinPub.restype = c_uint32

    # session, hash, hashLen, indexes, indexes len, sig, sigLenInOut
    ehsmlib.u32SignBitcoinHash.argtypes = [c_ulong, POINTER(c_char), c_size_t, POINTER(c_uint32), c_size_t, POINTER(c_char), POINTER(c_size_t)]
    ehsmlib.u32SignBitcoinHash.restype = c_uint32

    return EHSMLib(ehsmlib)


class EHSMLib:
    ehsmlib = None

    msgs = {
        CKR_FUNCTION_FAILED: "Function failed",
        CKR_ARGUMENTS_BAD: "Invalid function arguments",
        CKR_CRYPTOKI_NOT_INITIALIZED: "Library not initialized",
        CKR_PIN_INCORRECT: "Incorrect PIN",
        CKR_USER_NOT_LOGGED_IN: "User not logged in",
        CKR_USER_PIN_NOT_INITIALIZED: "User PIN not initialized",
        CKR_OBJECT_HANDLE_INVALID: "Object handle is invalid",
        BTC_KEY_NOT_FOUND: "BIP32 Key not found",
        BTC_KEY_ALREADY_EXISTS: "BIP32 key already exists"
    }

    def __init__(self, ehsmlib):
        self.ehsmlib = ehsmlib

    def checkRV(self, r):
        """Checks the return value and raises RunTimeError if not 0

        """
        if r != 0:
            if r in self.msgs:
                raise RuntimeError(self.msgs[r])
            else:
                raise RuntimeError("Function returned an error: " + hex(r))

    def enumerate_slots(self):
        """Returns a list of available HSM slots

        :returns: the u_long slot list
        :rtype: list
        """

        self.ehsmlib.C_Initialize(None)
        slotLen = P_ULONG(c_ulong(0))
        try:
            self.checkRV(self.ehsmlib.C_GetSlotList(True, None, slotLen))
            if slotLen[0] > 0:
                slots = (c_ulong * slotLen[0])()
                self.checkRV(self.ehsmlib.C_GetSlotList(True, slots, slotLen))
                return slots
        finally:
            self.ehsmlib.C_Finalize(None)

    def get_info(self, slot):
        """Returns the token info struct

        Requires the library to be initialized and a valid slot as parameter
        :param slot: a valid hsm slot (from enumerate_slots)
        :type slot: c_ulong
        :returns: the CKTokenInfo struct
        :rtype: CKTokenInfo
        """

        info = CKTokenInfo()
        self.checkRV(self.ehsmlib.C_GetTokenInfo(slot, info))
        return info

    def is_initialized(self, slot):
        """Returns true if the device has been initialized

        Requires the library to be initialized and a valid slot as parameter
        :param slot: a valid hsm slot (from enumerate_slots)
        :type slot: c_ulong
        """

        info = self.get_info(slot)
        if info.flags & CKF_TOKEN_INITIALIZED:
            return True
        return False

    def is_user_pin_set(self, slot):
        """Returns true if user pin has been set on the device

        Requires the library to be initialized and a valid slot as parameter
        :param slot: a valid hsm slot (from enumerate_slots)
        :type slot: c_ulong
        """

        info = self.get_info(slot)
        if info.flags & CKF_USER_PIN_INITIALIZED:
            return True
        return False

    def init_token(self, slot, pin, label):
        """Initializes the device

        Requires the library to be initialized and a valid slot, security officer (SO) pin and label as parameters
        :param slot: a valid hsm slot (from enumerate_slots)
        :type slot: c_ulong
        :param pin: a valid security officer (SO) pin
        :type pin: bytes
        :param label: a valid label
        :type label: bytes
        """

        label = label.ljust(32)
        self.checkRV(self.ehsmlib.C_InitToken(slot, pin, len(pin), label))

    def init_user_pin(self, session, pin):
        """Set a user (SU) pin for the device

        Requires the library to be initialized and a valid session and user (SU) pin as parameters
        :param session: a valid RW hsm SO session (from get_logged_in_rw_session)
        :type session: c_ulong
        :param pin: a valid user (SU) pin
        :type pin: bytes
        """

        self.checkRV(self.ehsmlib.C_InitPIN(session, pin, len(pin)))

    def _open_rw_session(self, slot):
        session = c_ulong(0)
        self.checkRV(self.ehsmlib.C_OpenSession(slot, 6, None, None, session))
        return session

    def init(self):
        """Initializes the eHSM PKCS11 library

        Required before any functions can be called
        """

        self.checkRV(self.ehsmlib.C_Initialize(None))

    def finalize(self):
        """Finalizes the eHSM PKCS11 library

        Call to cleanup sessions and release locks on the device
        """

        self.ehsmlib.C_Finalize(None)

    def get_logged_in_rw_session(self, slot, pin, user=CKU_USER):
        """Gets a logged in session for the user

        :param slot: the device slot
        :param pin: the user pin/passphrase
        :param user: the user type - CKU_USER or CKU_SO
        :return: a session
        """

        session = self._open_rw_session(slot)
        if pin is None:
            raise RuntimeError("pin must be supplied")
        self.checkRV(self.ehsmlib.C_Login(session, user, pin, len(pin)))
        return session

    def close_session(self, session):
        """Closes a session

        :param session: the session handle
        """

        self.checkRV(self.ehsmlib.C_CloseSession(session))

    def destroy_object(self, session, handle):
        """
        Destroys the object with the provided handle
        :param session: a valid RW session
        :param handle: the object handle
        :return: None
        """

        self.checkRV(self.ehsmlib.C_DestroyObject(session, handle))

    def _to_uint32_arr(self,indexes):
        indexes_type = c_uint32 * len(indexes)
        arr = indexes_type()
        i = 0
        for index in indexes:
            arr[i] = index
            i = i+1
        return arr

    def bip32_sign_data(self, session, hash, indexes):

        arr = self._to_uint32_arr(indexes)
        outSize = c_size_t(0)
        outSize.value = 128
        data = ctypes.create_string_buffer(outSize.value)

        # session, hash, hashLen, indexes, indexes len, sig, sigLenInOut
        self.checkRV(self.ehsmlib.u32SignBitcoinHash(session, hash, len(hash), arr, len(indexes),
                                               data, outSize))
        return data.raw[:outSize.value]

    def bip32_get_xpub(self, session, indexes, net):
        """Returns an base58 xpub encoded public key for the provided path and net

        See https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

        :param session: a valid logged in session
        :param indexes: the indexes representing the path
        :param net: the network id to use
        :return: an xpub encoded key
        """

        arr = self._to_uint32_arr(indexes)
        outSize = c_size_t(0)
        outSize.value = 128
        data = ctypes.create_string_buffer(outSize.value)
        self.checkRV(self.ehsmlib.u32GetBitcoinPub(session, arr, len(indexes), data, outSize))
        xpubversion_bytes = net.to_bytes(length=4, byteorder="big")
        payload = xpubversion_bytes + data.raw[:outSize.value]
        if len(payload) != 78:
            raise RuntimeError(f"Unexpected xpub payload len {len(payload)}")
        return base58.b58encode_check(payload).decode("utf-8")

    def bip32_import_root_key(self, session, bip32_seed):
        """Imports a root key from the provided seed

        :param session: a valid session
        :param bip32_seed: the binary bip32 seed bytes
        :return: None
        """

        self.checkRV(self.ehsmlib.u32ImportBitcoinKey(session, bip32_seed, len(bip32_seed)))

    def bip32_has_root_key(self, session):
        """ Return true if a BTC key is present

        :param session: a valid session handle
        :return: Tuple(bool, object handle)
        """

        handle = c_ulong(0)
        rv = self.ehsmlib.u32HasBitcoinKey(session, handle)
        if rv == 0:
            return True, handle
        if not rv == BTC_KEY_NOT_FOUND:
            self.checkRV(rv)
        return False, None

    def fw_version(self, slot):
        """Returns true if user pin has been set on the device

        Requires the library to be initialized and a valid slot as parameter
        :param slot: a valid hsm slot (from enumerate_slots)
        :type slot: c_ulong
        """

        info = self.get_info(slot)
        return info.firmwareVersion.major, info.firmwareVersion.minor

