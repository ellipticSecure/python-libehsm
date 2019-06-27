#
# WARNING, these tests will destroy any existing BTC keys on a device (if you happen to have the same
# password as the unit test set, which I hope you did not).

# Do NOT run on a device used to store actual keys, it may pin lock the device due to incorrect password entered during
# tests.
#

import os
import unittest
import binascii
import ehsm

from ehsm.constants import *

TEST_SO_PW = b"testso"
TEST_SU_PW = b"testsu"


class EHSMTestCase(unittest.TestCase):

    def setUp(self):
        super().setUp()
        if not 'TEST_MODULE' in os.environ:
            raise RuntimeError("Specify a the path to the ehsm shared library using environment variable 'TEST_MODULE'")
        print("Loading "+os.environ['TEST_MODULE'])
        self.mirkey = ehsm.load_ehsm(os.environ['TEST_MODULE'])
        self.slots = self.mirkey.enumerate_slots()
        self.assertTrue(len(self.slots) > 0, "No available slots")
        self.slot = self.slots[0]

    def tearDown(self):
        super().tearDown()
        if self.mirkey is not None:
            self.mirkey.finalize()


class TestBtc(EHSMTestCase):

    def _check_init_ehsm(self):
        mirkey = self.mirkey
        info = mirkey.get_info(self.slot)
        if not info.flags & CKF_TOKEN_INITIALIZED:
            # Initialize
            mirkey.init_token(self.slot, TEST_SO_PW, b"test label")
            session = mirkey.get_logged_in_rw_session(self.slot, TEST_SO_PW, CKU_SO)
            mirkey.init_user_pin(session, TEST_SU_PW)
            info.flags = info.flags & CKF_USER_PIN_INITIALIZED
            mirkey.close_session(session)

        if not info.flags & CKF_USER_PIN_INITIALIZED:
            # Set user pin
            session = mirkey.get_logged_in_rw_session(self.slot, TEST_SO_PW, CKU_SO)
            mirkey.init_user_pin(session, TEST_SU_PW)
            mirkey.close_session(session)

        if info.firmwareVersion.major < 1 or (info.firmwareVersion.major == 1 and info.firmwareVersion.minor < 13):
            raise RuntimeError("Firmware version too old too support BIP32 tests")

    def test_version(self):
        mirkey = self.mirkey
        mirkey.init()
        try:
            major, minor = mirkey.fw_version(self.slot)
            print(f'\nFW Version: {major}.{minor}')
        finally:
            mirkey.finalize()

    def test_bip32_xpub_vect1(self):
        mirkey = self.mirkey
        mirkey.init()
        try:
            self._check_init_ehsm()
            session = mirkey.get_logged_in_rw_session(self.slot, TEST_SU_PW)
            found, handle = mirkey.bip32_has_root_key(session)
            if found:
                mirkey.destroy_object(session, handle)

            # from test vectors defined in https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
            mirkey.bip32_import_root_key(session, binascii.unhexlify("000102030405060708090a0b0c0d0e0f"))
            net = 0x0488B21E # mainnet
            indexes = []
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub,"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")

            indexes = [0x80000000]
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub,"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")

            indexes = [0x80000000, 1]
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub,"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")

            indexes = [0x80000000, 1, 0x80000002]
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub,"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")

            indexes = [0x80000000, 1, 0x80000002, 2]
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub,"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")

            indexes = [0x80000000, 1, 0x80000002, 2, 1000000000]
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub,"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")

            found, handle = mirkey.bip32_has_root_key(session)
            mirkey.destroy_object(session, handle)

        finally:
            mirkey.finalize()

    def test_bip32_xpub_vect2(self):
        mirkey = self.mirkey
        mirkey.init()
        try:
            self._check_init_ehsm()
            session = mirkey.get_logged_in_rw_session(self.slot, TEST_SU_PW)
            found, handle = mirkey.bip32_has_root_key(session)
            if found:
                mirkey.destroy_object(session, handle)

            # from test vectors defined in https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
            net = 0x0488B21E # mainnet
            mirkey.bip32_import_root_key(session, binascii.unhexlify("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))
            indexes = []
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub, "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")

            indexes = [0]
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub, "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")

            indexes = [0, 2147483647 | 0x80000000]
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub, "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a")

            indexes = [0, 2147483647 | 0x80000000, 1]
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub, "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon")

            indexes = [0, 2147483647 | 0x80000000, 1, 2147483646 | 0x80000000]
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub, "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL")

            indexes = [0, 2147483647 | 0x80000000, 1, 2147483646 | 0x80000000, 2]
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub, "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")

            found, handle = mirkey.bip32_has_root_key(session)
            mirkey.destroy_object(session, handle)

        finally:
            mirkey.finalize()

    def test_bip32_xpub_vect3(self):
        mirkey = self.mirkey
        mirkey.init()
        try:
            self._check_init_ehsm()
            session = mirkey.get_logged_in_rw_session(self.slot, TEST_SU_PW)
            found, handle = mirkey.bip32_has_root_key(session)
            if found:
                mirkey.destroy_object(session, handle)

            # from test vectors defined in https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
            net = 0x0488B21E # mainnet
            mirkey.bip32_import_root_key(session, binascii.unhexlify("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"))
            indexes = []
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub,"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")

            indexes = [0x80000000]
            pub = mirkey.bip32_get_xpub(session, indexes, net)
            self.assertEqual(pub,"xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y")

            found, handle = mirkey.bip32_has_root_key(session)
            mirkey.destroy_object(session, handle)

        finally:
            mirkey.finalize()

    def test_btc_import(self):
        mirkey = self.mirkey
        mirkey.init()
        try:
            self._check_init_ehsm()
            session = mirkey.get_logged_in_rw_session(self.slot, TEST_SU_PW)
            found, handle = mirkey.bip32_has_root_key(session)
            if found:
                mirkey.destroy_object(session, handle)

            seed = bytes(64)
            mirkey.bip32_import_root_key(session, seed)
            found, handle = mirkey.bip32_has_root_key(session)
            self.assertTrue(found, "Key not found after import!")
            mirkey.destroy_object(session, handle)
        finally:
            mirkey.finalize()

    def test_btc_sign(self):
        mirkey = self.mirkey
        mirkey.init()
        try:
            self._check_init_ehsm()
            session = mirkey.get_logged_in_rw_session(self.slot, TEST_SU_PW)
            found, handle = mirkey.bip32_has_root_key(session)
            if found:
                mirkey.destroy_object(session, handle)

            mirkey.bip32_import_root_key(session, binascii.unhexlify("000102030405060708090a0b0c0d0e0f"))
            hash = bytes(32)
            indexes = []
            sig = mirkey.bip32_sign_data(session, hash, indexes)
            sighex = binascii.hexlify(sig).decode("utf-8")
            #print("\nsig:"+sighex)
            self.assertEqual(sighex, "3045022100faf92a52783a193c7000ccb665aedf7d1a8981d9de907c057013749e67f4451e02207ee2fd0e13cbf2c6fa0a73b29f42c7cbb124b8874c4b39c9b11dd3c8942de13d")
            found, handle = mirkey.bip32_has_root_key(session)
            mirkey.destroy_object(session, handle)
        finally:
            mirkey.finalize()
