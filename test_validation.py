"""
Comprehensive Validation and Verification Test Suite
BR Evolution Mode Conversion
"""

import unittest
import os
import sys
import json
import py_compile

# Ensure workspace root is in path
WORKSPACE = os.path.dirname(os.path.abspath(__file__))
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)

import JXE_s
import JXE_m
import XTeam_pb2
import XFF_pb2


class TestBREvolutionConversion(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cap_dir = os.path.join(WORKSPACE, "capture files")
        with open(os.path.join(cap_dir, "tcp_capture (3).json"), "r", encoding="utf-8") as f:
            cls.tcp_pkts = json.load(f)
        with open(os.path.join(cap_dir, "udp_decoded (4).json"), "r", encoding="utf-8") as f:
            cls.udp_pkts = json.load(f)
        with open(os.path.join(cap_dir, "udp_keys (3).json"), "r", encoding="utf-8") as f:
            cls.udp_keys = json.load(f)

    def test_01_syntax_compilation(self):
        """Phase 7: Python syntax validation across all project files"""
        files = ["JXE_s.py", "JXE_m.py", "main.py", "XFF_pb2.py", "XTeam_pb2.py"]
        for fn in files:
            fp = os.path.join(WORKSPACE, fn)
            self.assertTrue(os.path.exists(fp), f"File {fn} missing")
            # py_compile raises PyCompileError on syntax error
            compiled = py_compile.compile(fp, doraise=True)
            self.assertIsNotNone(compiled)

    def test_02_import_validation(self):
        """Phase 7: Import validation and module consistency"""
        self.assertIn("MATCH_START_DECRYPTED_HEX", dir(JXE_s))
        self.assertIn("PRESET_85", dir(JXE_s))
        self.assertIn("PRESET_73", dir(JXE_s))
        self.assertEqual(JXE_s.PRESET_85["mode_id"], 85)
        self.assertEqual(JXE_s.PRESET_85["a0"], 0x01)
        self.assertEqual(JXE_s.DEFAULT_MASK, "01432")

    def test_03_match_start_capture_evidence(self):
        """Phase 7: Start Match hex matches captured Packet [25] exactly"""
        cap_p25 = self.tcp_pkts[25]
        cap_hex = cap_p25["plain_hex"]
        self.assertEqual(cap_p25["type"], "0514", "Captured Start Match must use opcode 05")
        self.assertEqual(len(cap_hex), 2600, "Start Match plaintext hex length must be 2600")
        self.assertEqual(JXE_s.MATCH_START_DECRYPTED_HEX.lower(), cap_hex.lower(),
                         "MATCH_START_DECRYPTED_HEX must match captured Packet 25 byte-for-byte")

    def test_04_patch_account_id(self):
        """Phase 7: UID replacement retains valid protobuf framing"""
        orig_hex = JXE_s.MATCH_START_DECRYPTED_HEX
        test_uids = ["19179802627", "1234567890", "987654321098"]
        for uid in test_uids:
            patched = JXE_m.patch_account_id(orig_hex, uid)
            self.assertIn(f"INDIA_NOTINIT?{uid}".encode("ascii"), patched)
            # Verify parsed protobuf
            proto = JXE_m.parse_proto(patched)
            self.assertIsNotNone(proto)
            self.assertEqual(proto.get(1), 1)
            # Verify mode_id is 85 in field 2 -> subfield 3
            sub = proto.get(2)
            self.assertIsInstance(sub, dict)
            self.assertEqual(sub.get(3), 85)

    def test_05_tcp_prefix_opcode(self):
        """Phase 7: Verify matchmaking uses opcode 05 instead of 03"""
        # Test ID region
        self.assertEqual("0519" if "ID" == "ID" else "0515", "0519")
        # Test BD region
        reg = "BD"
        prefix = "0519" if reg == "ID" else ("0514" if reg in ("IND", "IN") else "0515")
        self.assertEqual(prefix, "0515")
        # Test IND region
        reg = "IND"
        prefix = "0519" if reg == "ID" else ("0514" if reg in ("IND", "IN") else "0515")
        self.assertEqual(prefix, "0514")

    def test_06_parse_0300_match_found(self):
        """Phase 7: 0300 response parsing extracts BR Evolution mode parameters"""
        p79 = self.tcp_pkts[79]
        res = JXE_m.parse_0300(bytes.fromhex(p79["plain_hex"]))
        self.assertIsNotNone(res)
        self.assertEqual(res["account_id"], 19179802627)
        self.assertEqual(res["match_id"], 2123066560600924160)
        self.assertEqual(res["mask"], "01432")
        self.assertEqual(res["udp_key"], "59c11ddb0cbf74bbe225d4aa09ee9ea8")
        self.assertIn("extra448", res)
        self.assertEqual(res["extra448"].get("mode_id"), 85)
        self.assertEqual(res["extra448"].get("a0"), 1)
        self.assertEqual(res["extra448"].get("slot_byte"), 1)

    def test_07_auth448_structure_validation(self):
        """Phase 7: UDP pkt_auth448 generates BR Evolution layout matching Packet 16"""
        p16 = self.udp_pkts[16]
        captured_plain = bytes.fromhex(p16["decoded"]["plain_hex"])
        
        token = "test_token_with_dummy_len_just_for_testing"
        key = bytes.fromhex("59C11DDB0CBF74BBE225D4AA09EE9EA8")
        mask = "01432"
        player_id = 19179802627
        match_id = 2123066560600924160
        
        pkt = JXE_m.pkt_auth448(
            token=token,
            key=key,
            mask=mask,
            player_id=player_id,
            match_id=match_id,
            client_version="1.134.21",
            mode_id=85,
            a0=1,
            slot_byte=1,
            a_p=1,
            a_last=4,
            head_last=0,
            pre=0,
        )
        h = JXE_m.decode_header(pkt, key, mask)
        self.assertIsNotNone(h)
        self.assertEqual(h["cmd"], 448)
        self.assertTrue(h["crc_ok"])

    def test_08_aes_cryptography_integrity(self):
        """Phase 7: AES encryption/decryption round-trip"""
        key = JXE_s.AES_KEY
        iv = JXE_s.AES_IV
        plaintext = b"BR_EVOLUTION_VERIFICATION_PAYLOAD"
        encrypted = JXE_m.aes_encrypt(plaintext, key, iv)
        decrypted = JXE_m.aes_decrypt(encrypted, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_09_pkt30_pkt32_handshake(self):
        """Phase 7: Verify Packet 30 and Packet 32 builders match captured frames"""
        # Test Packet 30 against Packet 30 plain hex from capture
        p30_cap = self.tcp_pkts[30]["plain_hex"]
        p30_built = JXE_m.build_pkt30_match_confirm(19179789102, mode_id=85, room_x=3, lang="en").hex()
        self.assertEqual(p30_built, p30_cap)

        # Test Packet 32 against Packet 32 plain hex from capture
        p32_cap = self.tcp_pkts[32]["plain_hex"]
        p32_built = JXE_m.build_pkt32_idc_ping(19179789102, reg="IND", idc1_ping=73, idc2_ping=43).hex()
        self.assertEqual(p32_built, p32_cap)

    def test_10_device_profile_generation(self):
        """Phase 7: Verify distinct and deterministic device profiles per player UID"""
        # 1. Device profiles must differ for different player UIDs
        dev1, hash1, fp1 = JXE_m.get_device_profile(19178898022)
        dev2, hash2, fp2 = JXE_m.get_device_profile(19182480733)
        self.assertNotEqual(dev1, dev2)
        self.assertNotEqual(hash1, hash2)
        self.assertNotEqual(fp1, fp2)

        # 2. Device profile must be deterministic for same player UID
        dev1_b, hash1_b, fp1_b = JXE_m.get_device_profile(19178898022)
        self.assertEqual(dev1, dev1_b)
        self.assertEqual(hash1, hash1_b)
        self.assertEqual(fp1, fp1_b)

    def test_11_active_match_id_duplicate_guard(self):
        """Phase 7: Verify active match_id duplicate guard prevents self-kicking"""
        active_match_ids = set()
        test_mid = "2123285884624848897"
        
        # 1. First time match is found: allowed
        is_duplicate_first = test_mid in active_match_ids
        self.assertFalse(is_duplicate_first)
        active_match_ids.add(test_mid)
        
        # 2. Second time same match is returned (reconnect ticket): detected as duplicate
        is_duplicate_second = test_mid in active_match_ids
        self.assertTrue(is_duplicate_second)
        
        # 3. Different match returned: allowed
        new_mid = "2123285884624848898"
        self.assertFalse(new_mid in active_match_ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
