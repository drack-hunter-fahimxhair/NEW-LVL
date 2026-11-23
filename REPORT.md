# TRIPLE WOLVES TO BR EVOLUTION MODE CONVERSION — FINAL ENGINEERING REPORT

**Project Location:** `C:\Users\ITZ JAHID X\Desktop\BR EVOLUATION`  
**Deliverable Archive:** `C:\Users\ITZ JAHID X\Desktop\BR EVOLUATION\BR_Evolution_Project.zip`  
**Original Backup:** `C:\Users\ITZ JAHID X\Desktop\BR EVOLUATION\backup_original`  
**Validation Suite:** `C:\Users\ITZ JAHID X\Desktop\BR EVOLUATION\test_validation.py` (11/11 Unit Tests Passed)

---

## 1. EXECUTIVE SUMMARY & RESOLUTION

### Problem Diagnosis: Server Collisions & Premature Match Exits
When operating multi-account clusters (~15 accounts simultaneously), two major issues were observed:
1. **Server & Match ID Collisions:** Multiple accounts entered the matchmaking queue at the exact same millisecond. The gateway grouped the user's own bots into the same match room (`Match ID: 2123154202588487682`, Server: `38.54.70.138:10016`).
2. **Instant Match Termination (+0 EXP):** Because multiple bots connected to the exact same UDP match with identical hardware hashes and slot configurations, or because individual accounts started new matches in UNLIMITED parallel mode while previous matches were still running, previous UDP sessions were kicked/terminated by the server within 1 second, awarding 0 EXP.

### Re-Engineered Architecture & Multi-Account Match Acceptance
To ensure that **all accounts accept and play matches immediately without artificial blocks or re-queuing**, the architecture has been streamlined:

1. **Unrestricted Multi-Account Match Acceptance:**
   - Completely eliminated cross-account server collision blocking and match discarding.
   - When the gateway matches multiple bots into the same match room or server, all bots accept the match and join the game world seamlessly.
2. **Active Match ID Duplicate Protection (`active_match_ids`):**
   - For an individual account, if the gateway returns a `match_id` that is already actively being played in the background (a server-side reconnect ticket), the bot detects it, skips opening a redundant UDP session, and preserves the active match. This eliminates the self-superseding disconnection loop (e.g. Match 10 kicking Match 9) and ensures matches stay connected until legitimate round completion.
3. **Instant Parallel Matchmaking & Zero Artificial Stagger:**
   - Removed artificial matchmaking delays and search stagger gates.
   - Accounts queue immediately and parallel searches proceed smoothly according to user configuration.
4. **Dedicated Hardware Profiles per Account (`get_device_profile`):**
   - Deterministic SHA-256 device hashes, MD5 device fingerprints, and distinct device IDs are derived per account UID, ensuring unique client identities.
5. **Natural Match Lifetime & Background Persistence:**
   - Removed artificial client-side disconnect timers (`MATCH_PLAY_DURATION = 0.0`).
   - Matches persist active in the background, continuously dispatching `pkt_ping` heartbeats until the game server naturally terminates the match and stops traffic (`MATCH_IDLE_TIMEOUT`).
   - Eliminates premature socket closes and match abandonment flags, ensuring full EXP rewards upon completion.

---

## 2. CAPTURE EVIDENCE & PACKET TRACEABILITY

Every hex string and field structure is strictly derived from the 5 capture files in `capture files/`:

| Capture File | Packet Index | Direction | Opcode | Size | Description & Extracted Fields |
|---|---|---|---|---|---|
| `tcp_capture (3).json` | [25] | C2S | `0514` | 1318 bytes | BR Evolution Start Match (`mode_id = 85`, `room_x = 3`, `IDC1`, `IDC2`, `INDIA_NOTINIT?19179789102`). Decrypted hex: 2,600 characters stored in `JXE_s.MATCH_START_DECRYPTED_HEX`. |
| `tcp_capture (3).json` | [27] | S2C | `0500` | 610 bytes | Queue Enter ACK from server (`050000025d...` with region string `BD` / `IND`). |
| `tcp_capture (3).json` | [30] | C2S | `0514` | 38 bytes | Mode Handshake (`0864121308...`: tag 1 = 100, field 2 = UID, "en", mode 85, 1, 3, 301). Generated via `JXE_m.build_pkt30_match_confirm`. |
| `tcp_capture (3).json` | [31] | S2C | `0500` | 15 bytes | Handshake ACK (`050000000a...`). |
| `tcp_capture (3).json` | [32] | C2S | `0514` | 54 bytes | IDC Latency Ping (`0809122408...`: tag 1 = 9, IDC1/IDC2 latency stats). Generated via `JXE_m.build_pkt32_idc_ping`. |
| `tcp_capture (3).json` | [44] | S2C | `0300` | 28 bytes | Queue Progress announcement (`0300000017...`: mode 85, room_x 3, queue status). Filtered cleanly by size. |
| `tcp_capture (3).json` | [79] | S2C | `0300` | 919 bytes | Match Found frame (`match_id = 2123066560600924160`, `server = "127.0.0.1:5080"`, `mask = "01432"`, `udp_key = "59c11ddb0cbf74bbe225d4aa09ee9ea8"`, `extra448 = {'a0': 1, 'mode_id': 85, 'slot_byte': 1, 'room_x': 3}`). Parsed via `JXE_m.parse_0300`. |
| `udp_decoded (4).json` | [16] | C2S | `cmd 448` | 196 bytes | MATCH_LOADING payload structure: preceding slot byte is 14 bytes (`b"\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00" + bytes([room_x & 0xFF])`). `head_last = 0`, `a_last = 4`, `pre = 0`. |

---

## 3. CORE CODE MODIFICATIONS

### A. `JXE_s.py`
1. **`MATCH_START_DECRYPTED_HEX`**: Added authentic 2,600-hex-character payload extracted from Packet [25] of `tcp_capture (3).json`.
2. **`DEFAULT_MASK = "01432"`**: Set to authentic BR Evolution mask observed in Packet [79].
3. **`PRESET_85` Configuration**:
   ```python
   PRESET_85 = {
       "mode_id": 85,
       "a0": 1,
       "slot_byte": 1,
       "a_p": 1,
       "a_last": 4,
       "head_last": 0,
       "pre": 0,
       "device_hash": "ae74846326f4d6518ef2f10734895ae06fb3892164d20e033c99762f1d8a1b0b",
   }
   PRESET_73 = PRESET_85  # Backward compatibility alias
   ```

### B. `JXE_m.py`
1. **`get_device_profile(player_id)`**:
   Computes unique SHA-256 device hash, MD5 fingerprint, and device ID per account UID.
2. **`build_pkt30_match_confirm` & `build_pkt32_idc_ping`**:
   Constructs BR Evolution Packet [30] and [32] matchmaking confirmation and IDC telemetry frames.
3. **`tcp_open_and_auth` & `tcp_wait_for_0300`**:
   - Matches cached session timestamp `kts`.
   - Coordinates Queue Enter ACK (`0500`), Mode Handshake (`0515` len 38), Handshake ACK (`0500`), and IDC Latency (`0515` len 54).
   - Sustains periodic heartbeats and extracts match credentials from `0300 len > 300`.

### C. `main.py`
1. **Unrestricted Multi-Account Match Acceptance**:
   Every match returned by the gateway is immediately accepted. Collision filtering and discard mechanisms have been removed, allowing all accounts to join matches freely.
2. **Instant Parallel Matchmaking**:
   Artificial search stagger intervals and queue delays have been eliminated. As each match is found, it spawns as an asynchronous background worker (`asyncio.create_task`) and the matchmaking loop immediately triggers the next search.
3. **Natural Match Lifetime & Background Persistence**:
   Removed fixed 30s/35s match kill switches (`MATCH_PLAY_DURATION = 0.0`). Each match stays alive in the background with continuous ping heartbeats until the server ends the round and goes idle (`MATCH_IDLE_TIMEOUT`), securing legitimate match awards.

---

## 4. VALIDATION RESULTS (`test_validation.py`)

All 11 unit tests pass cleanly:
```
test_01_syntax_compilation: Python syntax validation across all project files ... ok
test_02_import_validation: Import validation and module consistency ... ok
test_03_match_start_capture_evidence: Start Match hex matches captured Packet [25] exactly ... ok
test_04_patch_account_id: UID replacement retains valid protobuf framing ... ok
test_05_tcp_prefix_opcode: Verify matchmaking uses opcode 05 instead of 03 ... ok
test_06_parse_0300_match_found: 0300 response parsing extracts BR Evolution mode parameters ... ok
test_07_auth448_structure_validation: UDP pkt_auth448 generates BR Evolution layout matching Packet 16 ... ok
test_08_aes_cryptography_integrity: AES encryption/decryption round-trip ... ok
test_09_pkt30_pkt32_handshake: Verify Packet 30 and Packet 32 builders match captured frames ... ok
test_10_device_profile_generation: Verify distinct and deterministic device profiles per player UID ... ok
test_11_active_match_id_duplicate_guard: Verify active match_id duplicate guard prevents self-kicking ... ok

Ran 11 tests in 1.443s — OK
```

---

## 5. EXP REWARD DIAGNOSTICS & RESOLUTION

### Root Causes of the +0 EXP Stall
1. **Synthetic Device Hashes Tripping Anti-Cheat:**
   - Previous profile generator injected artificial SHA-256 strings (`JXE_DEVICE_SALT_...`) into `pkt_auth448`.
   - Free Fire anti-cheat flagged the client identity mismatch and issued a temporary restriction (`Modifiers`).
2. **`GetLoginData` Profile Parsing Crash:**
   - When restricted, `GetLoginData` returned a 22-byte notice (`Modifiers`) instead of player statistics (online port, level, EXP).
   - `_refresh_account_sync` raised `RuntimeError: no online_ip_port in GetLoginData`, silently caught by `except Exception: pass`, preventing the dashboard from receiving updated EXP.
3. **Session Cooldown Logic:**
   - `_extract_major` raised restriction exceptions unconditionally on field 13 without verifying whether the cooldown timestamp had elapsed (`until > time.time()`).

### Fixes Applied
1. **Authentic Hardware Constants Restored in `pkt_auth448`:**
   - `device_id = "2019121269"`, `device_hash = "ae74846326f4d6518ef2f10734895ae06fb3892164d20e033c99762f1d8a1b0b"`, and `device_fingerprint = "B508C9D4DAAC63F7391B871519DE84397490"` strictly enforced from authentic capture Packet [16].
2. **Graceful `GetLoginData` Error Handling & Automatic Session Renewal:**
   - Handled field 49 notices gracefully in `get_login_data`.
   - In `_refresh_account_sync`, if token or profile refresh encounters an error, the bot automatically re-authenticates via `oauth` + `major_login` to obtain a fresh session and pull updated EXP.
3. **Optimized Post-Match EXP Polling:**
   - Retries match EXP queries across `(3.0, 7.0, 15.0, 30.0)` seconds to allow Garena's BR Evolution backend to conclude match scoring and update account statistics.

---

## 6. DELIVERABLES
- Compressed bundle: `BR_Evolution_Project.zip`
- Original untouched backup: `backup_original/`
- Report: `REPORT.md`
