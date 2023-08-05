rule DarkGate_Loader_87233_00090 {
meta:
author = "Emanuele De Lucia"
description = "Detects DarkGate loader by strings decryption routine"
hash1 = "efe4dd6e9ec7f3d60a456a863d47a1624ca5354bd37f8a3a7c7a4dd4f68596f4"
hash2 = "da05617eded07cec14d283b73336c4582b4e812c99c81da14c06f28d7432e0f9"
hash3 = "4c84b3f2be74644fa8157b93471586fdaaaeab18a3b2732663e08ce7c12e20c6"
hash4 = "e7b76e11101e35c46a7199851f82c69e819a3d856f6f68fa3af0636c3efde0ca"
hash5 = "1a94ea3a5b595fa4758ab0e4a3a70a43631439d79d3e94f5f539b00b64d2a1e6"
score = 80
strings:
$hex = { 55 8B EC 83 C4 ?? 53 56 57 33 C9 89 4D ?? 89 55 ?? 89 45 ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 ?? E8 ?? ?? ?? ?? 8B D0 8B 45 ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? BF ?? ?? ?? ?? 8D 5D ?? 8B 45 ?? E8 ?? ?? ?? ?? 3B F0 7E ?? C6 03 ?? EB ?? 8D 45 ?? 8B 55 ?? 8A 54 32 ?? E8 ?? ?? ?? ?? 8B 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 7D ?? C7 45 ?? ?? ?? ?? ?? 8A 45 ?? 48 88 03 46 43 4F 75 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? 8A 4D ?? 80 E1 ?? C1 E1 ?? 8A 5D ?? 80 E3 ?? 81 E3 ?? ?? ?? ?? C1 EB ?? 02 CB 88 4C 10 ?? FF 45 ?? 80 7D ?? ?? 74 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? 8A 4D ?? 80 E1 ?? C1 E1 ?? 8A 5D ?? 80 E3 ?? 81 E3 ?? ?? ?? ?? C1 EB ?? 02 CB 88 4C 10 ?? FF 45 ?? 80 7D ?? ?? 74 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? 8A 4D ?? 80 E1 ?? C1 E1 ?? 8A 5D ?? 80 E3 ?? 02 CB 88 4C 10 ?? FF 45 ?? 8B 45 ?? E8 ?? ?? ?? ?? 3B F0 0F 8E ?? ?? ?? ?? FF 4D ?? 8B 45 ?? 8B 55 ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 5F 5E 5B 8B E5 5D C3 }
condition:
$hex
}
