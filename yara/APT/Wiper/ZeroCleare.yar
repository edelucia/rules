rule APT_ZeroCleare_87211_00387 {
   meta:
      description = "Detects ZeroCleare wiper variants by internal strings"
      author = "Emanuele De Lucia"
	  tlp = "white"
      hash1 = "d8ec8ec8dfa582c44e81b8a7fcc44defc3d2fa658f75fa495124aedc3b0db367"
      hash2 = "e1204ebbd8f15dbf5f2e41dddc5337e3182fc4daf75b05acc948b8b965480ca0"
   strings:
      $ = "SOFTWARE\\EldoS\\EventLog" fullword wide
      $ = ".?AVERDError@@" fullword ascii
      $ = "RawDisk3" fullword wide
      $ = "\\\\?\\RawDisk3" fullword wide
      $ = " delete[]" fullword ascii
      $ = "###RawDisk3AMD64###" fullword ascii
   condition:
      uint16(0) == 0x5a4d and 
	  filesize < 300KB and
	  all of them
}
