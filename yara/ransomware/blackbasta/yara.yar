rule BlackBasta_Ransomware_82733_00018 : eCRIME THREAT GROUP {
   meta:
      description = "Detects BlackBasta Ransomware payloads by common strings"
      author = "Emanuele De Lucia"
      hash1 = "ae7c868713e1d02b4db60128c651eb1e3f6a33c02544cc4cb57c3aa6c6581b6e"
      hash2 = "7883f01096db9bcf090c2317749b6873036c27ba92451b212b8645770e1f0b8a"
      hash3 = "5b6c3d277711d9f847be59b16fd08390fc07d3b27c7c6804e2170f456e9f1173"
   strings:
      $ = "Input is not valid base64-encoded data." fullword ascii
      $ = "(you should download and install TOR browser first https://torproject.org)" fullword ascii
      $ = "Done time: %.4f seconds, encrypted: %.4f gb" fullword ascii
      $ = "operator<=>" fullword ascii
      $ = ".data$rs" fullword ascii
      $ = "https://aazsbsgya565vlu2c6bzy6yfiebkcbtvvcytvolt33s77xypi7nypxyd.onion:80/" fullword ascii
      $ = "Error 755: " fullword ascii
      $ = "mpz_import: Nails not supported." fullword ascii
   condition: (uint16(0) == 0x5a4d and ( 6 of them ))
}
