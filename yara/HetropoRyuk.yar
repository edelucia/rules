rule HetropoRyuk_Ransomware_827322_00001 {
   meta:
      description = "Detects Hetropo Ryuk .Net variants"
      author = "Emanuele De Lucia"
      hash1 = "ad8cbada036d76a3c003c19d56ec611db24fb9ef1ed51a1e18fae13683a6fbab"
	  tlp = "white"
   strings:
      $ = "Coinmama - hxxps://www.coinmama.com Bitpanda - hxxps://www.bitpanda.com" fullword wide 
	  $ = "All of your files have been encrypted" fullword wide
      $ = "appMutex" fullword ascii 
      $ = "read_it.txt" fullword wide  
      $ = "How do I pay, where do I get Bitcoin?" fullword wide 
   condition: uint16(0) == 0x5a4d and all of them
}
