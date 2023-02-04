rule ESXiArgs_Ransomware_72633_00001 {
   meta:
      description = "Detects ESXiArgs variants by internal strings"
      author = "Emanuele De Lucia"
      date = "2023-02-04"
      hash1 = "11b1b2375d9d840912cfd1f0d0d04d93ed0cddb0ae4ddb550a5b62cd044d6b66"
	  score = 100
   strings:
      $ = "[ %s ] - FAIL" fullword ascii
      $ = "get_pk_data: key file is empty!" fullword ascii
      $ = "lPEM_read_bio_RSAPrivateKey" fullword ascii
      $ = "lRSA_public_encrypt" fullword ascii
	  $ = "usage: encrypt <public_key> <file_to_encrypt> [<enc_step>] [<enc_size>] [<file_size>]" fullword ascii
   condition:
      uint16(0) == 0x457f and 
	  filesize < 100KB and
      all of them
}
