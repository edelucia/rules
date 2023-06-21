rule TriangleDB_SpyWare_98345_00001 {
   meta:
      description = "Detects TriangleDB variants by internal strings"
      author = "Emanuele De Lucia"
      reference = "https://securelist.com/triangledb-triangulation-implant/110050/"
      date = "2023-06-21"
      hash1 = "fd9e97cfb55f9cfb5d3e1388f712edd952d902f23a583826ebe55e9e322f730f"
	  score = 100
   strings:
      $ = "unmungeHexString:" 
      $ = "getCInfoForDump" 
      $ = "encryptData:withCompression:errorCode:" 
      $ = "CRXBlank" 
	  $ = "CRXQuery"
   condition:
      uint16(0) == 0xfacf and 
	  filesize < 2000KB and
      all of them
}
