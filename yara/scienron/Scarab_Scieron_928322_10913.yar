rule Scarab_Scieron_928322_10913 {   
       meta:   
           author = "Emanuele De Lucia"
           tlp = "white"
           hash1 = "7d905bedc48554a23c4630bf5163803488ac3f650082c728dc60a6724b2bb331"		   
       strings: 
	    /*
		0x10001a40L 0FB708                        movzx ecx, word ptr [eax]
		0x10001a43L 6683F92C                      cmp cx, 0x2c
		0x10001a47L 740C                          je 0x10001a55
		0x10001a49L 6683F93B                      cmp cx, 0x3b
		0x10001a4dL 7406                          je 0x10001a55
		0x10001a4fL 6683F97C                      cmp cx, 0x7c
		0x10001a53L 7505                          jne 0x10001a5a
		0x10001a55L 33C9                          xor ecx, ecx
		0x10001a57L 668908                        mov word ptr [eax], cx
		*/
        $mz =  { 4d 5a }	   
        $hex = { 0f b7 08 66 83 f9 2c 74 0c 66 83 f9 3b 74 06 66 83 f9 7c 75 05 33 c9 66 89 08 }
	condition: ($mz at 0 and $hex)
}
