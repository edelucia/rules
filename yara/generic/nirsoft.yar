/*
    This rule detects software released by NirSfot via Copyright in file information;
    NirSoft software can be abused by threat actor for network-scanning and credential-dumping tasks (ChromePass,DialupPass,MailPassView,NetRouteView etc.etc.);
    falsepositives: legitimate use of NirSoft softwares;
*/

rule NirSoft_Software_82733_00001 {
meta:
author = "Emanuele De Lucia"
tlp = "white"
description = "Detects software released by Nir Sofer via Copyright"
level = "medium"
strings:
$mz = {4d5a}
$cr = /Copyright \xA9 [0-9]{4} - [0-9]{4} Nir Sofer/ wide
condition: $mz at 0 and $cr 
}
