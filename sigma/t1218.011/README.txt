T1218.011

Adversaries may abuse rundll32.exe to proxy execution of malicious code. 
Using rundll32.exe, vice executing directly (i.e. Shared Modules), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations.
Rundll32.exe is commonly associated with executing DLL payloads (ex: rundll32.exe {DLLname, DLLfunction}).

Source: MITRE ATT&CK
