T1574.012 - COR_PROFILER

Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. 
The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). 
These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.

Source: https://attack.mitre.org/
