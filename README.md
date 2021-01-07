# CVEs
## Background
Below is a list of CVEs I've found, reported to teh vendor and checked they are fixed.

# CVE Table
|CVE                                        |Product       |Component     |Bug Type(s)                                                    |Effect         |Brief Description|
|---                                        |---           |---           |---                                                            |---            |---|
|[CVE-2017-16549](CVE-2017-16549/readme.md) | K7 Antivirus | k7sentry.sys |CWE-120:<br>Buffer Copy without Checking Size of Input         |BSOD           |DeviceIoControl: Output buffer written to without checking length
|[CVE-2017-16550](CVE-2017-16550/readme.md)	| K7 Antivirus | k7sentry.sys |CWE-120:<br>Buffer Copy without Checking Size of Input         |BSOD           |DeviceIoControl: Output buffer written to without checking length
|[CVE-2017-16551](CVE-2017-16551/readme.md)	| K7 Antivirus | k7sentry.sys |Logical Flaw                                                   |LPE            |User Mode MEDIUM Integrity to Kernel Mode LPE
|[CVE-2017-16552](CVE-2017-16552/readme.md) | K7 Antivirus | k7sentry.sys |CWE-120:<br>Buffer Copy without Checking Size of Input         |BSOD           |DeviceIoControl: Output buffer written to without checking length
|[CVE-2017-16553](CVE-2017-16553/readme.md)	| K7 Antivirus | k7sentry.sys |LLogicalogic Flaw|LPE|User Mode MEDIUM Integrity to Kernel Mode LPE
|[CVE-2017-16554](CVE-2017-16554/readme.md)	| K7 Antivirus | k7sentry.sys |CWE-120:<br>Buffer Copy without Checking Size of Input         |BSOD           |DeviceIoControl: Output buffer written to without checking length
|[CVE-2017-16555](CVE-2017-16555/readme.md)	| K7 Antivirus | k7sentry.sys |Logical Flaw                                                   |LPE            |User Mode MEDIUM Integrity to Kernel Mode LPE
|[CVE-2017-16556](CVE-2017-16556/readme.md) | K7 Antivirus | k7sentry.sys |CWE-242:<br>Use of Inherently Dangerous Function               |               |Heap Overflow due to unsafe string handling routines
|[CVE-2017-16557](CVE-2017-16557/readme.md)	| K7 Antivirus | k7sentry.sys |Logical Flaw                                                   |LPE            |User Mode MEDIUM Integrity to Kernel Mode LPE
|[CVE-2017-17429](CVE-2017-17429/readme.md) | K7 Antivirus | k7sentry.sys |CWE-782:<br>Exposed IOCTL with Insufficient Access Control     |Confidentiality Bypass|Raw disk access reading from LOW Integrity 
|[CVE-2018-8044](CVE-2018-8044/readme.md)	| K7 Antivirus | k7sentry.sys |CWE-367:<br>TOCTOU                                             |LPE            |UM HIGH Integrity to Kernel Mode
|[CVE-2018-8724](CVE-2018-8724/readme.md)   | K7 Antivirus | K7TSMngr.exe |Logical Flaw|LPE|Arbitary process creation with a SYSTEM account from LOW 
|[CVE-2018-8725](CVE-2018-8725/readme.md)	| K7 Antivirus | K7TSMngr.exe |CWE-122:<br>Heap-based Buffer Overflow                                         ||Heap Overflow in the pipe handler
|[CVE-2018-8726](CVE-2018-8726/readme.md)	| K7 Antivirus | K7TSMngr.exe |CWE-121:<br>Stack-based Buffer Overflow                        |               |Stack Overflow due a call to *wsprintfA* without validating all the strings.
|[CVE-2018-9332](CVE-2018-9332/readme.md)	| K7 Antivirus | K7TSMngr.exe |CWE-306:<Br>Missing Authentication for Critical Function       |LPE            |Logical Flaw: Registry Modification, allowing a LOW to SYSTEM privilege escallation
|[CVE-2018-9333](CVE-2018-9333/readme.md)	| K7 Antivirus | K7TSMngr.exe |CWE-122:<Br>Heap-based Buffer Overflow                         |               |Multiple heap buffer overflows due to issues with string parsing.
|[CVE-2018-11005](CVE-2018-11005/readme.md)	| K7 Antivirus | K7TSMngr.exe |CWE-126:<Br>Buffer Over-Read                                   |Crash Service  |Out of bounds read, DoS
|[CVE-2018-11006](CVE-2018-11006/readme.md)	| K7 Antivirus | K7TSMngr.exe |Logical Flaw                                                   |LPE            |LOW integirty process can get a SYSTEM service to perform arbitary file copy.
|[CVE-2018-11007](CVE-2018-11007/readme.md)	| K7 Antivirus | K7TSMngr.exe |CWE-121:<br>Stack-based Buffer Overflow                        |Crash Service  |Infinite recursion of function, consuming all stack, leading to DoS
|[CVE-2018-11008](CVE-2018-11008/readme.md)	| K7 Antivirus | K7TSMngr.exe |Logical Flaw                                                   |LPE            |Arbitary registry value setting at SYSTEM from LOW
|[CVE-2018-11009](CVE-2018-11009/readme.md)	| K7 Antivirus | K7TSMngr.exe |CWE-122:<br>Heap-based Buffer Overflow                         |               |Heap Buffer Overflow due to wsprintfW being used
|[CVE-2018-11010](CVE-2018-11010/readme.md)	| K7 Antivirus | K7TSMngr.exe |CWE-122:<br>Heap-based Buffer Overflow                         |               |Heap Buffer Overflow due to wsprintfA being used
|[CVE-2018-11246](CVE-2018-11246/readme.md) | K7 Antivirus | K7TSMngr.exe |CWE-126:<Br>Buffer Over-Read                                   |               |Arbitary memory disclosure to windows registry

## K7 Security Note
For the issues sent to K7 security, they were professional and quickly provided a secure communication channel to one of their Senior Software Architects to resolve the vulnerabilities in their product, actively engaging to remove the vulnerabilities.
