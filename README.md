MCEDP is a Client side High Interaction Honeypot.Goals of this HoneyClient are improving existing HI Client honeypots fundamental feathers and also eliminating their limits! Some of the methods used in MCEDP are first known to be implemented in MS EMET.

Feathers
Some of MCEDP feathers are:
�	No System Infection
�	Exploit detection without any signature
�	Detecting 0Day exploits
�	Detecting shellcodes
�	Dumping shellcodes
�	Dynamic Analysis of Shellcode
�	Detecting ROP
�	Detecting ROP module and key ROP function
�	Dumping ROP
�	Dumping Malware
�	and ...

Supported Programs
MCEDP developed to generally work on Windows XP, Vista and 7 and can detect exploit written for software�s like :
�	IE 6,7,8,9
�	Firefox
�	MS Office Products
�	Adobe Acrobat Reader
�	Adobe Flash 
�	and ...

Most of MCEDP tests were performed on Windows 7 and IE 8, 9. at this release MCEDP use Stack Pointer Monitoring method to detect ROP but in near future I will add some methods which has been introduced in MS Blue hat Contest [1].In addition MCEDP has some general protections like Permanent DEP, activating this feather may let you detect and test more complicated and advanced exploits (for example by activating Heap Spray Protection you can find out whether the exploit use memory leakage to get Shellcode and ROP address or not).

Known Weaknesses
One of fundamental weakness of this type of programs is being bypassed! Attackers can use some methods (which has not been seen in the wild yet!) to bypass Shellcode and ROP detector modules. Currently I'm aware of most of these bypassing methods [2] and I'm going to fix them in near future. Another problem is Java Sandbox Escape exploits, this kind of exploits are often logical and do not use any kind of memory corruption or legacy Shellcodes. Because MCEDP is designed base on memory corruption issues and Shellcode execution, it can�t detect this type of Java exploits yet!

Future Plans
�	Adding some more methods for detecting Shellcodes and ROPs
�	Resolving weaknesses in order to prevent  MCEDP bypass methods
�	Detecting Java Logical Exploits ( and other types of logical vulnerabilities )
�	Making a Web service to communicating remotely with the Honeypot
�	Making a web based UI
�	and ...

Currently MCEDP does not work automatically on Windows XP-IE6, and you have to manually inject it in IE after it started (I think this might be caused by AppInitDLL and MCEDP dll dependencies).

Your opinion means great deal to us; Please let me know your ideas about this project to help me improve it in future.

-Shahriyar Jalayeri ( Shahriyar.j {at} gmail {dot}  com )
twitter.com/ponez

-----

[1] http://www.microsoft.com/security/bluehatprize/
[2] http://threatpost.com/en_us/blogs/researcher-finds-technique-bypass-microsofts-emet-protections-080912

