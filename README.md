MCEDP HoneyClient
MCEDP is a High Interaction Client Honeypot. Despite other High-Interaction honeyClients which detect malicious servers based on system changes (file system and registery modifications, invoked/killed processes, …), MCEDP uses a new approach. To accomplish this, MCEDP uses exploit detection methods to detect drive-by downloads at exploitation stage and dump malware file. Using this approach, MCEDP eliminates some limitations of current HoneyClients and improves the detection speed of High-Interaction client Honeypots. Some of the methods used in MCEDP have been first implemented in MS EMET.

  Features
Some of MCEDP features are:

-No System Infection
-Exploit detection without any signature
-Detecting 0-Day exploits
-Detecting shellcodes
-Dumping shellcodes
-Dynamic Analysis of Shellcode
-Detecting ROP
-Detecting ROP module and key ROP function
-Dumping ROP
-Dumping Malware

  Supported Programs
MCEDP developed to generally work on Windows XP, Vista and 7 and can detect exploits written for softwares like :

-IE 6,7,8,9
-Firefox
-MS Office Products
-Adobe Acrobat Reader
-Adobe Flash
-and …
Most of MCEDP tests were performed on Windows 7 and IE 8, 9. At this release MCEDP use Stack Pointer Monitoring method to detect ROP but in near future I will add some methods which has been introduced in MS Blue hat Contest. In addition MCEDP has some general protections like Permanent DEP, activating this feature may let you detect and test more complicated and advanced exploits (for example by activating Heap Spray Protection you can find out whether the exploit use memory leakage to get Shellcode and ROP address or not).

  Known Weaknesses
One of fundamental weakness of this type of programs is being bypassed! Attackers can use some methods (which has not been seen in the wild yet!) to bypass Shellcode and ROP detector modules. Currently I’m aware of most of these bypassing methods and I’m going to fix them in near future. Another problem is Java Sandbox Escape exploits. This kind of exploits are often logical and do not use any kind of memory corruption or legacy Shellcodes. Because MCEDP is designed base on memory corruption issues and Shellcode execution, it can’t detect this type of Java exploits yet!

  Future Plans
-Adding some more methods for detecting Shellcodes and ROPs
-Resolving weaknesses in order to prevent  MCEDP bypass methods
-Detecting Java Logical Exploits ( and other types of logical vulnerabilities )
-Making a Web service to communicate remotely with the Honeypot
-Making a web based UI
-and …
It’s the first beta version of MCEDP and its manager (for feeding input [URL] to honeypot) isn’t complete yet. Currently MCEDP does not work automatically on Windows XP-IE6, and you have to manually inject it in IE after it started (I think this might be caused by AppInitDLL and MCEDP dll dependencies).

Your opinion means a great deal to us; Please let me know your ideas about this project to help me improve it in the future.