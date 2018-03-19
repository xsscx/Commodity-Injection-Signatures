This Repo is pulled together from most of the Public Repo's for XXE, XML, MSLT Injection. 
===============

All the windows specific injections and errors are based on working with Burp Repeater.

Comments: 

You've found an XXE/XML/XSLT Injection Bug on a Windows MSXML Parser and/or Browser and you're looking for PoC and Details... 

XXE/XML/XSLT Injection on Windows is often a low-priority Bug, similar to XSS. You want to escalte, but, how?

You can usually demonstrate SSRF, but, whats the Risk? (Not much).

You can echo back CDATA and XSS the Client, and demonstrate that Risk, but what about the MSXML Parser?

You're going to be disappointed unless you find a misconfiguration allowing for C# processing and/or weak file system permissions.

This Repository does provide verified injection signatures, but you need to massage all the parameters by hand.

My advice on demonstrating Risk for XXE on Windows is to provide a simple PoC demonstrating you control the CPU for 2 > 4 seconds of DoS.

Fuzzing out the Directory and File Structure creates alot of Noise. 

Know what you are looking for in advance and be prepared to Exfiltrate with 1 GET/POST.

Reminder: MSXML3,4 is EoL and insecure by Default. MSXML6 is slightly-secure by Default. 

Your Mileage May Vary



