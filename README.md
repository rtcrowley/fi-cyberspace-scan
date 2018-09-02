# FI Cyberspace Scan

Local File Inclusion CLI tool written in Python to speed up LFI checks. Similar to using Burp or ZAP, but less bulky and resource intensive. Plus it's in color for easy readability. File lists are included in the app, ranging from basic to verbose. Set different **Cyber-Attack Modes**, unique **Encoded Path Types** or turn on **Deep Directory Traversal** or **NULL Bytes**.

Valid LFI results are based on HTTP response codes, then HTTP response sizes. A non-200 will result in a failure, then a reflected byte size different from a pre-tested baseline will result in a valid find. Valid finds will be displayed in terminal output.

Before executing the attack, you'll be prompted with the set parameters, then can either confirm & execute OR exit the program. All parameters are preset besides **Target**. Adding these flags will update the set parameters, prior to execution.

___

## Usage:

![alt text](https://rtcrowley.github.io/cs_help.png?raw=true "cyber usage")

### Cyber-Attack Modes

**ICE-Breaker** - *Mode 1*: Validate your target is vulnerable to LFI by using the ICE-Breaker attack. This mode uses multiple encoded path types with deep traversal. Setting the null byte and deep traversal flag is disabled since this attack mode (directory list) already includes them. Includes the reflected byte size upon each successful hit.

**Mole-IX** - *Mode 2*: This mode uses a basic, quick directory list to scan for the most common files on a Linux system. Less loud than Mode 3.

**Kuang-Grade-Mark-11** - *Mode 3*: Verbose non-targeted attack. Includes Linux, Macintosh, Windows, logs, conf, ini /proc/self/fd entries and more.

**WIN-Construct** - *Mode 4*: Targeted attack mode against a Windows server. Sets default path type to ..\ instead of ../

___

## Example

Here is a sample output for the [Kuang-Grade-Mark-11](http://www.antonraubenweiss.com/gibson/history/v1/glossary.html) mode, which tests a large directory list. The target is a purposely vulnerable machine with many misconfigured file permissions. In this case there are valid hits in the root **/** and 4 directories deep **../../../../**

![alt text](https://rtcrowley.github.io/cs_m11.png?raw=true "mark11")

Prior to running the above or most verbose attack, you could initially run the **ICE-Breaker**. The ICE-Breaker will test for valid path types using common world-readable files. This is the preferred initial discovery mode when you're trying to find a FI vulnerability. 

In this example we see multiple encoded paths are also valid from the root directory and after 4 directories deep.

![alt text](https://rtcrowley.github.io/icebreaker.png?raw=true "icebreaker")
