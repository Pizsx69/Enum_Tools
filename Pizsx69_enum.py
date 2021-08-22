#!/usr/bin/python3
"""
Pizs\\x69 OSCP Enum tools.
"""
import os.path
from os import path
import os


file_list=[]
folder_list=[]
home_list=[]
default_command_list=[]
find_command_list =[]

def main():
    #Ide kell egy switch windows or linux.
    Load_FileList()
    User_List()
    Folder_check()
    Default_Command_List()
    Find_Command_List()

    Start_Enum()

#F_OK
#X_OK
#W_OK
#R_OK
def Start_Enum():

    fo = open("/tmp/important_command.txt","w")
    fo.write("IMPORTANT RUN MANUAL \"SUDO -l\" ")
    for x in default_command_list:
        try:
            proc = os.popen(x)
            fo.write("#"*80+"\n")
            fo.write(x+"\n")
            fo.write("//"*80+"\n")            
            fo.write(proc.read())
            fo.write("\n")

        except ValueError:
            pass
    fo.close()

    fo = open("/tmp/find_command.txt","w")
    for x in find_command_list:
        try:
            proc = os.popen(x)
            fo.write("#"*80+"\n")
            fo.write(x+"\n")
            fo.write("//"*80+"\n")            
            fo.write(proc.read())
            fo.write("\n")

        except ValueError:
            pass
    fo.close()

    fo = open("/tmp/writeable_files.txt","w")
    for x in file_list:
        try:
            if(path.exists(x)):
                if os.access(x,os.W_OK):
                    fo.write("\n")
                    fo.write(x)

        except ValueError:
            pass
    fo.close()

    fo = open("/tmp/readable_files.txt","w")
    for x in file_list:
        try:
            if(path.exists(x)):
                if os.access(x,os.R_OK):
                    fo.write("\n")
                    fo.write(x)

        except ValueError:
            pass
    fo.close()

    fo = open("/tmp/executes_files.txt","w")
    for x in file_list:
        try:
            if(path.exists(x)):
                if os.access(x,os.X_OK):
                    fo.write("\n")
                    fo.write(x)

        except ValueError:
            pass
    fo.close()
    #for x in find_command_list:
    #    try:
    #       output = os.system(x)
    #       #print(output)
    #    except ValueError:
    #        print(ValueError)
#
    #for x in home_list:
     #   if(path.exists(x)):
      #      if os.access(x,os.W_OK):
       #         print(x)

def Find_Command_List():
    global find_command_list
    find_command_list=[
    "find / -perm -u=s -type f 2>/dev/null",
    "find / -type f -name \"*.bak\" -o -name \"*.log\" -o -name \"*.sh\" -o -name \"*.py\" -o -name \"*.c\" 2>/dev/null",
    "find / -perm -1000 -O -g=s -o -u=s -type d 2>/dev/null",
    #"find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld \{\} \; 2>/dev/null",
    #"find /dir -xdev \\( -nouser -o -nogroup \\) -print",
    #"find / -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) -print",
    "find / \\( -perm -o w -perm -o x \\) -type d 2>/dev/null",
    #"find / -perm -o x -type d 2>/dev/null",
    #"find / -perm -o w -type d 2>/dev/null",
    #"find / -writable -type d 2>/dev/null",
    ]
            
def Default_Command_List():
    global default_command_list
    default_command_list=[
    #"sudo -l",
    "cat /etc/sudoers",
    "which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null",
    "lsof -i",
    "cat /etc/passwd",
    "cat /etc/group",
    "cat /etc/shadow",
    "cat ~/.bash_history",
    "cat ~/.nano_history",
    "cat ~/.atftp_history",
    "cat ~/.mysql_history",
    "cat ~/.php_history",
    "cat ~/.bashrc",
    "cat ~/.profile",
    "cat /var/mail/root",
    "cat /var/spool/mail/root",
    "cat /var/apache2/config.inc",
    "cat /var/lib/mysql/mysql/user.MYD",
    "cat /root/anaconda-ks.cfg",
    #"ls -aRl /etc/ | awk \'$1 ~ /^.*w.*/\' 2>/dev/null",
    #"ls -aRl /etc/ | awk \'$1 ~ /^..w/\' 2>/dev/null",
    #"ls -aRl /etc/ | awk \'$1 ~ /^.....w/\' 2>/dev/null",
    #"ls -aRl /etc/ | awk \'$1 ~ /w.$/\' 2>/dev/null",
    #"find /etc/ -readable -type f 2>/dev/null",
    #"find /etc/ -readable -type f -maxdepth 1 2>/dev/null",
    #"ls -alh /var/log",
    #"ls -alh /var/mail",
    #"ls -alh /var/spool",
    #"ls -alh /var/spool/lpd",
    #"ls -alh /var/lib/pgsql",
    #"ls -alh /var/lib/mysql",
    #"cat /var/lib/dhcp3/dhclient.leases",
    "cat /etc/syslog.conf",
    "cat /etc/chttp.conf",
    "cat /etc/lighttpd.conf",
    "cat /etc/cups/cupsd.conf",
    "cat /etc/inetd.conf",
    "cat /etc/apache2/apache2.conf",
    "cat /etc/my.conf",
    "cat /etc/httpd/conf/httpd.conf",
    "cat /opt/lampp/etc/httpd.conf",
    "cat /etc/fstab",
    "df -h",
    "lpstat -a"  
    ]

def Folder_check():
    global folder_list
    folder_list = [
    "ls -ahlR /root/",
    "ls -ahlR /home/",
    "ls -alhR /var/log/httpd/",
    "ls -alhR /var/log/lighttpd/",
    "ls -alhR /var/log/conman/",
    "ls -alhR /var/log/mail/",
    "ls -alhR /var/log/prelink/",
    "ls -alhR /var/log/audit/",
    "ls -alhR /var/log/setroubleshoot/",
    "ls -alhR /var/log/samba/",
    "ls -alhR /var/log/sa/",
    "ls -alhR /var/log/sssd/",
    "ls -alhR /var/www/",
    "ls -alhR /srv/www/htdocs/",
    "ls -alhR /usr/local/www/apache22/data/",
    "ls -alhR /opt/lampp/htdocs/",
    "ls -alhR /var/www/html/",
    "ls -alhR /var/mail/"

    ]
def User_List():
    users_dir = os.listdir("/home/")
    global home_list

    temp_home_list = [
    "/.bash_history",
    "/.mysql_history",
    "/.my.cnf",
    "/.ssh/id_rsa",
    "/.ssh/id_rsa.keystore",
    "/.ssh/id_rsa.pub",
    "/.ssh/known_hosts"
    ]

    for x in users_dir:
        for i in temp_home_list:          
            home_list.append("/home/"+x+"/"+i)


def Load_FileList():
    global file_list
    file_list =[
    "/opt/lampp/logs/access.log",
    "/opt/lampp/logs/access_log",
    "/opt/lampp/logs/error.log",
    "/opt/lampp/logs/error_log",
    "/opt/xampp/logs/access.log",
    "/opt/xampp/logs/access_log",
    "/opt/xampp/logs/error.log",
    "/opt/xampp/logs/error_log",
    "/opt/apache/conf/httpd.conf",
    "/opt/apache2/conf/httpd.conf",
    "/logs/pure-ftpd.log",
    "/logs/security_debug_log",
    "/logs/security_log",
    "/opt/lampp/etc/httpd.conf",
    "/opt/xampp/etc/php.ini",
    "/var/adm/log/xferlog",
    "/var/apache2/config.inc",
    "/var/apache/logs/access_log",
    "/var/apache/logs/error_log",
    "/var/cpanel/cpanel.config",
    "/var/lib/mysql/my.cnf",
    "/var/lib/mysql/mysql/user.MYD",
    "/var/local/www/conf/php.ini",
    "/var/log/apache2/access_log",
    "/var/log/apache2/error_log",
    "/var/log/apache2/error.log",
    "/var/log/apache/access.log",
    "/var/log/apache/error.log",
    "/var/log/apache-ssl/access.log",
    "/var/log/apache-ssl/error.log",
    "/var/log/boot",
    "/var/htmp",
    "/var/log/chttp.log",
    "/var/log/cups/error.log",
    "/var/log/daemon.log",
    "/var/log/debug",
    "/var/log/dmesg",
    "/var/log/dpkg.log",
    "/var/log/exim_mainlog",
    "/var/log/exim/mainlog",
    "/var/log/exim_paniclog",
    "/var/log/exim.paniclog",
    "/var/log/exim_rejectlog",
    "/var/log/exim/rejectlog",
    "/var/log/faillog",
    "/var/log/ftplog",
    "/var/log/ftp-proxy",
    "/var/log/ftp-proxy/ftp-proxy.log",
    "/var/log/httpd/access_log",
    "/var/log/httpsd/ssl.access_log",
    "/var/log/httpsd/ssl_log",
    "/var/log/kern.log",
    "/var/log/lighttpd/access.log",
    "/var/log/lighttpd/error.log",
    "/var/log/lighttpd/lighttpd.access.log",
    "/var/log/lighttpd/lighttpd.error.log",
    "/var/log/mail.info",
    "/var/log/mail.log",
    "/var/log/maillog",
    "/var/log/mail.warn",
    "/var/log/message",
    "/var/log/messages",
    "/var/log/mysqlderror.log",
    "/var/log/mysql.log",
    "/var/log/mysql/mysql-bin.log",
    "/var/log/mysql/mysql.log",
    "/var/log/mysql/mysql-slow.log",
    "/var/log/proftpd",
    "/var/log/pureftpd.log",
    "/var/log/pure-ftpd/pure-ftpd.log",
    "/var/log/secure",
    "/var/log/vsftpd.log",
    "/var/log/wtmp",
    "/var/log/xferlog",
    "/var/log/yum.log",
    "/var/mysql.log",
    "/var/spool/cron/crontabs/root",
    "/var/webmin/miniserv.log",
    "/var/log/lastlog",
    "/var/run/utmp",
    "/var/log/messages.log",
    "/var/log/messages.0",
    "/var/log/messages.0.gz",
    "/var/log/messages.1",
    "/var/log/messages.1.gz",
    "/var/log/messages.2",
    "/var/log/messages.2.gz",
    "/var/log/messages.3",
    "/var/log/messages.3.gz",
    "/var/log/syslog.log",
    "/var/log/syslog",
    "/var/log/syslog.0",
    "/var/log/syslog.0.gz",
    "/var/log/syslog.1",
    "/var/log/syslog.1.gz",
    "/var/log/syslog.2",
    "/var/log/syslog.2.gz",
    "/var/log/syslog.3",
    "/var/log/syslog.3.gz",
    "/var/log/auth.log",
    "/var/log/auth.log.0",
    "/var/log/auth.log.0.gz",
    "/var/log/auth.log.1",
    "/var/log/auth.log.1.gz",
    "/var/log/auth.log.2",
    "/var/log/auth.log.2.gz",
    "/var/log/auth.log.3",
    "/var/log/auth.log.3.gz",
    "/var/www/conf/httpd.conf",
    "/var/www/logs/access.log",
    "/var/www/logs/access_log",
    "/var/www/logs/error.log",
    "/var/www/logs/error_log",
    "/var/root/.bash_history",
    "/var/root/.sh_history",
    "/var/log/access.log",
    "/var/log/access_log",
    "/var/log/error.log",
    "/var/log/error_log",
    "/var/log/apache2/access.log",
    "/var/log/apache/access_log",
    "/var/log/apache/error_log",
    "/var/log/httpd/access.log",
    "/var/log/httpd/error.log",
    "/var/log/httpd/error_log",
    "/var/mail/www-data",
    "/var/mail/www",
    "/var/mail/apache",
    "/var/mail/nobody",
    "/var/www/.bash_history",
    "/var/db/shadow/hash",
    "/etc/master.passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/hosts",
    "/etc/release",
    "/etc/redhat-release",
    "/etc/crontab",
    "/etc/inittab",
    "/etc/httpd.conf",
    "/etc/apache2.conf",
    "/etc/apache2/httpd.conf",
    "/etc/httpd/httpd.conf",
    "/etc/apache2/conf/httpd.conf",
    "/etc/apache/conf/httpd.conf",
    "/etc/apache2/sites-enabled/000-default",
    "/etc/apache2/sites-available/default",
    "/etc/nginx.conf",
    "/etc/nginx/nginx.conf",
    "/etc/nginx/sites-available/default",
    "/etc/nginx/sites-enabled/default",
    "/etc/ssh/sshd_config",
    "/etc/my.cnf",
    "/etc/php.ini",
    "/etc/http/conf/httpd.conf",
    "/etc/http/httpd.conf",
    "/etc/httpd/php.ini",
    "/etc/php4/apache/php.ini",
    "/etc/php5/apache2/php.ini",
    "/etc/php/php.ini",
    "/etc/php/php4/php.ini",
    "/etc/php/cgi/php.ini",
    "/etc/php5/cgi/php.ini",
    "/etc/passwd",
    "/etc/aliases",
    "/etc/anacrontab",
    "/etc/apache2/apache2.conf",
    "/etc/at.allow",
    "/etc/at.deny",
    "/etc/bashrc",
    "/etc/bootptab",
    "/etc/chrootUsers",
    "/etc/chttp.conf",
    "/etc/conf.modules",
    "/etc/cron.allow",
    "/etc/cron.deny",
    "/etc/cups/cupsd.conf",
    "/etc/exports",
    "/etc/fstab",
    "/etc/ftpaccess",
    "/etc/ftpchroot",
    "/etc/ftphosts",
    "/etc/groups",
    "/etc/grub.conf",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
    "/etc/httpd/access.conf",
    "/etc/httpd/conf/httpd.conf",
    "/etc/httpd/logs/access_log",
    "/etc/httpd/logs/access.log",
    "/etc/httpd/logs/error_log",
    "/etc/httpd/logs/error.log",
    "/etc/httpd/srm.conf",
    "/etc/inetd.conf",
    "/etc/issue",
    "/etc/lighttpd.conf",
    "/etc/lilo.conf",
    "/etc/logrotate.d/ftp",
    "/etc/logrotate.d/proftpd",
    "/etc/logrotate.d/vsftpd.log",
    "/etc/lsb-release",
    "/etc/modules.conf",
    "/etc/motd",
    "/etc/mtab",
    "/etc/my.conf",
    "/etc/mysql/my.cnf",
    "/etc/network/interfaces",
    "/etc/networks",
    "/etc/npasswd",
    "/etc/php4.4/fcgi/php.ini",
    "/etc/php4/cgi/php.ini",
    "/etc/php5/apache/php.ini",
    "/etc/php/apache2/php.ini",
    "/etc/php/apache/php.ini",
    "/etc/printcap",
    "/etc/profile",
    "/etc/proftp.conf",
    "/etc/proftpd/proftpd.conf",
    "/etc/pure-ftpd.conf",
    "/etc/pureftpd.passwd",
    "/etc/pureftpd.pdb",
    "/etc/pure-ftpd/pure-ftpd.conf",
    "/etc/pure-ftpd/pure-ftpd.pdb",
    "/etc/pure-ftpd/putreftpd.pdb",
    "/etc/resolv.conf",
    "/etc/samba/smb.conf",
    "/etc/securetty",
    "/etc/snmpd.conf",
    "/etc/ssh/ssh_config",
    "/etc/ssh/ssh_host_dsa_key",
    "/etc/ssh/ssh_host_dsa_key.pub",
    "/etc/ssh/ssh_host_key",
    "/etc/ssh/ssh_host_key.pub",
    "/etc/sysconfig/network",
    "/etc/syslog.conf",
    "/etc/termcap",
    "/etc/vhcs2/proftpd/proftpd.conf",
    "/etc/vsftpd.chroot_list",
    "/etc/vsftpd.conf",
    "/etc/vsftpd/vsftpd.conf",
    "/etc/wu-ftpd/ftpaccess",
    "/etc/wu-ftpd/ftphosts",
    "/etc/wu-ftpd/ftpusers",
    "/etc/X11/XF86Config",
    "/etc/sudoers",
    "/proc/version",
    "/proc/cmdline",
    "/proc/self/environ",
    "/proc/self/fd/0",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
    "/proc/self/fd/255",
    "/usr/local/apache/logs/access.log",
    "/usr/local/apache/logs/access_log",
    "/usr/local/apache/logs/error.log",
    "/usr/local/apache/logs/error_log",
    "/usr/local/apache2/logs/access.log",
    "/usr/local/apache2/logs/access_log",
    "/usr/local/apache2/logs/error.log",
    "/usr/local/apache2/logs/error_log",
    "/usr/local/apache2/conf/httpd.conf",
    "/usr/local/apache/conf/httpd.conf",
    "/usr/local/apache/httpd.conf",
    "/usr/local/apache2/httpd.conf",
    "/usr/local/httpd/conf/httpd.conf",
    "/usr/local/etc/apache/conf/httpd.conf",
    "/usr/local/etc/apache2/conf/httpd.conf",
    "/usr/local/etc/httpd/conf/httpd.conf",
    "/usr/apache2/conf/httpd.conf",
    "/usr/apache/conf/httpd.conf",
    "/usr/local/php4/httpd.conf",
    "/usr/local/php4/lib/php.ini",
    "/usr/bin/env",
    "/usr/etc/pure-ftpd.conf",
    "/usr/lib/php.ini",
    "/usr/lib/php/php.ini",
    "/usr/local/apache/conf/modsec.conf",
    "/usr/local/apache/conf/php.ini",
    "/usr/local/apache/log",
    "/usr/local/apache/logs",
    "/usr/local/apache/audit_log",
    "/usr/local/apache/error_log",
    "/usr/local/apache/error.log",
    "/usr/local/cpanel/logs",
    "/usr/local/cpanel/logs/access_log",
    "/usr/local/cpanel/logs/error_log",
    "/usr/local/cpanel/logs/license_log",
    "/usr/local/cpanel/logs/login_log",
    "/usr/local/cpanel/logs/stats_log",
    "/usr/local/etc/httpd/logs/access_log",
    "/usr/local/etc/httpd/logs/error_log",
    "/usr/local/etc/php.ini",
    "/usr/local/etc/pure-ftpd.conf",
    "/usr/local/etc/pureftpd.pdb",
    "/usr/local/lib/php.ini",
    "/usr/local/php4/httpd.conf.php",
    "/usr/local/php5/httpd.conf",
    "/usr/local/php5/httpd.conf.php",
    "/usr/local/php5/lib/php.ini",
    "/usr/local/php/httpd.conf",
    "/usr/local/php/httpd.conf.ini",
    "/usr/local/php/lib/php.ini",
    "/usr/local/pureftpd/etc/pure-ftpd.conf",
    "/usr/local/pureftpd/etc/pureftpd.pdn",
    "/usr/local/pureftpd/sbin/pure-config.pl",
    "/usr/local/www/logs/httpd_log",
    "/usr/local/Zend/etc/php.ini",
    "/root/.bash_history",
    "/var/log/boot.log",
    "/var/log/user.log",
    "/var/log/Xorg.x.log",
    "/var/log/alternatives.log",
    "/var/log/btmp",
    "/var/log/cups",
    "/var/log/anaconda.log",
    "/var/log/cron"
    ]




if __name__ == "__main__":
    main()