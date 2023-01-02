from os import system as sy
from sys import exit

sy('clear')
print("""
      ..............        KALI LINUX TOOL
            ..,;:ccc,.      INSTALLER
          ......''';lxO.
.....''''..........,:ld;
           .';;;:::;,,.x,
      ..'''.            0Xxoc:,.  ... 
  ....                ,ONkc;,;cokOdc',.
 .                   OMo           ':ddo.
                    dMc               :OO;
                    0M.                 .:o.
                    ;Wd  
                     ;XO,
                       ,d0Odlc;,..
                           ..',;:cdOOd::,.
                                    .:d;.':;.
                                       'd,  .'
                                         ;l   ..
                                          .o
                                            c
                                            .'
                                             .
      """)

#get kali tools
op = input('[1] Default tools(default installation), recommended\n[2] Default + additional tools(all tools), some packages might break\n')
print(op)
if op == '1':
    print('Default installation selected\n')
    tools = ['nmap','hydra','metasploit-framework','sqlmap','gobuster','wireshark','sherlock','cewl','aircrack-ng','wpscan','dirbuster','wifite','dirb',
    'maltego','wordlists','ettercap','beef-xss','tcpdump','subfinder','crunch','hashcat','netcat','nikto','armitage','testdisk','hping3','goldeneye',
    'powershell','john','theharvester','traceroute','whois','fcrackzip','burpsuite','steghide','responder','recon-ng','ffuf','autopsy','bettercap',
    'metagoofil','mimikatz','wfuzz','reaver','lynis','amass','arpwatch','sublist3r','skipfish','netdiscover','mdk3','kismet','impacket-scripts','dmitry',
    'airgeddon','scapy','legion','impacket','hash-identifier','dsniff','dnsmap','dnsmap','bloodhound','binwalk','wifiphisher','sslstrip','slowhttptest',
    'rkhunter','medusa','fierce','crackmapexec','commix','chntpw','arp-scan','xsser','spiderfoot','parsero','nuclei','ghidra','foremost','dnsrecon',
    'dirsearch','capstone','bed','whatweb','shellter','rainbowcrack','maryam','macchanger','jsql','hakrawler','dnsenum','chisel','arjun','android-sdk',
    'amap','wafw00f','veil','sslyze','sslscan','setoolkit']

elif op == '2':
    print('Complete installation selected\n')
    tools = ['0trace','abootimg','aesfix','aeskeyfind','afflib','aflplusplus','aircrack-ng','airgeddon','altdns','amap','amass','android-sdk','apache-users',
    'apache2','apktool','apple-bleee','arjun','armitage','arp-scan','arping','arpwatch','asleap','assetfinder','atftp','autopsy','axel','b374k',
    'backdoor-factory','bed','beef-xss','berate-ap','bettercap','bettercap-ui','bind9','bing-ip2hosts','binwalk','bloodhound','bloodhound.py','bluelog',
    'blueranger','bluesnarfer','bluez','braa','bruteforce-salted-openssl','bruteforce-wallet','bruteshark','brutespray','btscanner','bulk-extractor','bully',
    'burpsuite','bytecode-viewer','cabextract','cadaver','caldera','capstone','ccrypt','certgraph','certipy-ad','cewl','changeme','chaosreader','cherrytree',
    'chirp','chisel','chkrootkit','chntpw','chromium','cifs-utils','cisco-auditing-tool','cisco-global-exploiter','cisco-ocs','cisco-torch','cloud-enum',
    'cloudbrute','cmospwd','cmseek','cntlm','code-oss','colly','command-not-found','commix','copy-router-config','covenant-kbx','cowpatty','crack','crackle',
    'crackmapexec','creddump7','crowbar','crunch','cryptcat','cryptsetup','cryptsetup-nuke-password','cupid-wpa','curlftpfs','cutecom','cutycapt','cymothoa',
    'darkstat','davtest','dbd','dbeaver','dc3dd','dcfldd','ddrescue','de4dot','defectdojo','dex2jar','dfdatetime','dfvfs','dfwinreg','dhcpig','dirb',
    'dirbuster','dirsearch','dislocker','distorm3','dmitry','dns2tcp','dnscat2','dnschef','dnsenum','dnsgen','dnsmap','dnsrecon','dnstracer','dnstwist',
    'dnswalk','dnsx','doona','dos2unix','dotdotpwn','dradis','driftnet','dscan','dsniff','dufflebag','dumpsterdiver','dumpzilla','dvwa','dwarf2json',
    'eaphammer','eapmd5pass','edb-debugger','email2phonenumber','emailharvester','enum4linux','enumiax','ethtool','ettercap','evil-ssdp','evil-winrm',
    'exe2hexbat','exifprobe','exiv2','expect','exploitdb','exploitdb-bin-sploits','exploitdb-papers','ext3grep','ext4magic','extundelete','eyewitness',
    'fake-hwclock','faraday-agent-dispatcher','faraday-cli','faraday-client','fcrackzip','fern-wifi-cracker','feroxbuster','ffuf','fierce','fiked',
    'finalrecon','firefox-developer-edition-kbx','firewalk','firmware-mod-kit','firmware-sof','flashrom','foremost','forensic-artifacts','forensics-colorize',
    'fping','fragrouter','framework2','freeradius','freeradius-wpe','freerdp2','ftester','fuse3','galleta','gdb','gdb-peda','gdisk','getallurls','ghidra',
    'git','gitleaks','gnuradio','gobuster','godoh','golang-github-binject-go-donut','goldeneye','goofile','google-nexus-tools','gospider','gpart','gparted',
    'gpp-decrypt','gqrx-sdr','gr-air-modes','gr-iqbal','gr-osmosdr','grokevt','gss-ntlmssp','gtkhash','guymager','gvm','hackrf','hak5-wifi-coconut',
    'hakrawler','hamster-sidejack','hash-identifier','hashcat','hashcat-utils','hashdeep','hashid','hashrat','hb-honeypot','hcxtools','heartleech',
    'hexinject','hivex','hostapd-mana','hostapd-wpe','hosthunter','hostsman','hotpatch','hping3','htshells','httprint','httprobe','httpx-toolkit','httrack',
    'hurl','hydra','hyperion','i2c-tools','iaxflood','ibombshell','ident-user-enum','ifenslave','ike-scan','impacket','impacket-scripts','inetsim',
    'initramfs-tools','inspectrum','inspy','instaloader','intrace','inviteflood','iodine','ipv6-toolkit','irpas','ismtp','isr-evilgrade','ivre','iw','jadx',
    'javasnoop','jboss-autopwn','jd-gui','john','johnny','joomscan','joplin','jsp-file-browser','jsql','juice-shop','kali-community-wallpapers',
    'kali-defaults','kali-meta','kali-tweaks','kali-wallpapers','kalibrate-rtl','kerberoast','king-phisher','kismet','knocker','koadic','lapsdumper',
    'laudanum','lbd','legion','libewf','libfindrtp','libfreefare','libimage-exiftool-perl','libnfc','libpst','linux-exploit-suggester','llvm-defaults',
    'lvm2','lynis','mac-robber','macchanger','magicrescue','maltego','maltego-teeth','maryam','maskprocessor','masscan','massdns','mc','mdbtools','mdk3',
    'mdk4','medusa','memdump','mercurial','merlin','metacam','metagoofil','metasploit-framework','mfcuk','mfoc','mfterm','mimikatz','minicom','miredo',
    'missidentify','mitmproxy','mongo-tools','msfpc','multiforcer','multimac','multimon-ng','myrescue','mysql-defaults','naabu','name-that-hash','nasm',
    'nasty','nbtscan','nbtscan-unixwiz','ncat-w32','ncrack','ncurses-hexedit','net-snmp','netbase','netcat','netdiscover','netkit-ftp','netkit-telnet',
    'netkit-tftp','netmask','netsed','netsniff-ng','netw-ib-ox-ag','nextnet','nfs-utils','ngrep','nikto','nipper-ng','nishang','nmap','nmapsi4','nuclei',
    'o-saft','oclgausscrack','odat','offsec-courses','ohrwurm','ollydbg','onesixtyone','openocd','openssh','openvpn','ophcrack','oscanner','osrframework',
    'outguess','owasp-mantra-ff','owl','p0f','p7zip','pack','pacu','padbuster','paros','parsero','parted','pasco','passing-the-hash','patator',
    'payloadsallthethings','pdf-parser','pdfcrack','pdfid','peass-ng','peirates','perl-cisco-copyconfig','pev','phishery','photon','php-defaults','phpggc',
    'phpsploit','pipal','pixiewps','plaso','plecost','plocate','pnscan','pocsuite3','polenum','pompem','poshc2','powercat','powershell','powershell-empire',
    'powersploit','princeprocessor','protos-sip','proxify','proxmark3','proxychains-ng','proxytunnel','pskracker','ptunnel','pwnat','pwncat',
    'python-defaults','python-faraday','python-pip','python-virtualenv','qemu','qsslcaudit','quark-engine','radare2','radare2-cutter','rainbowcrack','rake',
    'rarcrack','rcracki-mt','rdesktop','reaver','rebind','recon-ng','recordmydesktop','recoverdm','recoverjpeg','redfang','redsnarf','redsocks','reglookup',
    'regripper','rephrase','requests','responder','rev-proxy-grapher','rfcat','rfdump','ridenum','rifiuti','rifiuti2','rizin-cutter','rkhunter','robotstxt',
    'ropper','routerkeygenpc','routersploit','rsakeyfind','rsmangler','rtlsdr-scanner','rtpbreak','rtpflood','rtpinsertsound','rtpmixsound','ruby-pedump',
    's3scanner','safecopy','sakis3g','samba','samdump2','sbd','scalpel','scapy','screen','scrounge-ntfs','sctpscan','seclists','secure-socket-funneling',
    'sendemail','sentrypeer','set','sfuzz','shed','shellfire','shellnoob','shellter','sherlock','sidguesser','siege','silenttrinity','siparmyknife',
    'sipcrack','sipp','sipsak','sipvicious','skipfish','sleuthkit','sliver','slowhttptest','smali','smbmap','smtp-user-enum','sniffjoke','snmpcheck',
    'snmpenum','snowdrop','socat','sparrow-wifi','spectools','spiderfoot','spike','spooftooph','spray','sprayingtoolkit','spraykatz','sqldict',
    'sqlitebrowser','sqlmap','sqlninja','sqlsus','ssdeep','ssldump','sslh','sslscan','sslsniff','sslsplit','sslstrip','sslyze','starkiller','statsprocessor',
    'stegcracker','steghide','stegsnow','stunnel4','subfinder','subjack','sublist3r','subversion','sucrack','sudo','swaks','t50','tcpdump','tcpflow',
    'tcpick','tcpreplay','teamsploit','termineter','testdisk','testssl.sh','tftpd32','thc-ipv6','thc-pptp-bruter','thc-ssl-dos','theharvester','tightvnc',
    'tlssled','tmux','tnftp','tnscmd10g','traceroute','truecrack','trufflehog','tundeep','twofi','u-boot','ubertooth','udptunnel','uhd','uhd-images','undbx',
    'unhide','unhide.rb','unicorn-magic','unicornscan','uniscan','unix-privesc-check','unrar-nonfree','upx-ucl','urlcrazy','usbutils','util-linux',
    'vboot-utils','veil','vim','vinetto','vlan','voiphopper','vpnc','wafw00f','wapiti','watobo','wce','webacoo','webscarab','webshells','websploit','weevely',
    'wfuzz','wgetpaste','what-is-python','whatmask','whatweb','whois','wifi-honey','wifiphisher','wifipumpkin3','wifite','wig','wig-ng','windows-binaries',
    'windows-privesc-check','winexe','winregfs','wireshark','witnessme','wmi','wordlistraider','wordlists','wotmate','wpa-sycophant','wpscan','xmount',
    'xplico','xprobe','xspy','xsser','yara','yersinia','zaproxy','zenmap-kbx','zerofree','zim','zonedb','zsh','zsh-autosuggestions','zsh-syntax-highlighting']
else:
    print('invalid option')
    exit()

packages = '\n'
avail_packages = []
failed_packages = []

#print total packages to install
print(str(len(tools))+' tools are to be downloaded')
print(' '.join(tools)+'\n\n')
input('press enter to continue...')
sy('clear')

#check tools in brew
print('\nGetting list of packages available for brew...\n')
sy('curl https://formulae.brew.sh/formula/ -s  > packages')

for i in open('packages', errors='ignore').read().split('\n'):
    if '/formula/' in i:
        packages+=i.split('/formula/')[1].split('"')[0]+'\n'

sy('rm packages')
for i in tools:
    if '\n'+i+'\n' in packages:
        avail_packages.append(i)
    else:
        failed_packages.append(i)

packages = ' '.join(avail_packages)
#print status of the installation, no of packages available out of total packages, their names
print(str(len(avail_packages))+'/'+str(len(tools))+' packages available in brew\n'+packages)

if input('\nDownload? [y/n] ').lower() == 'y':sy('brew install '+ packages)
else:exit()

#try failed packages from macport
print('Below are the packages that were not found in brew, total of '+str(len(failed_packages))+'tools')
if input("Try downloading the failed packages from port? you need to have port installed [y/n]").lower() == 'y':sy('sudo port install '+' '.join(failed_packages))
else:exit()