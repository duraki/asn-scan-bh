# asn-scan-bh

## What?

A simple investigation about the state of IT/ICS security on Intrawebz. For regional entities of Bosnia-Herzegovina based on CIDR and ISP ASN provided range. It scans whole Bosnia-Herzegovina IPv4 addresses for top 1000 ports. Later, it parses those for further investigation. 

## How?

Pretty simple. First thing first, get an ASN list based on your country. Then, extract CIDR ranges from the ASN list. After you've completed the first part, you need to clean up all IPv6 samples from the CIDR list -- so Masscan will not fail. Anyway, lets see how I did it.
  
- I got the ASN list from [here](...) and then copied them in a file so I can parse with some xnu-fu skillz =p

``` 
$ more asn-list-details.txt
AS9146          BH Telecom d.d. Sarajevo        172,800
AS42560         Telemach d.o.o. Sarajevo        143,360
AS25144         Telekomunikacije Republike Srpske akcionarsko drustvo Banja Luka        123,392
AS20875         HT d.o.o. Mostar        73,728
AS198252        ELTA KABEL d.o.o.       38,144
AS16178         Logosoft , information engineering and Internet providing       35,840
AS21107         Blicnet d.o.o.  33,280
AS35567         DASTO semtel d.o.o.     29,440
AS42571         Telrad Net doo  21,504
AS202632        TXTV d.o.o. Tuzla       18,688
AS43752         Ministry for Scientific and Technological Development, Higher Education and Information Society of the Republic of Srpska       16,384
AS57869         MISS.NET d.o.o.         11,264
AS43179         Team Consulting d.o.o.  10,240
AS8670          University of Sarajevo  8,192
...

$ awk '{print $1}' asn-list-details.txt > asn.txt && more asn.txt
AS9146
AS42560
AS25144
AS20875
AS198252
AS16178
...
```

Nice, after getting all ASN listed in `asn.txt` file, I've used ASN to CIDR conversion tool located [here](....link).
Using `wget` I pulled the CIDR range to another file which we will name `cidrs.txt`.

Lets see:

```
$ wget https://pastebin.com/raw/gk9q56dV -O cidrs.txt
```

What was left to do is increase the chance of some findings via `masscan` preferences of my own. You can refer to `man masscan` for more detailed usage, or by reading the source code =p.

### masscan

* Download, compile and install [masscan](https://github.com/robertdavidgraham/masscan).
* Test your installation

```
$ masscan --regress
regression test: success!
```

* Run masscan against cidr ranges:

```
$ masscan --top-ports 1000 --rate 100000 -oG ms-out.txt -oJ ms-out.json -iL cidrs.txt --open-only --wait 2 --banners --interactive
```

This will scan top ports with a rate of 100k p/p/s. It will output positive (`--open-only`) results in plain text (`-oG`) and json (`-oJ`) and it will print to stdout due to interactive flag. The arg `--wait 2` means the proc will wait 2 seconds before giving up (just making things quicker).

**Author's Terminal Output:** 

```
0xduraki@ ~/dev/asn-scan-bh  masscan --top-ports 1000 --rate 100000 -oG ms-out.txt -oJ ms-out.json -iL cidrs.txt --open-only --wait 2 --banners --interactive
Starting masscan 1.3.2 (....) at 2021-04-18 05:44:11 GMT
Initiating SYN Stealth Scan
Scanning 766976 hosts [1000 ports/host]
Discovered open port 9876/tcp on 80.87.241.29
rate: 98.78-kpps,  0.71% done,   2:06:40 remaining, found=1
rate: 98.71-kpps,  0.72% done,   2:06:46 remaining, found=1
Discovered open port 53/tcp on 178.209.2.102
Discovered open port 23/tcp on 91.191.6.207
...
```

## ~things
  
As you can see, we have a total of ~766k IPv4 to scan. Which is not a lot, but it's stil a very large set for a country as small as Bosnia-Herzegovina. This is, of course, excluding IPv6 which I will write about very soon.


### netw scan

Total scan time of the IPv4 address space for given ASN on my ISP with bandwith i/o: **BANDWITH HERE** speedresult.net via (im sooory) Wi-Fi (next to AP) took about ~2h. Meanwhile, as `interactive` flag was given, I could really see what is happening, which shortened the time somehow =p and also offered me to play while the scans finish. Once I have a positive `IPv4:PORT` match, I asked Unix what port is for which stuff. See terminal output below:

```
# => ie masscan stdout prints:
...
Discovered open port 1723/tcp on 195.34.71.161

# => me, in another tty:
$ cat /etc/services | grep 1723
pptp            1723/udp     # pptp
pptp            1723/tcp     # pptp
ssh-mgmt        17235/tcp   # SSH Tectia Manager
ssh-mgmt        17235/udp   # SSH Tectia Manager
#               17236-17728 Unassigned
``` 

This way, I had more to look at and objectively junk on unfiltered ports hanging in the wild. Ie. why is Fortinet FW obviously sitting in the pubnet, all while whole world can access it? Doesn't seems like a good sec practice to me. A lot of time, I've been looking to what service it yields back to me and then see if there are possible exploits available:

```
# => Port availability
$ cat /etc/services | grep ssdp
ssdp		1900/udp     # SSDP
ssdp		1900/tcp     # SSDP

msf6 auxiliary(scanner/smb/smb_login) > search ssdp

Matching Modules
================

   #  Name                                          Disclosure Date  Rank       Check  Description
   -  ----                                          ---------------  ----       -----  -----------
   0  exploit/linux/upnp/dlink_dir859_exec_ssdpcgi  2019-12-24       excellent  No     D-Link Devices Unauthenticated Remote Command Execution in ssdpcgi
   1  exploit/multi/upnp/libupnp_ssdp_overflow      2013-01-29       normal     No     Portable UPnP SDK unique_service_name() Remote Code Execution
   2  auxiliary/scanner/upnp/ssdp_amp                                normal     No     SSDP ssdp:all M-SEARCH Amplification Scanner
   3  auxiliary/scanner/upnp/ssdp_msearch                            normal     No     UPnP SSDP M-SEARCH Information Discovery
```

### scada/ics/iot

As for the why I'm writing this blog? It's because I'm heading towards more specialised industry as I'm switching jobs and leaving great, great [Infigo](https://infigo.hr) where I've met very smart people, and joining [Applied Risk](https://applied-risk.com) from Amsterdam, de-facto company dealing with ICS on another level. Fantastic, I can't wait to express my inner thoughts once I get my hands dirty on those PLCs.

**For SCADA in particular**, I've chose to visit back my private GitHub repo sitting in [ics_bh](https://github.com/duraki/ics_bh/) that already defines some of the juicy stuff. I've spent a few days collecting all sources for scadasec and internal stuff via Webinars. Then I resumed and researched what I had and started working on this tool.

The `ics_bh` utility I wrote a few weeks earlier does some banner grabbing on famous ICS vendors installed in Europe. I'm yet to open-source this little guy, but I hope you will forgive due to me trying C++.

**snippet from `/vendors.h:`**

```
/* icsbh - State of SCADA security in Bosnia-Herzegovina
 * Copyright (c) 2021 Halis Duraki (0xduraki)
 */

...

typedef enum : int { /* u = udp , t = tcp*/
    FLNet = 55000,              // to ..55003, u
    Fieldbus_HSE = 1089,        // to 1091, t,u
    BACnet = 47808,             // u
    DNP3 = 20000,               // u,t
    EtherNet_IP = 44818,        // u,t
    EtherCAT = 34980,           // u
    ModBus = 502,               // u,t
    ProCon_PLC = 20547,         // u,t
    Wago_PLC = 2455,            // u,t
    RedLion_Crimson = 789,      // t
    SIEMENS_S7 = 102,           // t
    NIAGRA_FW_0 = 1911,         // ???
    NIAGRA_FW_1 = 4911,         // ???
    IEC104 = 2404,              // ???
    IEC60870, // 2404 as above
    GeneralElectric, // like EtherNet
    Omron, // same as DeviceNet, RS-232C
    PCWorx = 20547, 2455, 9600, 1962,
    OPC_UA_DiscoveryServer = 4840,
    PROFINET = t[34962..34964], u[34962 to 34964],
    ROC_PLUS = tu[4000],
    DCSFOXAPI = 55555 // tu
    DCSAIMAPI = 45678 // tu
    Sielco_Sistemi_Winlog = 46824, // remotely exploitable with vulnerability winlog_runtime_2 from metasploit

} Protocols;
```

Therefore, we can all agree that reusing masscan might be more appropriate, but where is the fun in that? =p
I came up with this command-line. Can you come up with something better?

**Hold up!!** As per masscan documentation, `[masscan] supports banner checking on the [...] protocols`, tho below it says: `[...] problem with this is that masscan contains its own TCP/IP stack [...] when the local system receives a SYN-ACK, it responds with a RST packet that kills the connection ...`. 

That makes sense, see [masscan (8)](http://manpages.ubuntu.com/manpages/bionic/man8/masscan.8.html) section **SPURIOUS RESETS**. We can force this to make masscan tunnel through additional ipaddr inside your home network, or as per [MacOS documentation](https://github.com/robertdavidgraham/masscan#banner-checking): 

```
# => find available range for port choice
$ sysctl net.inet.ip.portrange.first net.inet.ip.portrange.last
net.inet.ip.portrange.first: 49152
net.inet.ip.portrange.last: 65535

$ echo "block in proto tcp from any to any port 53337" >> /etc/pf.conf
$ pfctl -E
```

Now `masscan` will run more powerful, we just need to pass `--adapter-port` flag. Like so:

```
# => tcp scan of scada ports
$ masscan --rate 100000 -p 102,789,1089-1091,1541,1911,1962,2404,2455,4000,4840,4911,5052,5056,5450,9600,11001,12135-12137,18000,55555,20000,20547,34962-34964,38000-38015,38200-38700,44818,45678,46824,50001-50028,50110-50111,56001-56099,62900-62930 -oG ms-scada-out.txt -oJ ms-scada-out.json -iL cidrs.txt --open-only --banners --interactive --adapter-port 53337

# => udp scan of scada ports
$ masscan --rate 100000 -p U:502,U:789,U:1089-1091,U:1541,U:1911,U:2404,U:2455,U:4000,U:4911,U:5050-5065,U:11001,U:20000,U:20547,U:34960-34964,U:44818,U:47808,U:45678,U:50020-50021,U:55000-55003,U:55555 -oG ms-scada-out-udp.txt -oJ ms-scada-out-udp.json -iL cidrs.txt --open-only --banners --interactive --adapter-port 53337
```


**Bonus points!!** for hard-core router ddos, try =p:

```
$ masscan cidrs.txt --rate 1000000000 -p0-65535,U:0-65535 -e eth0 -oG output.txt
```

**For IoT on other hand** , I've referenced to old stuff used famously by Mirai and alike. DDoS attacks were prevelent some time when I was young, but using exposed cctvs via high bandwith was really interesting art piece. Also .. the fire on the industry. dayyyuum

### pulling domains out of the address-space

Ah. This was actually my favoruite part, as I had various things to play with - network levels, and also <apps> sittings on the servers. I see a lot of guys pushing towards web. Yeah, I agree, but I'd also agree with Phineas Phisher when she told us that web can give you only much. If you really want to dig into hacking more naturally, you will have to explore deeper topics. If you are not prepared for that, then .. don't try. Is hacking really your passion? You can think about it and let me know =)

Again, all this was done just to experiment with recon on more mature level, not chashing papers only. I guess.

After I've completed the above task (due to `masscan` being really, really fast with rate/packets, the capnet occured - therefore I've waited for above masscan to finish) -- ie. extract live hosts on top*1000 ports. Later, I figured out, I could reverse the IPv4 and ASN for that matter, and try all DNS hosted on this address space. Mostly of what I thought would be `.ba` ccTLD for Bosnia-Herzegovina.

> Hint: You can always Ctrl+C to `masscan` command line, and later resume the scan. This means you can turn of your computer, go with your things, and continue later when you are in mood.

```
# => Ctrl+C
Scanning 766976 hosts [1000 ports/host]
^Cwaiting several seconds to exit...
saving resume file to: paused.conf

# => After a few days
$ masscan --resume paused.conf
Starting masscan 1.3.2 (.....) at 2021-04-18 06:58:55 GMT
Initiating SYN Stealth Scan
Scanning 766976 hosts [1000 ports/host]
rate: 98.62-kpps, 56.62% done,   0:55:02 remaining, found=x
```

> Note: By the time of writing, the latest official release of masscan -- version `1.3.2` will fail if `--resume paused.conf` is used due to robertdavidgraham/masscan#576. Compile from master if you want it, otherwise, don't send signals to tty.

I figured out I could use `amass` which most of the haxors use for recon, and try to extract domains matching those hosts. I could just pass multiple ASNs to `amass` intel command by `-asn` flag. But first, I had to convert those ASN to Integer types (ie. remove *AS*), because `amass` will accept only those. Again, Unix comes handy here to replace all 'AS' prefixes with nullbytes.

```
$ head -1 asn.txt | sed 's/AS//' # => ~smoke-test
9146

$ cat asn.txt | sed 's/AS//' | sed -e :begin -e '$!N;s/\n/,/; tbegin'
9146,42560,25144,20875,198252,16178,21107,35567,42571,202632,43752,57869,43179,8670,16145,59457,200698,34943,47959,59847,50537,199051,198994,212665,203744,209491,200914,201719,39826,35107,208881,209098,206474,205913,209271,43947,50249,39689,43604,61222,35143,42432,42450,42983,212572,47840,48443,50938,51386,197687,209493
```

Cool, now we have ASNs that we can pass to `amass` in a similar way:

```
$ amass intel -active -o asn-amass-intel.txt -ipv4 -src -asn 9146,42560,25144,20875,198252,16178,21107,35567,42571,202632,43752,57869,43179,8670,16145,59457,200698,34943,47959,59847,50537,199051,198994,212665,203744,209491,200914,201719,39826,35107,208881,209098,206474,205913,209271,43947,50249,39689,43604,61222,35143,42432,42450,42983,212572,47840,48443,50938,51386,197687,209493
``` 

I know, it's kinda stupid. But hey, it works properly. Don't forget to setup all API keys in `amass.ini` config file. The results:

```
- 
[Reverse DNS]     telemach.ba 109.237.32.4
[Reverse DNS]     urbzdk.ba 77.239.29.254
[Reverse DNS]     fis.ba 141.170.204.210
[Reverse DNS]     telemach.co.ba 77.78.192.15
[Reverse DNS]     imbih.gov.ba 77.78.198.102
[Reverse DNS]     tmch.net.ba 77.78.192.1
[Reverse DNS]     googlevideo.com 77.77.193.135
[Reverse DNS]     telemachhosting.ba 77.77.192.21
[Reverse DNS]     cloudhosting.ba 77.77.207.42
[Reverse DNS]     telemachhosting.co.ba 77.77.207.221
[Reverse DNS]     mojposao.ba 77.77.209.106
[Reverse DNS]     jamax.ba 77.77.212.182
[Reverse DNS]     standard-furniture.ba 77.221.1.99
[Reverse DNS]     vinet.ba 77.221.22.89
[Reverse DNS]     messer.ba 185.6.105.42
[Reverse DNS]     icitapeng.us 185.6.105.220
[Reverse DNS]     uniqaosiguranje.ba 185.6.104.36
[Reverse DNS]     ghb.ba 185.6.105.204
[Reverse DNS]     hs-hkb.ba 185.6.106.63
[Reverse DNS]     epprojects.net 77.78.199.21
[Reverse DNS]     ferk.ba 77.78.200.8
[Reverse DNS]     megamix.ba 77.78.196.33
...
```


##### References

* https://team-cymru.com/community-services/ip-asn-mapping/