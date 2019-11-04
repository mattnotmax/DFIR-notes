## NMAP for Incident Response

### Target Enumeration

`nmap 192.168.0.0/8`  
`nmap 192.168.0-255.1-254`  
`nmap 100.0.0.1/24 --exclude 100.0.0.5`  

`-iL <filename>`: Input from list. Separated by tabs, spaces or newlines.  
`--exclude <filename>`: Exclude from list.  
`cat list.txt | nmap -iL -`: input from standard input  

### Host Discovery

`-sL`: List scan. DNS resolution and print hosts.  
`-sP`: Ping scan. Only perform ping scan. ICMP echo request and TCP ACK packet to port 80.  
`-PN`: No ping scan. All other scans will be performed on all targets.  

### Reverse-DNS resolution

`-n`: No DNS Resolution  
`-R`: DNS resolution for all targets  

### Port Scanning
  
`-sS`: TCP SYN Scan  
Probe response:  
- TCP SYN/ACK = open  
- TCP RST = closed  
- No response = filtered  
- ICMP unreachable = filtered  
  
`-sT`: TCP Connect Scan (default when elevated privs not available)  
`-sU`: UDP Scan  
Probe response:  
- Any UDP response = open  
- No response = open|filtered  
- ICMP port unreachable (type 3) = closed  
- ICMP unreachable = filtered  
  
`-sF`: TCP FIN Scan  
`-sN`: TCP NULL Scan  
`-sX`: Xmas Scan  
Probe Response:  
- No response received = open|filtered  
- TCP RST = closed  
- ICMP unreachable = filtered  

`--scanflags`: Custom TCP scanning  
Example: `--scanflags SYNFIN` or `--scanflags PSH`  

Port Selection:
- `-p 22`: Single port  
- `-p ssh`: Port by name  
- `-p 22,443,8080`: multiple ports  
- `-p-`: all ports except zero  
- `-p http*`: wildcard port names  
- `-p 80-100`: range of ports  
-`-F`: Fast scan. Top 100 ports  

### Version Detection

`-sV`: Version detection.  

### OS Detection

`-O`: Perform OS detection. Good to include with `-v` for verbosity.  
`--osscan-guess`: provides a best guess of OS where unknown.  

### Traceroute

`--traceroute`: Performed post-scan using information from the scan results to determine the port and protocl most likely to reach its target.  


### Script Scanning

`-sC` or `--script=default`: Enable most common scripts. Those in `default` category.   
`--script <name>`: Enable script.  
`--script-args <args>`: add arguments to script. Eg. `--script-args a=foo,b=bar`  

Examples:  
`nmap --script asn-query.nse 100.100.100.1`: Map address to AS.   
`nmap --script ssh_hostkey --script-args ssh_hostkey=all 100.100.110.1`  
`nmap --script vuln,malware,version 100.100.110.1`  


### Output

`-oN`: Normal output.  
`-oX`: XML output.  
`-oG`: GREP output.  
`-oS`: SCrIpT KiDDie output.  
`-oA`: output to all formats. Supply `basename`.  

Arguments: uses `strftime`:  
- `%T = %H%M%S`  
- `%D = %m%d%y`  

Examples:  
`nmap -oX scan-%T-%D.xml 100.110.100.1`  
`nmap -oG - -p80 10.1.1.1/24 | awk '/open/{print $2 " " $3}'`: Grep output to stdout then awk to show IP / Domain. 


### Other

`-T1, -T2, -T3, -T4, -T5`: Higher number results in increase speed of scanning.  
`--reason`: provide more detailed reason for port status.  
`--open`: show only open ports.  
`-A`: Aggressive scanning: Same as `-O -sV -sC --traceroute`.  

NMAP Port States:

`open`: Application is actively accepting TCP/UDP connections.  
`closed`: Port is accessible but no application listening on it.  
`filtered`: Port state cannot be determined. Could be firewall, router, host-based firewall.  
`unfiltered`: Port is accessible but unable to determine if it's open or closed. Only from ACK scan.  
`open|filtered`: Unable to determine if port is open or filtered. Open port gives no response.  
`closed|filtered`: Unable to determine if port is closed or filtered. On for IP ID scan (`-sI`).  

Source: NAMP Network Scanning by Gordon 'Fyodor' Lyon.


