# REMNux Cheat Sheet

## Admin

`remnux upgrade` - update all tools and adds new ones.  
`remnux update` - updates existing modules and tools.  
`myip` - display internal IP
`code` - Visual Studio Code  

## IOC Hunting

`ipwhois_cli.py --whois --addr 100.100.100.100` - Retrieve and parse whois data for IP addresses.
`malwoverview.py` - add API keys to `~/.malwapi.conf`  
`nsrllookup -k <HASH>` - NSRL known lookup


## Docker Tools

### JSDetox JavaScript Analysis Tool

`docker run -d --rm --name jsdetox -p 3000:3000 remnux/jsdetox`  

`docker stop jsdetox`  




## Tools

`cyberchef`  - Decode and otherwise analyze data using this browser app.  
`xorsearch`  - Locate and decode strings obfuscated using common techniques. 
`chepy` - Decode and otherwise analyze data using this command-line tool and Python library.  
`xortool` - Analyze XOR-encoded data. 

