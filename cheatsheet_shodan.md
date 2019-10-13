# Shodan

## Basic Searching

`port:` Search by specific port  
`net:` Search based on an IP/CIDR  
`hostname:` Locate devices by hostname  
`os:` Search by Operating System  
`city:` Locate devices by city  
`country:` Locate devices by country  
`geo:` Locate devices by coordinates  
`org:` Search by organization  
`before/after:` Timeframe delimiter  
`hash:` Search based on banner hash  
`has_screenshot:true` Filter search based on a screenshot being present  
`title:` Search based on text within the title  

## Shodan Command Line

Credits:  
Every query credit gets you up to 100 results, which means that you can download at least 10,000 results every month - regardless of the type of search you're performing.

Initialising:  
`shodan init YOUR_API_KEY`  

Basic syntax:  
`shodan download --limit <number of results> <filename> <search query>`

NB: the filename should be `.json.gz`  

Using the `parse` command:  
`shodan parse --fields ip_str,port,hostname --separator , youroutput.json.gz`

Convert to CSV:  
`shodan convert output.json.gz csv`


## Incident Response

### Cobalt Strike Servers
```
"HTTP/1.1 404 Not Found" "Content-Type: text/plain" "Content-Length: 0" "Date" -"Server" -"Connection" -"Expires" -"Access-Control" -"Set-Cookie" -"Content-Encoding" -"Charset"
```

### Metaspolit
```
ssl:"MetasploitSelfSignedCA" http.favicon.hash:"-127886975"
```

### Empire
```
http.html_hash:"611100469"
```

### Responder
```
"HTTP/1.1 401 Unauthorized" "Date: Wed, 12 Sep 2012 13:06:55 GMT"
```

#### Sources     
https://thor-sec.com/cheatsheet/shodan/shodan_cheat_sheet/  
https://developer.shodan.io/api/banner-specification  
http://orkish5.ddns.net/wp-content/uploads/2018/07/Shodan-Complete-Guide.pdf  
https://twitter.com/cglyer/status/1182024668099862528
https://twitter.com/felixaime/status/1182549481688109056
