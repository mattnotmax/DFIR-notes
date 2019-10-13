# Notes for installing and configuring OnionScan

Tested on Windows 10, Windows sub-system for Linux (Ubuntu 18.04)

## Update and install

```
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install golang-go
```

## Edit bashrc

```
sudo nano ~/.bashrc
```

```
export GOROOT=""
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

```
source ~/.bashrc
go version
```

## Install Go dependencies

```
go get github.com/HouzuoGuo/tiedot
go get golang.org/x/crypto/openpgp
go get golang.org/x/net/proxy
go get golang.org/x/net/html
go get github.com/rwcarlsen/goexif/exif
go get github.com/rwcarlsen/goexif/tiff
```

## Install OnionScan

```
go get github.com/s-rah/onionscan
```

## Worthwhile also installing TorSocks

TorSocks will allow you to send bash commands through Tor network. Useful for OSINT

```
sudo apt-get install torsocks
```

To send all commands through TorSocks for that bash session

```
. torsocks on
```

## Edit OnionScan source to enable scanning of v3 Onion addresses

```
cd ~/go/src/github.com/s-rah/onionscan/utils/validation.go
nano validation.go
```

Change range of regex to `{16,56}`. This will actually allow any onion address from 16-56 addresses but...yeah it works:

```
package utils

import (
        "regexp"
        "strings"
)

func IsOnion(identifier string) bool {
        // TODO: At some point we will want to support i2p
        if len(identifier) >= 22 && strings.HasSuffix(identifier, ".onion") {
                matched, _ := regexp.MatchString(`(^|\.)[a-z2-7]{16,56}\.onion$`, identifier)
                return matched
        }
        return false
}
```

## Compile OnionScan

```
go install github.com/s-rah/onionscan
```

## Run! But change the default Tor listen port to allow for new port number 9150:

```
./onionscan -torProxyAddress=127.0.0.1:9150 -verbose thisisyouronionsitev3blahblahblah.onion
```

## Known issues (for me anyway):

For me OnionScan basically hung at the end:

```
2019/10/07 22:08:26 Updating thisisyouronionsitev3blahblahblah.onion --- crawl ---> 9154276203000963695 (database-id)
2019/10/07 22:08:26 Inserting thisisyouronionsitev3blahblahblah.onion --- crawl ---> 1913611600464075093 (database-id)
2019/10/07 22:08:26 Inserting thisisyouronionsitev3blahblahblah.onion --- crawl ---> 6558761444901449001 (database-id)
2019/10/07 22:08:26 Updating thisisyouronionsitev3blahblahblah.onion --- crawl ---> 1746943776256641825 (database-id)
--------------- OnionScan Report ---------------
Generating Report for: thisisyouronionsitev3blahblahblah.onion

High Risk: Apache mod_status is enabled and accessible
         Why this is bad: An attacker can gain very valuable information from this internal status page including IP addresses, co-hosted services and user activity.
         To fix, disable mod_status or serve it on a different port than the configured hidden service.

^C
linux@Matt:~/go/bin$
```

## Get SSH Fingerprint for Shodan searching

```
 ssh-keygen -E md5 -lf <(ssh-keyscan thisisyouronionsitev3blahblahblah.onion 2>/dev/null)
```

## Enjoy!

## Useful Links & References

https://github.com/s-rah/onionscan
https://medium.com/@catalyst256/osint-etag-youre-it-ecd7e923392c
https://sal.as/post/install-golan-on-wsl/
https://osintcurio.us/2019/03/05/apache-mod_status-in-tor-hidden-services-destroy-anonymity/
https://null-byte.wonderhowto.com/how-to/detect-misconfigurations-anonymous-dark-web-sites-with-onionscan-0181366/
https://twitter.com/CharlieVedaa/status/541031447986184192
https://www.vice.com/en_us/article/kb7bg3/onionscan-checks-if-your-dark-web-site-really-is-anonymous
https://rehmann.co/blog/onionscan-cannot-connect-tor-proxy-torproxyaddress-setting-correct/
https://github.com/alecmuffett/the-onion-diaries/blob/master/basic-production-onion-server.md
https://searchsecurity.techtarget.com/news/252448297/Misconfigured-Tor-sites-leave-public-IP-addresses-exposed
