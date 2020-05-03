# Random Linux notes

Get current public IP

```
 wget -qO- http://ipecho.net/plain ; echo
 ```


Install impacket

```
$ git clone https://github.com/SecureAuthCorp/impacket.git
$ sudo apt install virtualenv
$ virtualenv impacket-venv
$ source impacket-venv/bin/activate
(impacket-venv) $ cd ~/impacket
(impacket-venv) impacket/$ pip3 install -r requirements.txt
(impacket-venv) impacket/$ pip3 install .
(impacket-venv) impacket/$ cd ~/impacket-venv/bin
(impacket-venv) impacket-venv/bin/$ python3 ./GetADUsers.py
```
