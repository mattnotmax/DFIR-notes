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

## Remnux Config

### Install Network Miner

```
sudo apt install mono-devel
sudo apt install libcanberra-gtk-module libcanberra-gtk3-module
wget https://www.netresec.com/?download=NetworkMiner -O /tmp/nm.zip
sudo unzip /tmp/nm.zip -d /opt/
cd /opt/NetworkMiner*
sudo chmod +x NetworkMiner.exe
sudo chmod -R go+w AssembledFiles/
sudo chmod -R go+w Captures/

mono NetworkMiner.exe --noupdatecheck
```


### Install .NET Runtime & PowerShell 7

```
wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y aspnetcore-runtime-6.0
sudo apt-get install -y powershell
pwsh
```

### Eric Zimmerman Tools

```
wget https://f001.backblazeb2.com/file/EricZimmermanTools/Get-ZimmermanTools.zip
mkdir /home/remnux/eztools
unzip Get-ZimmermanTools.zip
pwsh
./Get-ZimmermanTools.ps1 -Dest /home/remnux/eztools/ -NetVersion 6
```

### Running Eric Zimmerman Tools

```
# Run the DLL not the exe
dotnet LECmd.dll <args>
```