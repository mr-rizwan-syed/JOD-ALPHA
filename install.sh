#!/bin/bash
#title:         JOD-ALPHA-Dependency-Installer


apt install python3 -y
apt install python3-pip -y
apt install git -y
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gf@latest
go install github.com/ameenmaali/qsinject@latest
go install github.com/tomnomnom/qsreplace@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/haccer/subjack@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/rverton/webanalyze/cmd/webanalyze@latest

apt install dnsrecon -y
apt install dirsearch -y

go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
nuclei -update
nuclei -ut 


git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf

git clone https://github.com/r00tkie/grep-pattern.git /tmp/grep-pattern
mv /tmp/grep-pattern/* ~/.gf/

pip install csvkit
