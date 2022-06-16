#!/bin/bash
#title:         JOD-ALPHA-Dependency-Installer

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

apt install dnsrecon -y

go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
nuclei -u
nuclei -ut 


git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf

git clone https://github.com/r00tkie/grep-pattern.git /tmp/grep-pattern
mv /tmp/grep-pattern/* ~/.gf/

pip install csvkit

wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -P ./MISC/
