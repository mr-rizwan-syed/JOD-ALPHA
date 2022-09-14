#!/bin/bash
#title:         Chomtya-Dependency-Installer

apt install nmap -y
apt install xsltproc -y
apt install csvkit -y
pip install xmlmerge
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
nuclei -update
nuclei -ut
