#!/bin/bash
#title:         Chomtya-Dependency-Installer

apt install nmap
apt install xsltproc
pip install xmlmerge
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
nuclei -update
nuclei -ut
