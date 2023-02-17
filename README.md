# CHOMTE.SH

1. Simple and modular code base making it easy to contribute.
2. Fast And fully configurable flags to probe multiple elements.
3. Supports just a target domain as an input.

## Prerequisite
Install Golang
`https://tzusec.com/how-to-install-golang-in-kali-linux/`

## Installation 

`git clone https://github.com/mr-rizwan-syed/JOD-ALPHA`

`cd JOD-ALPHA`

`chmod +x *.sh`

`./install.sh`

```
└─# ./chomte.sh


 ██████╗██╗  ██╗ ██████╗ ███╗   ███╗████████╗███████╗   ███████╗██╗  ██╗
██╔════╝██║  ██║██╔═══██╗████╗ ████║╚══██╔══╝██╔════╝   ██╔════╝██║  ██║
██║     ███████║██║   ██║██╔████╔██║   ██║   █████╗     ███████╗███████║
██║     ██╔══██║██║   ██║██║╚██╔╝██║   ██║   ██╔══╝     ╚════██║██╔══██║
╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║   ██║   ███████╗██╗███████║██║  ██║
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝   ╚═╝   ╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
└─#

~~~~~~~~~~~
 U S A G E
~~~~~~~~~~~
Usage: ./chomte.sh -p <ProjectName> -d <domain.com> -i <127.0.0.1> -brt -n
Usage: ./chomte.sh -p <ProjectName> -i <127.0.0.1> [option]

  Mandatory Flags:
    -p  | --project         : Specify Project Name here
    -d  | --domain          : Specify Root Domain here / Domain List here
    -i  | --ip              : Specify IP / CIDR/ IPlist here
 Optional Flags
    -n  | --nmap            : Nmap Scan against open ports
    -brt | --dnsbrute       : DNS Recon Bruteforce
    -h | --help             : Show this help

Example: ./chomte.sh -p projectname -d example.com -brt
Example: ./chomte.sh -p projectname -d Domains-list.txt
Example: ./chomte.sh -p projectname -i 127.0.0.1
Example: ./chomte.sh -p projectname -i IPs-list.txt -n

```

### Optional
`curl -L https://raw.githubusercontent.com/mr-rizwan-syed/JOD-ALPHA/main/install.sh | bash`

## Acknowledgement

Community contributions have made the project what it is.
