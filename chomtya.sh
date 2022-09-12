#!/bin/bash
#title: CHOMTYA
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Scans
#author:        R12W4N
#version:       1.0
#==============================================================================
red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
blue=`tput setaf 4`
magneta=`tput setaf 5`
cyan=`tput setaf 6`
reset=`tput sgr0`
wul=`tput smul`

ColorGreen () {
        echo -ne $green$1$reset
}
ColorCyan () {
        echo -ne $cyan$1$reset
}
ColorRed () {
        echo -ne $red$1$reset
}

ColorBlue () {
        echo -ne $blue$1$reset
}


banner(){
echo ${green} '

 ██████╗██╗  ██╗ ██████╗ ███╗   ███╗████████╗██╗   ██╗ █████╗ 
██╔════╝██║  ██║██╔═══██╗████╗ ████║╚══██╔══╝╚██╗ ██╔╝██╔══██╗
██║     ███████║██║   ██║██╔████╔██║   ██║    ╚████╔╝ ███████║
██║     ██╔══██║██║   ██║██║╚██╔╝██║   ██║     ╚██╔╝  ██╔══██║
╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║   ██║      ██║   ██║  ██║
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝
      '  ${reset}                                                      
}



function trap_ctrlc ()
{
    echo "Ctrl-C caught...performing clean up"
    echo "Doing cleanup"
    trap "kill 0" EXIT
    exit 2
}

trap "trap_ctrlc" 4


## Below functions checks for existence of result directories

domaindirectorycheck(){
    if [ -d Results/$project ]
    then
        echo -e
        echo -e "[${RED}I${RESET}] Results/$project Directory already exists...\n${RESET}"
    else
        mkdir -p Results/$project
        echo -e "[${GREEN}I${RESET}] Results/$project Directory Created\n${RESET}"
    fi
    
}

print_usage() {
        printf '
        Chomtya Usage: [-h] [-p project] [-i IPList] [-h help]

        mandatory arguments:
          -i iplist          Newline-delimmited list of targets. Accepts CIDRs or ranges (192.168.0.1-255)        
	  
        optional arguments:
          -h                     Print this help menu
';
}


if [[ $* == *-h ]]; then
        print_usage
        exit 1;
fi

### Argument helper
while getopts "p:i:d:" opt; do
    case "${opt}" in

        p) project=${OPTARG} ;;
        i) iplist=${OPTARG} ip=true;;
        d) domain=${OPTARG} dom=true;;
        *)
            print_usage
            ;;
    esac
done
shift $((OPTIND-1))

## Functions

function var_setter() {
	echo -e "Please enter value for $1: "
	read temp_var
	export $1=$temp_var
	echo -e "[+] $1 is now set to $temp_var !"
}

function var_checker() {
	echo -e "[*] Checking for required arguments..."

	if [[ -z ${project} ]]; then
		ColorRed '[-] ERROR: Project Name is not set\n'
		ColorRed '[-] Missing -p'  >&2
        print_usage
        exit 1
    else
        domaindirectorycheck
    fi

    ########################

    if [[ ${ip} == true ]] || [[ ${dom} == true ]];then
        
        if [[ ${ip} == true ]];then
                echo IP Module $iplist $ip
                portscanner $iplist
                nmapconverter
                functionhttpx $iplist
                nucleiscanner
                echo nuclei $iplist
        elif [[ -z ${iplist} ]]; then
            ColorBlue '[I] INFO: IP not specified.. Check -i again\n\n'$iplist  >&2
        fi

        ## Not Implemented - Use JOD-ALPHA
        if [[ ${dom} == true ]];then
                echo Domain Module $domain $true
                echo subdomainscan $domain
                echo subdomaintko $domain
                echo httpxfunction $domain
                echo waybackurls $domain - gf xss,sqli,idor...
                echo goofuzz $domain
                echo dirsearch $domain
                echo nuclei $domain
        elif [[ -z ${domain} ]]; then
            ColorBlue '[-] INFO: Domain not specified... Check -d again\n\n'$domain  >&2
        fi

    else
        ColorRed '[-] ERROR: IP or domain is not set\n[-] Missing -i or -d\n\n'  >&2
    fi
}


nmapconverter(){
    allxml=$(find Results/$project/nmapscans -type f -name '*.xml' -printf "%p ")
    xmlcom=$(xmlmerge $allxml > Results/$project/nmapscans/mergefinal.xml)
    eval $xmlcom

    python3 MISC/xml2csv.py -f Results/$project/nmapscans/mergefinal.xml -csv Results/$project/nmap.csv
    xsltproc -o Results/$project/nmap.html MISC/nmap-bootstrap.xsl Results/$project/nmapscans/mergefinal.xml 
}

portscanner(){

    naabuout="Results/$project/naabu.csv"
    nmapscans="Results/$project/nmapscans"

    scanner(){
        ports=$(cat $naabuout| grep $iphost | cut -d ',' -f 3 |xargs | sed -e 's/ /,/g')
            if [ -z "$ports" ]
            then
                echo "No Ports found for $iphost"
            else
                echo -e ${blue}"Running Nmap Scan on"${reset} $iphost ======${blue} $ports ${reset}
                nmap $iphost -p $ports -sV -sC -d -oX $nmapscans/nmapresult-$iphost.xml -oN $nmapscans/nmapresult-$iphost.nmap
            fi
        }    

        if [ -f "$naabuout" ]; then
            cat $naabuout | cut -d ',' -f 2 | grep -v ip | sort -u > Results/$project/aliveip.txt
            mkdir -p $nmapscans
            while read iphost; do
                scanner  
            done <"Results/$project/aliveip.txt"
        else
            echo $iplist   #start from here
            if [ -f "$1" ]; then
                naabu -list $1 -o $naabuout -csv
                cat $naabuout | cut -d ',' -f 2 | grep -v ip | sort -u > Results/$project/aliveip.txt
                mkdir -p $nmapscans
                while read iphost; do
                    scanner
                done <"Results/$project/aliveip.txt"
            else 
                naabu -host $1 -o $naabuout -csv
                cat $naabuout | cut -d ',' -f 2 | grep -v ip | sort -u > Results/$project/aliveip.txt
                mkdir -p $nmapscans
                while read iphost; do
                    scanner
                done <"Results/$project/aliveip.txt"
            fi
                
            echo $naabuout
            mkdir -p $nmapscans

        fi    

} 

functionhttpx(){
    httpxout="Results/$project/httpxout.csv"

    if [ -f "$naabuout" ]; then
        webports=$(cat $naabuout | cut -d ',' -f 3 | grep -v port | sort -u |xargs | sed -e 's/ /,/g')
        if [ -f "$1" ]; then
            cat $1 | httpx -p $webports -fr -sc -content-type -location -timeout 60 -retries 3 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout
            csvcut $httpxout -c url | grep -v url | anew Results/$project/urlprobed.txt
        elif ! [ -f "$1" ]; then
            cat $naabuout | cut -d ',' -f 2 | grep -v 'ip' | sort -u | anew Results/$project/aliveip.txt
            cat Results/$project/aliveip.txt | httpx -p $webports -fr -sc -content-type -location -timeout 60 -retries 3 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout
            csvcut $httpxout -c url | grep -v url | anew Results/$project/urlprobed.txt
        fi
    else
        echo $naabuout
        ColorRed "Need to scan port"
    fi

}

function nucleiscanner(){
    nuclei -l Results/$project/urlprobed.txt -o Results/$project/nucleiresults.txt
}

banner
var_checker





