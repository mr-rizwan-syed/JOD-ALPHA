#!/bin/bash
#title: CHOMTE.SH
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Scans
#author:        R12W4N
#version:       3.5.6
#==============================================================================
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
MAGENTA=`tput setaf 5`
CYAN=`tput setaf 6`
NC=`tput sgr0`
wul=`tput smul`

banner(){
echo ${GREEN} '

 ██████╗██╗  ██╗ ██████╗ ███╗   ███╗████████╗███████╗   ███████╗██╗  ██╗
██╔════╝██║  ██║██╔═══██╗████╗ ████║╚══██╔══╝██╔════╝   ██╔════╝██║  ██║
██║     ███████║██║   ██║██╔████╔██║   ██║   █████╗     ███████╗███████║
██║     ██╔══██║██║   ██║██║╚██╔╝██║   ██║   ██╔══╝     ╚════██║██╔══██║
╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║   ██║   ███████╗██╗███████║██║  ██║
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝   ╚═╝   ╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
      '  ${NC}                                                      
}

function trap_ctrlc ()
{
    echo "Ctrl-C caught...performing clean up"
    echo "Doing cleanup"
    trap "kill 0" EXIT
    exit 2
}

trap "trap_ctrlc" 4

# Show usage via commandline arguments
print_usage() {
  banner
  echo "${MAGENTA}"
  echo "~~~~~~~~~~~"
  echo " U S A G E"
  echo "~~~~~~~~~~~"
  echo "Usage: ./chomte.sh -p <ProjectName> -d <domain.com> -i <127.0.0.1> -brt -n"
  echo "Usage: ./chomte.sh -p <ProjectName> -i <127.0.0.1> [option]"
  echo ""
  echo "  Mandatory Flags:"
  echo "    -p  | --project         : Specify Project Name here"
  echo "    -d  | --domain          : Specify Root Domain here / Domain List here"
  echo "    -i  | --ip              : Specify IP / CIDR/ IPlist here"
  echo " Optional Flags "
  echo "    -n  | --nmap            : Nmap Scan against open ports"
  echo "    -brt | --dnsbrute       : DNS Recon Bruteforce"
  echo "    -h | --help             : Show this help"
  echo ""
  echo "Example: ./chomte.sh -p projectname -d example.com -brt"
  echo "Example: ./chomte.sh -p projectname -d Domains-list.txt"
  echo "Example: ./chomte.sh -p projectname -i 127.0.0.1"
  echo "Example: ./chomte.sh -p projectname -i IPs-list.txt -n"
  echo ""
  echo "${NC}"
  exit
}

domaindirectorycheck(){
    if [ -d Results/$project ]
    then
        echo -e
        echo -e "${BLUE}[I] Results/$project Directory already exists...\n${NC}"
    else
        mkdir -p Results/$project
        echo -e "${BLUE}[I] Results/$project Directory Created\n${NC}" 
    fi
    
}

function var_checker(){
    echo -e "${BLUE}[*] Checking for required arguments...${NC}"

	if [[ -z ${project} ]]; then
		echo -e "${RED}[-] ERROR: Project Name is not set${NC}"
		echo -e "${RED}[-] Missing -p ${NC}"
        print_usage
        exit 1
    else
        domaindirectorycheck
    fi
    #####################################################

    if [[ ${ipscan} == true ]] || [[ ${domainscan} == true ]];then

        [[ ${domainscan} == true ]] && rundomainscan
        [[ ${ipscan} == true ]] && runipscan     

    else
        echo -e "${RED}[-] ERROR: IP or domain is not set\n[-] Missing -i or -d${NC}"    
    fi
}

function declared_paths(){
    subdomains="Results/$project/$domain/subdomains.txt"  
     
    if [[ ${domainscan} == true ]];then
        dnsreconout="Results/$project/$domain/dnsrecon.txt"
        naabuout="Results/$project/$domain/naabu.csv"
        nmapscans="Results/$project/$domain/nmapscans"
        aliveip="Results/$project/$domain/aliveip.txt"
        httpxout="Results/$project/$domain/httpxout.csv"
        hostport="Results/$project/$domain/hostport.txt"
        ipport="Results/$project/$domain/ipport.txt"
    fi

    if [[ ${ipscan} == true ]];then
        naabuout="Results/$project/naabu.csv"
        nmapscans="Results/$project/nmapscans"
        aliveip="Results/$project/aliveip.txt"
        httpxout="Results/$project/httpxout.csv"
        hostport="Results/$project/hostport.txt"
        ipport="Results/$project/ipport.txt"
    fi
}

####################################################################
function dnsreconbrute(){
    # DNS Subdomain Bruteforcing
    if [[ "${dnsbrute}" == true ]]; then
        if [ ! -f "${dnsreconout}" ]; then
            echo -e "${dnsreconout} File does not exist"
            echo -e "${YELLOW}[*] Bruteforcing Subdomains DNSRecon${NC}"
            dmut --update-files &>/dev/null
            dmut -u "$domain" -w 100 -d MISC/subdomains-top1million-5000.txt --dns-retries 3 -s /root/.dmut/resolvers.txt --dns-errorLimit 25 --dns-timeout 300 -o $dnsreconout
            dnsbrute_sdc=$(cat $subdomains | anew $dnsreconout | wc -l)
            total_sdc=$(cat $subdomains | wc -l)
            echo -e "${GREEN}[+] New Unique Subdomains found by bruteforcing${NC}[$dnsbrute_sdc]"
            echo -e "${GREEN}[+] Total Subdomains Enumerated${NC}[$total_sdc]"
        else
            echo -e "${BLUE}[I] $dnsreconout already exists...SKIPPING...${NC}"
        fi
    fi
}

function getsubdomains(){
    # Subdomain gathering
    if [ -f ${subdomains} ]; then
        echo -e "${CYAN}[I] $subdomains already exists...SKIPPING...${NC}"
    else [ ! -f ${subdomains} ];
        echo -e "${BLUE}[*] Gathering Subdomains${NC}"
        subfinder -d $1 | anew $subdomains
        sdc=$(<$subdomains wc -l)
        echo -e "${GREEN}[+] Subdomains Collected ${NC}[$sdc]"
    fi
}

function nmapconverter(){
    # Convert to csv
    ls $nmapscans/*.xml | xargs -I {} python3 $PWD/MISC/xml2csv.py -f {} -csv {}.csv &>/dev/null 
    echo -e "${GREEN}[+] All Nmap CSV Generated ${NC}[$sdc]"
    
    # Merge all csv
    first_file=$(ls $nmapscans/*.csv | head -n 1)
    head -n 1 "$first_file" > $nmapscans/Nmap_Final_Merged.csv
    tail -q -n +2 $nmapscans/*.csv >> $nmapscans/Nmap_Final_Merged.csv
    echo -e "${GREEN}[+] Merged Nmap CSV Generated $nmapscans/Nmap_Final_Merged.csv${NC}[$sdc]"

    # Generating HTML Report Format
    ls $nmapscans/*.xml | xargs -I {} xsltproc -o {}_nmap.html MISC/nmap-bootstrap.xsl {} 
    echo -e "${GREEN}[+] HTML Report Format Generated ${NC}[$sdc]"
    
    # Generating RAW Colored HTML Format
    ls $nmapscans/*.nmap | xargs -I {} cat {} | ccze -A | ansi2html > {}.html
    echo -e "${GREEN}[+] HTML RAW Colored Format Generated ${NC}[$sdc]"
}

function portscanner(){
    # Port Scanning Start with Nmap
    scanner(){
        ports=$(cat $ipport| grep $iphost | cut -d ':' -f 2 | xargs | sed -e 's/ /,/g')
            if [ -z "$ports" ]
            then
                echo -e "No Ports found for $iphost"
            else
                echo -e ${CYAN}"[*] Running Nmap Scan on"${NC} $iphost ======${CYAN} $ports ${NC}
                if [ -n "$(find $nmapscans -maxdepth 1 -name 'nmapresult-$iphost*' -print -quit)" ]; then
                    echo -e "${CYAN}Nmap result exists for $iphost, Skipping this host...${NC}"
                else
                    nmap $iphost -p $ports -sV -sC -d -oX $nmapscans/nmapresult-$iphost.xml -oN $nmapscans/nmapresult-$iphost.nmap &>/dev/null
                fi            
            fi
        }    
        
        # This will check if naaabuout file is present than extract aliveip and if nmap=true then run nmap on each ip on respective open ports.
        if [ -f "$naabuout" ]; then
            csvcut -c ip $naabuout | grep -v ip | anew $aliveip
            if [[ $nmap == "true" ]];then
                echo -e ${YELLOW}"[*]Running Nmap Service Enumeration Scan" ${NC}
                mkdir -p $nmapscans
                while read iphost; do
                    scanner  
                done <"$aliveip"
                [ -e "$nmapscans/Nmap_Final_Merged.csv" ] && echo "$nmapscans/Nmap_Final_Merged.csv Exist" || nmapconverter
            fi
        # else run naabu to initiate port scan
        # start from here
        else
            echo $ip   
            if [ -f "$1" ]; then
                echo -e ${YELLOW}"[*]Running Quick Port Scan on $1" ${NC}
                naabu -list $1 -top-ports 1000 -cdn -ec -o $naabuout -csv | pv -p -t -e -N "Naabu Port Scan is Ongoing" > /dev/null
                cat $naabuout | cut -d ',' -f 2 | grep -v ip | anew $aliveip &>/dev/null
                csvcut -c host,port $naabuout 2>/dev/null | sort -u | grep -v 'host,port' | awk '{ sub(/,/, ":") } 1' | sed '1d' | anew $hostport &>/dev/null
                csvcut -c ip,port $naabuout 2>/dev/null | sort -u | grep -v 'ip,port' | awk '{ sub(/,/, ":") } 1' | sed '1d' | anew $ipport &>/dev/null
                if [[ $nmap == "true" ]];then
                    mkdir -p $nmapscans
                    echo -e ${YELLOW}"[*] Running Nmap Scan"${NC}
                    counter=0
                    while read iphost; do
                        scanner
                        counter=$((counter+1))
                        progress=$(($counter * 100 / $(wc -l < "$aliveip")))
                        printf "Progress: [%-50s] %d%%\r" $(head -c $(($progress / 2)) < /dev/zero | tr '\0' '#') $progress
                    done <"$aliveip"
                    [ -e "$nmapscans/Nmap_Final_Merged.csv" ] && echo -e "$nmapscans/Nmap_Final_Merged.csv Exist" || nmapconverter
                fi
            else
                echo -e ${YELLOW}"[*]Running Quick Port Scan on $1" ${NC}
                naabu -host $1 -top-ports 1000 -cdn -ec -o $naabuout -csv | pv -p -t -e -N "Naabu Port Scan is Ongoing" > /dev/null
                cat $naabuout | cut -d ',' -f 2 | grep -v ip | anew $aliveip
                csvcut -c ip,port $naabuout 2>/dev/null | sort -u | grep -v 'ip,port' | awk '{ sub(/,/, ":") } 1' | sed '1d' | anew $ipport
                    if [[ $nmap == "true" ]];then
                        mkdir -p $nmapscans
                        while read iphost; do
                            scanner
                        done <"$aliveip"
                        nmapconverter
                    fi
	        fi
            echo $naabuout
            mkdir -p $nmapscans
        fi    

}

function iphttpx(){

    webtechcheck(){
        webanalyze -update
        webanalyze -hosts $urlprobed -silent -crawl 2 -redirect -output csv 2>/dev/null | tee $webtech
    }

    if [ -f "$naabuout" ]; then
        if [ -f "$1" ]; then
            if [ ! -f $httpxout ]; then
                echo -e "[${GREEN}I${NC}] HTTPX Probe Started\n${NC}"
                echo -e "cat $1 | httpx -fr -sc -content-type -location -timeout 60 -retries 2 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout"
                cat $1 | httpx -fr -sc -content-type -location -timeout 60 -retries 2 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout | pv -p -t -e -N "HTTPX Probing is Ongoing" > /dev/null
                csvcut $httpxout -c url 2>/dev/null | grep -v url | anew $urlprobed
                echo -e "[${GREEN}I${NC}] HTTPX Probe Completed\n${NC}"
                echo -e "[${GREEN}I${NC}] Running WebTechCheck\n${NC}" 
                webtechcheck
            else
                echo -e "$httpxout exist"
            fi
     
        elif ! [ -f "$1" ]; then
            if [ ! -f $httpxout ]; then
                cat $naabuout | cut -d ',' -f 2 | grep -v 'ip' | sort -u | anew $aliveip
                echo "cat $1 | httpx -fr -sc -content-type -location -timeout 60 -retries 3 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout"
                cat $1 | httpx -fr -sc -content-type -location -timeout 60 -retries 3 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout | pv -p -t -e -N "HTTPX Probing is Ongoing" > /dev/null
                csvcut $httpxout -c url 2>/dev/null| grep -v url | anew $urlprobed
                webtechcheck
            else
                echo -e "$httpxout exist"
            fi
        fi
    else
        echo $naabuout
        ColorRed "Need to scan port"
    fi
}    

####################################################################
function rundomainscan(){
    if [ -n "${domain}" ];then
        declared_paths
        echo -e "Domain Module $domain $domainscan"
        if [ -f "$domain" ]; then
            mkdir -p Results/$project/$domain
            portscanner $domain
            iphttpx $hostport
        else
            mkdir -p Results/$project/$domain
            getsubdomains $domain
            dnsreconbrute
            portscanner $subdomains
            iphttpx $hostport
        fi
    else
        echo -e "${RED}[-] Domain not specified.. Check -d again${NC}"
    fi
}

function runipscan(){
    if [ -n "${ip}" ];then
        declared_paths
        echo IP Module $ip $ipscan
        portscanner $ip
        iphttpx $ipport
    else
        echo -e "${RED}[-] IP not specified.. Check -i again${NC}"
    fi
}
#######################################################################

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      print_usage
      shift 
      ;;
    -p|--project)
      project="$2"
      banner
      shift 
      ;;
    -d|--domain)
      domain="$2"
      domainscan=true
      shift 
      ;;
    -i|--ip)
      ip="$2"
      ipscan=true
      shift 
      ;;
    -n|--nmap)
      nmap=true
      shift 
      ;;
    -brt|--dnsbrute)
      dnsbrute=true
      shift
      ;;
    -naabu|--portscan)
      portscan=true
      shift 
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1 
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift 
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if [[ ! -n $1 ]]; then
    print_usage
fi

var_checker