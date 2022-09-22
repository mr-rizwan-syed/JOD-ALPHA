#!/bin/bash
#title: CHOMTYA-XLR8
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Scans
#author:        R12W4N
#version:       3.5
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

# Show usage via commandline arguments
print_usage() {
  banner
  echo "~~~~~~~~~~~"
  echo " U S A G E"
  echo "~~~~~~~~~~~"
  echo "Usage: ./chomtya-xlr8.sh -p <ProjectName> -d <domain.com> -i <127.0.0.1> [option]"
  echo "  Mandatory Flags:"
  echo "    -p  | --project    : Specify Project Name here"
  echo "    -d  | --domain     : Specify Root Domain here"
  echo "    -i  | --ip         : Specify IP / CIDR/ IPlist here"
  echo " Optional Flags "
  echo "    -n  | --nmap       : Nmap Scan against open ports"
  echo "    -dns | --dnsbrute  : DNS Recon Bruteforce" 
  echo "    -h | --help        : Show this help"
  echo ""
  exit
}

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

function var_checker(){
    echo -e "[*] Checking for required arguments..."

	if [[ -z ${project} ]]; then
		ColorRed '[-] ERROR: Project Name is not set\n'
		ColorRed '[-] Missing -p'  >&2
        print_usage
        exit 1
    else
        domaindirectorycheck
    fi
    #####################################################

    if [[ ${ipscan} == true ]] || [[ ${domainscan} == true ]];then
        
        if [[ ${ipscan} == true ]];then
            echo IP Module $ip $ipscan
            portscanner $ip
            iphttpx $ip
        elif [[ -z ${ipscan} ]]; then
            ColorBlue '[I] INFO: IP not specified.. Check -i again\n\n'$ip  >&2
        fi
        
        if [[ ${domainscan} == true ]];then
            echo Domain Module $domain $domainscan
            mkdir -p Results/$project/$domain
            cp results.log Results/$project/$domain
            getsubdomains
            portscanner $sdc
        elif [[ -z ${domain} ]]; then
            ColorBlue '[-] INFO: Domain not specified... Check -d again\n\n'$domain  >&2
        fi

    else
        ColorRed '[-] ERROR: IP or domain is not set\n[-] Missing -i or -d\n\n'  >&2
    fi
    ########################################################
}

function counter(){
    sdc=Results/$project/$domain/subdomains.txt
    psd=Results/$project/$domain/potential-sd.txt
    apache=Results/$project/$domain/apache-sd.txt
    apachetomcat=Results/$project/$domain/apache-tomcat-sd.txt
    wp=Results/$project/$domain/wordpress-sd.txt
    drupal=Results/$project/$domain/drupal-sd.txt
    joomla=Results/$project/$domain/joomla-sd.txt
    jira=Results/$project/$domain/jira-urls.txt
    gitl=Results/$project/$domain/gitlab-urls.txt
    jboss=Results/$project/$domain/jboss-urls.txt
    bigip=Results/$project/$domain/bigip-urls.txt
}

function checker(){
    
    is_subdomain_checker(){
        test -f "Results/$project/$domain/subdomains.txt"
    }
    
    is_dnsbrute_checker(){
        test -f "Results/$project/$domain/dnsreconoutput.csv"
    }
    
    is_dirsearch_checker(){
        test -f "Results/$project/$domain/$URL/dirsearch.csv"
    }
    
    is_all_sd_checker(){
        test -f "Results/$domain/all-sd-url.txt"
        test -f "Results/$domain/all-sd-url-stripped.txt"
    }
}

function dnsreconbrute(){

        function updatesd(){
            echo "Subdomain File >>>> $sdc"
            [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Total Passive Subdomains Collected by Subfinder${YELLOW} [$(cat $sdc | wc -l)]${RESET} "
            echo "Updating DNSRecon Output to Subdomains.txt"
            csvcut -c Name Results/$project/$domain/dnsreconoutput.csv | grep -v Name | anew Results/$project/$domain/subdomains.txt > Results/$project/$domain/dnsreconurl.txt
            [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Total Subdomains Collected by DNS Bruteforcing${YELLOW} [$(cat $sdc | wc -l)]${RESET}"
        } 

        function subdomain_brute(){

            [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Total Passive Subdomains Collected${YELLOW} [$(cat $sdc | wc -l)]${RESET} "
            
            echo "${BLUE}[+]${RESET}Initiating DNSRecon Bruteforcing"
            dnsrecon -d $domain -D $(pwd)/MISC/subdomains-top1million-5000.txt -t brt -c $(pwd)/Results/$project/$domain/dnsreconoutput.csv
            csvcut -c Name Results/$project/$domain/dnsreconoutput.csv | grep $domain | grep -v Name | anew Results/$project/$domain/dnsreconurl.txt
            cat Results/$project/$domain/dnsreconurl.txt |anew Results/$project/$domain/subdomains.txt        
            find Results/$project/$domain -type f -empty -print -delete
            
            dnsreconsd=$(cat Results/$project/$domain/dnsreconurl.txt | wc -l)
            sed -i -e "/dnsreconsd=/ s/=.*/=$dnsreconsd/" Results/$project/$domain/results.log

            dnsbrtc=$(cat Results/$project/$domain/results.log | grep dnsreconsd | cut -d = -f 2)

            [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Total Subdomains Collected by DNS Bruteforcing${YELLOW} $dnsbrtc ${RESET}"

            #dnsx -silent -w MISC/subdomains-top1million-5000.txt -d $domain | anew Results/$domain/dnsxout.txt
            #cat Results/$domain/dnsxout.txt | anew Results/$domain/subdomains.txt
        }

        if [[ $dnsbrute == "true" ]]; then
            if is_subdomain_checker; then
                if is_dnsbrute_checker; then
                    echo "DNSBrute File Already Exist: Results/$project/$domain/dnsreconoutput.csv"
                    subfindersd=$(cat $sdc | wc -l)
                    dnsreconsd=$(cat Results/$project/$domain/dnsreconurl.txt | wc -l)
                    sed -i -e "/dnsreconsd=/ s/=.*/=$dnsreconsd/" Results/$project/$domain/results.log
                    totalsd=$(( $dnsreconsd + $subfindersd ))
                    sed -i -e "/totalsd=/ s/=.*/=$totalsd/" Results/$project/$domain/results.log
                    updatesd && return
                else
                    echo "DNS Recon Subdomain Bruteforcing Scan Initiated"  
                    subdomain_brute
                fi
            fi
        fi
}
function domainjod(){
    if ! is_subdomain_checker; then
        subfinder -d $domain | anew Results/$project/$domain/subdomains.txt
        subfindersd=$(cat $sdc | wc -l)
        sed -i -e "/subfindersd=/ s/=.*/=$subfindersd/" Results/$project/$domain/results.log
        sed -i -e "/totalsd=/ s/=.*/=$subfindersd/" Results/$project/$domain/results.log
    fi
}

function getsubdomains(){
    if is_subdomain_checker; then
        counter
        echo "Results/$project/$domain/subdomains.txt File Already Exist" || return
        # Todo: ReRun if requested in argument if rerun=yes then run again
    else
        counter
        domainjod
        dnsreconbrute
    fi
}

function nmapconverter(){
    allxml=$(find Results/$project/nmapscans -type f -name '*.xml' -printf "%p ")
    xmlcom=$(xmlmerge $allxml > Results/$project/nmapscans/mergefinal.xml)
    eval $xmlcom

    python3 MISC/xml2csv.py -f Results/$project/nmapscans/mergefinal.xml -csv Results/$project/nmap.csv
    xsltproc -o Results/$project/nmap.html MISC/nmap-bootstrap.xsl Results/$project/nmapscans/mergefinal.xml 
}

function portscanner(){

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
            if [ $nmap == true ];then
                mkdir -p $nmapscans
                while read iphost; do
                    scanner  
                done <"Results/$project/aliveip.txt"
                nmapconverter
            fi
        else
            echo $ip   #start from here
            if [ -f "$1" ]; then
                naabu -list $1 -o $naabuout -csv
                cat $naabuout | cut -d ',' -f 2 | grep -v ip | sort -u > Results/$project/aliveip.txt
                
                if [[ $nmap == "true" ]];then
                    mkdir -p $nmapscans
                    while read iphost; do
                        scanner
                    done <"Results/$project/aliveip.txt"
                    nmapconverter
                fi
            else
                naabu -host $1 -o $naabuout -csv
                cat $naabuout | cut -d ',' -f 2 | grep -v ip | sort -u > Results/$project/aliveip.txt
                    if [[ $nmap == "true" ]];then
                        mkdir -p $nmapscans
                        while read iphost; do
                            scanner
                        done <"Results/$project/aliveip.txt"
                        nmapconverter
                    fi
	        fi
                
            echo $naabuout
            mkdir -p $nmapscans
        fi    

}

function iphttpx(){
    httpxout="Results/$project/httpxout.csv"
    webtech="Results/$project/webanalyze.csv"
    webtechcheck(){
        webanalyze -update
        webanalyze -hosts Results/$project/urlprobed.txt -silent -crawl 2 -redirect -output csv 2>/dev/null | tee $webtech

    }
    if [ -f "$naabuout" ]; then
        webports=$(cat $naabuout | cut -d ',' -f 3 | grep -v port | sort -u |xargs | sed -e 's/ /,/g')
        if [ -f "$1" ]; then
            cat $1 | httpx -p $webports -fr -sc -content-type -location -timeout 60 -retries 3 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout
            csvcut $httpxout -c url | grep -v url | anew Results/$project/urlprobed.txt
            webtechcheck
        elif ! [ -f "$1" ]; then
            cat $naabuout | cut -d ',' -f 2 | grep -v 'ip' | sort -u | anew Results/$project/aliveip.txt
            cat Results/$project/aliveip.txt | httpx -p $webports -fr -sc -content-type -location -timeout 60 -retries 3 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout
            csvcut $httpxout -c url | grep -v url | anew Results/$project/urlprobed.txt
            webtechcheck
        fi
    else
        echo $naabuout
        ColorRed "Need to scan port"
    fi

}

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      print_usage
      shift 
      ;;
    -p|--project)
      project="$2"
      banner
      domaindirectorycheck
      checker
      counter
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
    -dns|--dnsbrute)
      dnsbrute=true
      dnsreconbrute
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