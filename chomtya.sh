#!/bin/bash
#title: CHOMTYA-XLR8
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Scans
#author:        R12W4N
#version:       3.5.6
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
  echo "Usage: ./chomtya.sh -p <ProjectName> -d <domain.com> -i <127.0.0.1> -brt -n"
  echo "Usage: ./chomtya.sh -p <ProjectName> -i <127.0.0.1> [option]"
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
  echo "Example: ./chomtya.sh -p projectname -d example.com -brt"
  echo "Example: ./chomtya.sh -p projectname -d Domains-list.txt"
  echo "Example: ./chomtya.sh -p projectname -i 127.0.0.1"
  echo "Example: ./chomtya.sh -p projectname -i IPs-list.txt -n"
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
            counter
            echo IP Module $ip $ipscan
            portscanner $ip
            iphttpx $ipport
        elif [[ -z ${ipscan} ]]; then
            ColorBlue '[I] INFO: IP not specified.. Check -i again\n\n'$ip  >&2
        fi
        
        if [[ ${domainscan} == true ]];then
            counter
            echo Domain Module $domain $domainscan
            mkdir -p Results/$project/$domain
            cp results.log Results/$project/$domain
            if [ -f "$domain" ]; then
                portscanner $domain
                iphttpx $hostport
            else
                getsubdomains
                portscanner $sdc
                iphttpx $hostport
            fi
            
            
            #if [[ ${portscan} == "true" ]];then portscanner $sdc; fi
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

    if [[ ${ipscan} == true ]];then
        naabuout="Results/$project/naabu.csv"
        nmapscans="Results/$project/nmapscans"
        aliveip="Results/$project/aliveip.txt"
        httpxout="Results/$project/httpxout.csv"
        hostport="Results/$project/hostport.txt"
        ipport="Results/$project/ipport.txt"
	webtech="Results/$project/webanalyze.csv"
        urlprobed="Results/$project/urlprobed.txt"
        apache="Results/$project/apache-sd.txt"
        apachetomcat="Results/$project/apache-tomcat-sd.txt"
        nginx="Results/$project/nginx-sd.txt"
        wp="Results/$project/wordpress-sd.txt"
        drupal="Results/$project/drupal-sd.txt"
        joomla="Results/$project/joomla-sd.txt"
        jira="Results/$project/jira-urls.txt"
        gitl="Results/$project/gitlab-urls.txt"
        jboss="Results/$project/jboss-urls.txt"
        bigip="Results/$project/bigip-urls.txt"

    fi
      
    if [[ ${domainscan} == true ]];then
        naabuout="Results/$project/$domain/naabu.csv"
        nmapscans="Results/$project/$domain/nmapscans"
        aliveip="Results/$project/$domain/aliveip.txt"
        httpxout="Results/$project/$domain/httpxout.csv"
        hostport="Results/$project/$domain/hostport.txt"
        ipport="Results/$project/$domain/ipport.txt"
        webtech="Results/$project/$domain/webanalyze.csv"
        urlprobed="Results/$project/$domain/urlprobed.txt"
        apache="Results/$project/$domain/apache-sd.txt"
        apachetomcat="Results/$project/$domain/apache-tomcat-sd.txt"
        nginx="Results/$project/$domain/nginx-sd.txt"
        wp="Results/$project/$domain/wordpress-sd.txt"
        drupal="Results/$project/$domain/drupal-sd.txt"
        joomla="Results/$project/$domain/joomla-sd.txt"
        jira="Results/$project/$domain/jira-urls.txt"
        gitl="Results/$project/$domain/gitlab-urls.txt"
        jboss="Results/$project/$domain/jboss-urls.txt"
        bigip="Results/$project/$domain/bigip-urls.txt"
        iis="Results/$project/$domain/iis-urls.txt"

    fi
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
            subfindersd=$(cat $sdc | wc -l)
            [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Total Passive Subdomains Collected by Subfinder${YELLOW} [$subfindersd]${RESET} "
            echo "Updating DNSRecon Output to Subdomains.txt"
            
            csvcut -c Name Results/$project/$domain/dnsreconoutput.csv | grep $domain | grep -v Name | anew Results/$project/$domain/dnsreconurl.txt
            cat Results/$project/$domain/dnsreconurl.txt 2>/dev/null |anew Results/$project/$domain/subdomains.txt   
            
            dnsreconsd=$(cat Results/$project/$domain/dnsreconurl.txt | wc -l)
            [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Total Subdomains Collected by DNS Bruteforcing${YELLOW} [$dnsreconsd]${RESET}"
            
            sed -i -e "/dnsreconsd=/ s/=.*/=$dnsreconsd/" Results/$project/$domain/results.log
            #totalsd=$(( $dnsreconsd + $subfindersd ))  
            #echo "Total Subdomains after adding is $totalsd"
            totalsd=$(cat $sdc | wc -l)
            sed -i -e "/totalsd=/ s/=.*/=$totalsd/" Results/$project/$domain/results.log
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

            totalsd=$(cat Results/$project/$domain/subdomains.txt  | wc -l)
            sed -i -e "/totalsd=/ s/=.*/=$totalsd/" Results/$project/$domain/results.log

            #dnsx -silent -w MISC/subdomains-top1million-5000.txt -d $domain | anew Results/$domain/dnsxout.txt
            #cat Results/$domain/dnsxout.txt | anew Results/$domain/subdomains.txt
        }

        if [[ $dnsbrute == "true" ]]; then
            if is_subdomain_checker; then
                if is_dnsbrute_checker; then
                    echo "DNSBrute File Already Exist: Results/$project/$domain/dnsreconoutput.csv"
                    updatesd && return
                else
                    echo "DNS Recon Subdomain Bruteforcing Scan Initiated"
                    subdomain_brute
                    updatesd && return
                fi
            fi
        fi
}
function domainjod(){
    if ! is_subdomain_checker; then
        subfinder -d $domain | anew Results/$project/$domain/subdomains.txt
        subfindersd=$(cat $sdc | wc -l)
        sed -i -e "/subfindersd=/ s/=.*/=$subfindersd/" Results/$project/$domain/results.log
    fi
}

function getsubdomains(){
    if is_subdomain_checker; then
        echo "Results/$project/$domain/subdomains.txt File Already Exist" || return
        # Todo: ReRun if requested in argument if rerun=yes then run again
    else
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

    scanner(){
        ports=$(cat $ipport| grep $iphost | cut -d ':' -f 2 | xargs | sed -e 's/ /,/g')
            if [ -z "$ports" ]
            then
                echo "No Ports found for $iphost"
            else
                echo -e ${blue}"Running Nmap Scan on"${reset} $iphost ======${blue} $ports ${reset}
                nmap $iphost -p $ports -sV -sC -d -oX $nmapscans/nmapresult-$iphost.xml -oN $nmapscans/nmapresult-$iphost.nmap
            fi
        }    
        
        # This will check if naaabuout file is present than extract aliveip and if nmap=true then run nmap on each ip on respective open ports.
        if [ -f "$naabuout" ]; then
            cat $naabuout | cut -d ',' -f 2 | grep -v ip | anew $aliveip
            if [[ $nmap == "true" ]];then
                mkdir -p $nmapscans
                while read iphost; do
                    scanner  
                done <"$aliveip"
                nmapconverter
            fi
        # else run naabu to initiate port scan
        # start from here
        else
            echo $ip   
            if [ -f "$1" ]; then
                naabu -list $1 -top-ports 1000 -cdn -ec -o $naabuout -csv
                cat $naabuout | cut -d ',' -f 2 | grep -v ip | anew $aliveip
                csvcut -c host,port $naabuout 2>/dev/null | sort -u | grep -v 'host,port' | awk '{ sub(/,/, ":") } 1' | sed '1d' | anew $hostport
                csvcut -c ip,port $naabuout 2>/dev/null | sort -u | grep -v 'ip,port' | awk '{ sub(/,/, ":") } 1' | sed '1d' | anew $ipport
                if [[ $nmap == "true" ]];then
                    mkdir -p $nmapscans
                    while read iphost; do
                        scanner
                    done <"$aliveip"
                    nmapconverter
                fi
            else
                naabu -host $1 -top-ports 1000 -cdn -ec -o $naabuout -csv
                cat $naabuout | cut -d ',' -f 2 | grep -v ip | anew $aliveip
                #csvcut -c host,port $naabuout 2>/dev/null| sort -u | grep -v 'host,port' |awk '{ sub(/,/, ":") } 1' | sed '1d' | anew $hostport
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
    techgorize(){
        # Apache Subdomains
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Apache' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Apache' | cut -d ',' -f 1 | anew $apache
        cat $webtech | grep -E 'Apache' | cut -d , -f 1 | anew $apache

        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Tomcat' | cut -d ',' -f 1,2 --output-delimiter=" ${MAGENTA}>>>${RESET} "
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Tomcat' | cut -d ',' -f 1 | anew $apachetomcat
        cat $webtech | grep -E 'Tomcat' | cut -d , -f 1 | anew $apachetomcat

        # Nginx Subdomains
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Nginx' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Nginx' | cut -d ',' -f 1 | anew $nginx

        # IIS Subdomains
        csvcut -c url,tech $httpxout2 >/dev/null| grep -E 'IIS' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'IIS' | cut -d ',' -f 1 | anew $iis
        cat $webtech | grep -E 'IIS' | cut -d , -f 1 | anew $iis


        # Wordpress Subdomains
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Wordpress|WordPress' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Wordpress|WordPress' | cut -d ',' -f 1 | anew $wp
        cat $webtech | grep -E 'WordPress|Wordpress' | cut -d , -f 1 | anew $wp
        
        # Joomla Subdomains
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Joomla' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Joomla' | cut -d ',' -f 1 | anew $joomla
        cat $webtech | grep -E 'Joomla' | cut -d , -f 1 | anew $joomla

        # Drupal Subdomains
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Drupal' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Drupal' | cut -d ',' -f 1 | anew $drupal

        # Jira Subdomains
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Jira' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'Jira' | cut -d ',' -f 1 | anew $jira

        # Gitlab Subdomains
        csvcut -c url,tech $httpxout 2>/dev/null | grep -E 'GitLab' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
        csvcut -c url,tech $httpxout 2>/dev/null | grep -E 'GitLab' | cut -d ',' -f 1 | anew $gitl

        # JBoss Subdomains
        csvcut -c url,tech $httpxout 2>/dev/null | grep -E 'JBoss' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
        csvcut -c url,tech $httpxout 2>/dev/null | grep -E 'JBoss' | cut -d ',' -f 1 | anew $jboss

        # BigIP Subdomains
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'BigIP' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
        csvcut -c url,tech $httpxout 2>/dev/null| grep -E 'BigIP' | cut -d ',' -f 1 | anew $bigip

        echo "WebTechCheck and Categorization Completed"
        
        # Delete Empty Files in domain Folder
        # find Results/$project/$domain -type f -empty -print -delete

        [ -f $sdc ] && echo -e "${GREEN}[+]${RESET}Total Subdomains [$(cat $sdc | wc -l)]"
        [ -f $psd ] && echo -e "${GREEN}[+]${RESET}Potential Subdomains [$(cat $psd | wc -l)]"
        [ -f $apache ] && echo -e "${GREEN}[+]${RESET}Apache Subdomains [$(cat $apache | wc -l)]"
        [ -f $apachetomcat ] && echo -e "${GREEN}[+]${RESET}Apache Tomcat Subdomains [$(cat $apachetomcat | wc -l)]"
        [ -f $nginx ] && echo -e "${GREEN}[+]${RESET}Nginx Subdomains [$(cat $nginx | wc -l)]"
        [ -f $iis ] && echo -e "${GREEN}[+]${RESET}Nginx Subdomains [$(cat $iis | wc -l)]"
        [ -f $wp ] && echo -e "${GREEN}[+]${RESET}WordPress Subdomains [$(cat $wp | wc -l)]"
        [ -f $drupal ] && echo -e "${GREEN}[+]${RESET}Drupal Subdomains [$(cat $drupal | wc -l)]"
        [ -f $joomla ] && echo -e "${GREEN}[+]${RESET}Joomla Subdomains [$(cat $joomla | wc -l)]"
        [ -f $jira ] && echo -e "${GREEN}[+]${RESET}Jira Subdomains [$(cat $jira | wc -l)]"
        [ -f $gitl ] && echo -e "${GREEN}[+]${RESET}GitLab Subdomains [$(cat $gitl | wc -l)]" 
        [ -f $jboss ] && echo -e "${GREEN}[+]${RESET}JBoss Subdomains [$(cat $jboss | wc -l)]" 
        [ -f $bigip ] && echo -e "${GREEN}[+]${RESET}BigIP Subdomains [$(cat $bigip | wc -l)]"
    }

    if [ -f "$naabuout" ]; then
        excludedports='21|22|44 5|3389'
        webports=$(cat $naabuout | cut -d ',' -f 3 | sort -u | grep -v port | grep -vE $excludedports |xargs | sed -e 's/ /,/g')
        if [ -f "$1" ]; then
            #echo "cat $1 | httpx -p $webports -fr -sc -content-type -location -timeout 60 -retries 2 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout"
            #cat $1 | httpx -p $webports -fr -sc -content-type -location -timeout 60 -retries 2 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout
            echo "cat $1 | httpx -fr -sc -content-type -location -timeout 60 -retries 2 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout"
            cat $1 | httpx -fr -sc -content-type -location -timeout 60 -retries 2 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout
            csvcut $httpxout -c url 2>/dev/null | grep -v url | anew $urlprobed
            echo -e "[${GREEN}I${RESET}] HTTPX Probe Completed\n${RESET}"
            echo -e "[${GREEN}I${RESET}] Running WebTechCheck\n${RESET}" 
            webtechcheck
            techgorize
        elif ! [ -f "$1" ]; then
            cat $naabuout | cut -d ',' -f 2 | grep -v 'ip' | sort -u | anew $aliveip
            echo "cat $1 | httpx -fr -sc -content-type -location -timeout 60 -retries 3 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout"
            cat $1 | httpx -fr -sc -content-type -location -timeout 60 -retries 3 -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o $httpxout
            csvcut $httpxout -c url 2>/dev/null| grep -v url | anew $urlprobed
            webtechcheck
            techgorize
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
      dnsreconbrute
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
