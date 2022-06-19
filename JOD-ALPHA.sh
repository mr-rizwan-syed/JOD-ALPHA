#!/bin/bash
#title:         JOD-ALPHA
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Scans
#author:        R12W4N
#version:       1.5.2
#==============================================================================
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
MAGENTA=`tput setaf 5`
CYAN=`tput setaf 6`
RESET=`tput sgr0`
WUL=`tput smul`

function trap_ctrlc ()
{
    echo "Ctrl-C caught...performing clean up"
    echo "Doing cleanup"
    trap "kill 0" EXIT
    exit 2
}

trap "trap_ctrlc" 4


banner(){
    echo '
         
     ██  ██████  ██████         █████  ██      ██████  ██   ██  █████  
     ██ ██    ██ ██   ██       ██   ██ ██      ██   ██ ██   ██ ██   ██ 
     ██ ██    ██ ██   ██ █████ ███████ ██      ██████  ███████ ███████ 
██   ██ ██    ██ ██   ██       ██   ██ ██      ██      ██   ██ ██   ██ 
 █████   ██████  ██████        ██   ██ ███████ ██      ██   ██ ██   ██ 
 '                                                                  
}

function counter(){
    sdc=Results/$domain/subdomains.txt
    psd=Results/$domain/potential-sd.txt
    apache=Results/$domain/apache-sd.txt
    apachetomcat=Results/$domain/apache-tomcat-sd.txt
    wp=Results/$domain/wordpress-sd.txt
    drupal=Results/$domain/drupal-sd.txt
    joomla=Results/$domain/joomla-sd.txt
    jira=Results/$domain/jira-urls.txt
    gitl=Results/$domain/gitlab-urls.txt
    jboss=Results/$domain/jboss-urls.txt
    bigip=Results/$domain/bigip-urls.txt

}


function dnsreconbrute(){

        function updatesd(){
            echo "Subdomain File >>>> $sdc"
            [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Total Passive Subdomains Collected by Subfinder${YELLOW} [$(cat $sdc | wc -l)]${RESET} "
            echo "Updating DNSRecon Output to Subdomains.txt"
            csvcut -c Name Results/$domain/dnsreconoutput.csv | grep -v Name | anew Results/$domain/subdomains.txt
            [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Total Subdomains Collected by DNSRecon${YELLOW} [$(cat $sdc | wc -l)]${RESET}"
        } 

        function subdomain_brute(){

            [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Total Passive Subdomains Collected${YELLOW} [$(cat $sdc | wc -l)]${RESET} "
                
            echo "${BLUE}[+]${RESET}Initiating DNSRecon Bruteforcing"
            dnsrecon -d $domain -D $(pwd)/MISC/subdomains-top1million-5000.txt -t brt -c $(pwd)/Results/$domain/dnsreconoutput.csv
            csvcut -c Name Results/$domain/dnsreconoutput.csv | grep -v Name | anew Results/$domain/subdomains.txt > Results/$domain/dnsreconurl.txt
           
            find Results/$domain -type f -empty -print -delete
            
            dnsreconsd=$(cat Results/$domain/dnsreconurl.txt | wc -l)
            sed -i -e "/dnsreconsd=/ s/=.*/=$dnsreconsd/" Results/$domain/results.log
            dnsbrtc=$(cat Results/$domain/results.log | grep dnsreconsd | cut -d = -f 2)

            [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Total Subdomains Collected by DNSRecon${YELLOW} $dnsbrtc ${RESET}"


            #dnsx -silent -w MISC/subdomains-top1million-5000.txt -d $domain | anew Results/$domain/dnsxout.txt
            #cat Results/$domain/dnsxout.txt | anew Results/$domain/subdomains.txt
        }
        
        ###########
        if is_dnsbrute_checker; then
            echo "DNSBrute File Already Exist: Results/$domain/dnsreconoutput.csv"
        fi
        ###########


}

function subdomains(){
    echo "${GREEN}[1] Gathering Subdomain${RESET}"
    subfinder -d $domain -silent | anew Results/$domain/subdomains.txt
    wait

    #sdc=Results/$domain/subdomains.txt
    
    subfindersd=$(cat $sdc | wc -l)
    sed -i -e "/subfindersd=/ s/=.*/=$subfindersd/" Results/$domain/results.log
    sdc1=$(cat Results/$domain/results.log | grep subfindersd | cut -d = -f 2)
    [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Passive Subdomains Collected${YELLOW} $sdc1 ${RESET}"

    if [[ $dnsreconbrute = "true" ]]; then
        #is_dnsbrute_checker | updatesd && echo "updatesd" || return
        if is_dnsbrute_checker; then
            echo "DNSBrute File Already Exist: Results/$domain/dnsreconoutput.csv"
            updatesd && return
        else
            echo "DNS Recon Subdomain Bruteforcing Scan Initiated"
            subdomain_brute
        fi
    fi

    echo "${GREEN}[+]${RESET}Probing all Subdomains [Collecting StatusCode,Title,Tech,cname...]"    
    cat Results/$domain/subdomains.txt | httpx -silent -sc -content-type -location -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o Results/$domain/$domain-probed.csv
    csvcut -c url,status-code Results/$domain/$domain-probed.csv | egrep -iv "401|403|404" | cut -d ',' -f 1 | grep -v url | anew Results/$domain/potential-sd.txt
    csvcut -c url Results/$domain/$domain-probed.csv | cut -d ',' -f 1 | grep -v url | anew Results/$domain/all-sd-url.txt
    cat Results/$domain/all-sd-url.txt | sed 's/https\?:\/\///' | cut -d ':' -f 1 | anew Results/$domain/all-sd-url-stripped.txt
    webanalyze -update
    webanalyze -hosts Results/$domain/potential-sd.txt -silent -crawl 2 -redirect -output csv > Results/$domain/webanalyze.csv

    cat Results/$domain/potential-sd.txt | sed 's/https\?:\/\///' | cut -d ':' -f 1 | anew Results/$domain/sub-url-stripped.txt


    # Apache Subdomains
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Apache' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Apache' | cut -d ',' -f 1 | anew Results/$domain/apache-sd.txt
    cat Results/$domain/webanalyze.csv | grep -E 'Apache' | cut -d , -f 1 | anew Results/$domain/apache-sd.txt 

    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Tomcat' | cut -d ',' -f 1,2 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Tomcat' | cut -d ',' -f 1 | anew Results/$domain/apache-tomcat-sd.txt
    cat Results/$domain/webanalyze.csv | grep -E 'Tomcat' | cut -d , -f 1 | anew Results/$domain/apache-tomcat-sd.txt 

    # Nginx Subdomains
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Nginx' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Nginx' | cut -d ',' -f 1 | anew Results/$domain/nginx-sd.txt

    # IIS Subdomains
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'IIS' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'IIS' | cut -d ',' -f 1 | anew Results/$domain/IIS-sd.txt
    cat Results/$domain/webanalyze.csv | grep -E 'IIS' | cut -d , -f 1 | anew Results/$domain/IIS-sd.txt


    # Wordpress Subdomains
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Wordpress|WordPress' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Wordpress|WordPress' | cut -d ',' -f 1 | anew Results/$domain/wordpress-sd.txt
    cat Results/$domain/webanalyze.csv | grep -E 'WordPress|Wordpress' | cut -d , -f 1 | anew Results/$domain/wordpress-sd.txt
    
    # Joomla Subdomains
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Joomla' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Joomla' | cut -d ',' -f 1 | anew Results/$domain/joomla-sd.txt
    cat Results/$domain/webanalyze.csv | grep -E 'Joomla' | cut -d , -f 1 | anew Results/$domain/joomla-sd.txt

    # Drupal Subdomains
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Drupal' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Drupal' | cut -d ',' -f 1 | anew Results/$domain/drupal-sd.txt

    # Jira Subdomains
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Jira' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Jira' | cut -d ',' -f 1 | anew Results/$domain/jira-sd.txt

    # Gitlab Subdomains
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'GitLab' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'GitLab' | cut -d ',' -f 1 | anew Results/$domain/gitlab-sd.txt

    # JBoss Subdomains
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'JBoss' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'JBoss' | cut -d ',' -f 1 | anew Results/$domain/jboss-sd.txt

    # BigIP Subdomains
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'BigIP' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'BigIP' | cut -d ',' -f 1 | anew Results/$domain/bigip-sd.txt

    # Delete Empty Files in domain Folder
    find Results/$domain -type f -empty -print -delete

    [ -f $sdc ] && echo -e "${GREEN}[+]${RESET}Total Subdomains [$(cat $sdc | wc -l)]"
    [ -f $psd ] && echo -e "${GREEN}[+]${RESET}Potential Subdomains [$(cat $psd | wc -l)]"
    [ -f $apache ] && echo -e "${GREEN}[+]${RESET}Apache Subdomains [$(cat $apache | wc -l)]"
    [ -f $apachetomcat ] && echo -e "${GREEN}[+]${RESET}Apache TomcatSubdomains [$(cat $apachetomcat | wc -l)]"
    [ -f $wp ] && echo -e "${GREEN}[+]${RESET}WordPress Subdomains [$(cat $wp | wc -l)]"
    [ -f $drupal ] && echo -e "${GREEN}[+]${RESET}Drupal Subdomains [$(cat $drupal | wc -l)]"
    [ -f $joomla ] && echo -e "${GREEN}[+]${RESET}Joomla Subdomains [$(cat $joomla | wc -l)]"
    [ -f $jira ] && echo -e "${GREEN}[+]${RESET}Jira Subdomains [$(cat $jira | wc -l)]"
    [ -f $gitl ] && echo -e "${GREEN}[+]${RESET}GitLab Subdomains [$(cat $gitl | wc -l)]" 
    [ -f $jboss ] && echo -e "${GREEN}[+]${RESET}JBoss Subdomains [$(cat $jboss | wc -l)]" 
    [ -f $bigip ] && echo -e "${GREEN}[+]${RESET}BigIP Subdomains [$(cat $bigip | wc -l)]" 
}

#########################################################
#Temporary Function 
#########################################################
allbackurls(){
    
  echo -e
        
  while IFS= read url
    do
       echo "Getting All URLs of $url"
       mkdir -p Results/$domain/Subdomains/$URL
       gau $url | anew Results/$domain/Subdomains/$URL/allurls.txt
    done <"Results/$domain/potential-sd.txt"

    cat Results/$domain/Subdomains/$URL/allurls.txt | unfurl -u Results/$domain/subdomains.txt
  
  echo "[${GREEN}I${RESET}] Done with Waybackurls and Gau${RESET}"
}

function getallurls(){
    if is_allurl_checker; then
        echo "Results/$domain/allurls.txt File Already Exist" || return
        # Todo: ReRun if requested in argument if rerun=yes then run again
    else
        allbackurls
    fi

}

# cat allurls.txt | unfurl -u domains
################################################################

dirsearchfunction(){
    rundirsearch(){
        if is_gfurld_checker; then
            echo "Results/Subdomains/$URL/ Folder Already Exist" || return
        else
            mkdir -p Results/$domain/Subdomains/$URL
            echo "[${GREEN}I${RESET}] Started Content Discovery on $URL ${RESET}"
            echo $URL | httpx -silent | { read URL1; dirsearch -u $URL1 -x  301,302,400,401,403,404,500,503 --random-agent --format=csv -o $(pwd)/Results/$domain/Subdomains/$URL/dirsearch.csv; }
            csvcut -c URL Results/$domain/Subdomains/$URL/dirsearch.csv| grep -v URL | anew Results/$domain/Subdomains/$URL/dirsearchurl.txt
            find Results/$domain/Subdomains/$URL/ -type f -empty -print -delete
        fi
    }

    dirvalidator(){
        
        if is_dirsearch_checker; then
        echo "Dirsearch.csv file  Already Exist for $URL" || return
        else
            rundirsearch
        fi
    }
    
    [ -z "$URL" ] && askurld || dirvalidator
    echo Got this $URL
    
}

#### ParamALL

parametercrawler(){
    
    runpc(){
    
        if is_gfurld_checker; then
            echo "Results/Subdomains/$URL/ Directory Already Exist" || return
        else
            echo Scannning $URL
            mkdir -p Results/$domain/Subdomains/$URL
            ##waybackurl-gau
            echo -e
            gau $URL | anew Results/$domain/Subdomains/$URL/all-urls.txt
            echo "[${GREEN}I${RESET}] Done with Gau and Waybackurls ${RESET}"
               
            #Stripping
            echo -e
            cat Results/$domain/Subdomains/$URL/all-urls.txt | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | anew Results/$domain/Subdomains/$URL/P-URL.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | sed 's/.*.?//' | sed 's/&/\n/' | sed 's/=.*//'|grep -v -E 'http|https'|anew Results/$domain/Subdomains/$URL/JustParameters.txt
            echo "[${GREEN}I${RESET}]Extracting URL with Valid Parameters${RESET}"
            cat Results/$domain/Subdomains/$URL/P-URL.txt | qsinject -i 'FUZZ' -iu -decode > Results/$domain/Subdomains/$URL/qsinjected.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf xss | qsinject -i 'FUZZ' -iu -decode | anew -q Results/$domain/Subdomains/$URL/xss.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf sqli | qsinject -i 'FUZZ' -iu -decode | anew -q  Results/$domain/Subdomains/$URL/sqli.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf ssrf | qsinject -i 'FUZZ' -iu -decode | anew -q  Results/$domain/Subdomains/$URL/ssrf.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf ssti | qsinject -i 'FUZZ' -iu -decode | anew -q  Results/$domain/Subdomains/$URL/ssti.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf redirect | qsinject -i 'FUZZ' -iu -decode | anew -q  Results/$domain/Subdomains/$URL/redirect.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf lfi | qsinject -i ' ' | anew -q  Results/$domain/Subdomains/$URL/lfi.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf rce | qsinject -i 'FUZZ' -iu -decode | anew -q  Results/$domain/Subdomains/$URL/rce.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf upload-fields | qsinject -i 'FUZZ' -iu -decode | anew -q  Results/$domain/Subdomains/$URL/upload-fields.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf interestingparams | anew -q Results/$domain/Subdomains/$URL/interestingparams.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf interestingEXT | anew -q Results/$domain/Subdomains/$URL/interestingEXT.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf img-traversal | anew -q Results/$domain/Subdomains/$URL/img-traversal.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf php-sources | anew -q Results/$domain/Subdomains/$URL/php-sources.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf s3-buckets | anew -q Results/$domain/Subdomains/$URL/s3-buckets.txt
            cat Results/$domain/Subdomains/$URL/P-URL.txt | gf servers | anew -q Results/$domain/Subdomains/$URL/servers.txt
            find Results/$domain/Subdomains/$URL/ -type f -empty -print -delete
            find Results/$domain/Subdomains/ -type d -empty -print -delete
        fi

        #gf-patterns
        #Some pattern may find sensitive info that's why string not replaced
        

    }
    
    upcvalidator(){
        
        if is_uniqueparameter_checker; then
        echo "Parameter Results Exist Already for $URL" || return
        else
            runpc
        fi
    }

    [ -z "$URL" ] && askurlp || upcvalidator
    echo Got this $URL
    
}

askurlp(){
        read -p "${RED}URL: ${RESET}" URL && echo -e
        parametercrawler
    }

askurld(){
        read -p "${RED}URL: ${RESET}" URL && echo -e
        dirsearchfunction
    }

runnparamconall(){
    while IFS= read subdo
    do 
        URL=$subdo
        parametercrawler
    done < "Results/$domain/sub-url-stripped.txt"
}

runndirsearchonall(){
    while IFS= read subdo
    do 
        URL=$subdo
        dirsearchfunction
    done < "Results/$domain/all-sd-url-stripped.txt"
    trap "trap_ctrlc" 4
}

alldirsearch(){
    read -p "${RED}Type ${GREEN}Yes${RESET} ${RED}to do Content Discovery on all Subdomains: ${RESET}" response && echo -e
    case "$response" in
        [yY][eE][sS]|[yY]) 
            runndirsearchonall
            ;;
        *)
            cdchoice
            ;;
    esac
}

allopt(){
    read -p "${RED}Type ${GREEN}Yes${RESET} ${RED}to Scan all potential subdomains: ${RESET}" response && echo -e
    case "$response" in
        [yY][eE][sS]|[yY]) 
            runnparamconall
            ;;
        *)
            choicemaker
            ;;
    esac
}

function choicemaker(){
      
    if is_subdomain_checker; then
    echo "Subdomain File Already Exist" || return
    else
        echo "${BLUE}Run Subdomain Scan First"
    fi
    
    echo "${RED}Choose on which domain you want to scan${RESET}"
    select d in $(<Results/$domain/sub-url-stripped.txt);
    do test "$d\c" && break; 
    echo ">>> Invalid Selection";
    done;
    URL=$d
}

function cdchoice(){
      
    if is_all_sd_checker; then
    echo "Subdomain File Already Exist" || return
    else
        echo "${BLUE}Run Subdomain Scan First"
    fi
    
    echo "${RED}Choose on which domain you want to scan${RESET}"
    select d in $(<Results/$domain/all-sd-url-stripped.txt);
    do test "$d\c" && break; 
    echo ">>> Invalid Selection";
    done;
    URL=$d
}

function startp(){
    while true; do
        choicemaker
        parametercrawler
        read -p "${BLUE}Do you want to run it again on each subdomains ${RESET}[y/n]?" yn
        case $yn in
            [Yy]* ) startp; break;;
            [Nn]* ) break;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

function cdchoiceloop(){
    while true; do
        cdchoice
        dirsearchfunction
        read -p "${BLUE}Do you want to run it again on each subdomains ${RESET}[y/n]?" yn
        case $yn in
            [Yy]* ) cdchoiceloop; break;;
            [Nn]* ) break;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

function contentdiscovery(){
    while IFS= read sdurl
    do 
        URL=$sdurl
        dirsearchfunction
    done < "Results/$domain/all-sd-url-stripped.txt" 
}


function subdomaintko(){
    echo -e "[*] Checking for Subdomain Takeover Scan"
    subjack -w $project/subdomains/subdomains.txt -t 100 -timeout 30 -c config/config.json > $results/subjacktko.txt && cat $results/subjacktko.txt
    
}




## Below functions checks for existence of result directories

domaindirectorycheck(){
    echo Results/$domain

    if [ -d Results/$domain ]
    then
        echo -e
        echo -e "[${RED}I${RESET}] Results/$domain Directory already exists...${RESET}"
    else
        mkdir -p Results/$domain

        echo -e "[${GREEN}I${RESET}] Results/$domain Directory Created${RESET}"
        cp results.log Results/$domain/
    fi
    
}

function checker(){
    
    is_subdomain_checker(){
        test -f "Results/$domain/subdomains.txt"
        test -f "Results/$domain/$domain-probed.csv"
    }
    
    is_dnsbrute_checker(){
        test -f "Results/$domain/dnsreconoutput.csv"
    }

    is_allurl_checker(){
        test -f "Results/$domain/allurls.txt"
    }

    is_gfurld_checker(){
        test -d "Results/Subdomains/$URL/"
    }

    is_uniqueparameter_checker(){
        test -f "Results/$domain/Subdomains/$URL/all-urls.txt"
        test -f "Results/$domain/Subdomains/$URL/P-URL.txt"
    }
    
    is_dirsearch_checker(){
        test -d "Results/$domain/Subdomains/$URL/dirsearch.csv"
    }
    
    is_all_sd_checker(){
        test -f "Results/$domain/all-sd-url.txt"
        test -f "Results/$domain/all-sd-url-stripped.txt"
    }
}

function getsubdomains(){
    if is_subdomain_checker; then
        echo "Results/$domain/subdomains.txt File Already Exist" || return
        counter
        # Todo: ReRun if requested in argument if rerun=yes then run again
    else
        counter
        subdomains
        
    fi
}

# Show usage via commandline arguments
usage() {
  banner
  echo "~~~~~~~~~~~"
  echo " U S A G E"
  echo "~~~~~~~~~~~"
  echo "Usage: ./jod-alpha.sh [option]"
  echo "  options:"
  echo "    -d    : Specify Domain here, This will Gather Subdomains"
  echo "    -gau  : Gather All Subdomain URLs Only"
  echo "    -gf   : Gather Subdomain URLs and run GF Patterns - Choice Menu"
  echo "    -all  : Gather All Subdomain URLs and run GF Patterns - Auto"
  echo "    -rr   : ReRun, Do Assessment Again on the given Domain"
  echo "    -i    : Show interactive menu"
  echo "    -h    : Show this help"
  echo ""
  exit
}

# Function to display menu options
show_menus() {
    banner
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "Main Menu"
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "  1. Gather Subdomains"
    echo "  2. Collect All URLs"
    echo "  3. Gather Subdomain URLs and run GF Patterns - Choice Menu"
    echo "  4. ReRun, Do Assessment Again on the given Domain"
    echo "  ---"
    echo "  0. Exit"
    echo ""
}

# Function to read menu input selection and take a action
read_options(){
    local choice
    read -p "Enter choice [ 1 - 2 ] " choice
    case $choice in
    1) getsubdomains;;
    2) getallurls;;
    3) startp;;
    5) rerun;;
    0) exit 0;;
    *) echo -e "${RED}Error...${RESET}" && sleep 2
    esac
}

# Use menu...
do_menu() {
  # Main menu handler loop
  while true
  do
    show_menus
    read_options
  done
}

# If no arguments provided, display usage information

#[[ -n "$2" ]] || usage

# Process command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      usage
      shift 
      ;;
    -d|--domain)
      domain="$2"
      domaindirectorycheck
      checker
      dnsreconbrute
      getsubdomains
      shift 
      ;;
    -dnsr|--dnsrecon)
      dnsreconbrute="true"
      shift 
      ;;
    -gau|--getallurls)
      getallurls
      shift 
      ;;
    -cd|--contentdiscovery)
      cdchoiceloop
      shift 
      ;;
    -acd|--alldirsearch)
      alldirsearch
      shift 
      ;;
    -rr|--rerun)
      rerun=yes
      shift 
      ;;
    -gf|--gfpatterns)
      startp
      shift 
      ;;
    -all|--allurls)
      allopt
      shift 
      ;;
    -i|--interactive)
      do_menu
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

if [[ -n $1 ]]; then
    usage
fi
