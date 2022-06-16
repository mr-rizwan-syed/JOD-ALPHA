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


# do something
function counter(){
    sdc=Results/$domain/subdomains.txt
    sdb=Results/$domain/dnsxout.txt 
    apache=Results/$domain/apache-urls.txt
    apachetomcat=Results/$domain/apache-tomcat-urls.txt
    wp=Results/$domain/wordpress-urls.txt
    drupal=Results/$domain/drupal-urls.txt
    joomla=Results/$domain/joomla-urls.txt
    jira=Results/$domain/jira-urls.txt
    gitl=Results/$domain/gitlab-urls.txt
    jboss=Results/$domain/jboss-urls.txt
    bigip=Results/$domain/bigip-urls.txt

    [ -f $sdc ] && echo -e "${GREEN}[+]${RESET}Total Subdomains [$(cat $sdc | wc -l)]"
    [ -f $sdb ] && echo -e "${GREEN}[+]${RESET}Potential Subdomains [$(cat $sdb | wc -l)]"
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


function dnsreconbrute(){
        function subdomain_brute(){
        echo "${BLUE}[+]${RESET}Initiating DNSRecon Bruteforcing"
      
        dnsrecon -d $domain -D $(pwd)/MISC/subdomains-top1million-5000.txt -t brt > Results/$domain/dnsreconoutput.txt
        cat Results/$domain/dnsreconoutput.txt | cut -d " " -f 4 | grep $domain | anew Results/$domain/dnsbrute.txt
        cat Results/$domain/dnsbrute.txt | anew Results/$domain/subdomains.txt
      
        #dnsx -silent -w MISC/subdomains-top1million-5000.txt -d $domain | anew Results/$domain/dnsxout.txt
        #cat Results/$domain/dnsxout.txt | anew Results/$domain/subdomains.txt

        sdct=Results/$domain/subdomains.txt
        echo "${GREEN}[+]${RESET}Total Subdomains including DNS Brute"
        [ -f $sdct ] && echo -e "${GREEN}[*]${RESET}Total Subdomains ${YELLOW} [$(cat $sdct | wc -l)]${RESET} "
        
        }

        if is_dnsbrute_checker; then
            echo "Results/$domain/dnsbrute.txt File Already Exist" || return
        else
            echo $dnsrecon
            if [[ $dnsreconbrute = "true" ]]
            then
                echo "DNS Recon Subdomain Bruteforcing Scan Initiated"
                subdomain_brute
            fi
        fi
}

function subdomains(){
    echo "${GREEN}[1] Gathering Subdomain${RESET}"
    subfinder -d $domain -silent | anew Results/$domain/subdomains.txt
    wait

    sdc=Results/$domain/subdomains.txt
    [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Passive Subdomains Collected${YELLOW} [$(cat $sdc | wc -l)]${RESET}"
   
    echo "${GREEN}[+]${RESET}Probing all Subdomains [Collecting StatusCode,Title,Tech,cname...]"

    cat Results/$domain/subdomains.txt | httpx -silent -sc -content-type -location -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o Results/$domain/$domain-probed.csv
    cat Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | grep -v 'url' | anew Results/$domain/sd-httpx.txt
    csvcut -c url,status-code Results/$domain/$domain-probed.csv | egrep -iv "401|403|404" | cut -d ',' -f 1 | grep -v url | anew Results/$domain/potential-sd.txt
    cat Results/$domain/potential-sd.txt | sed 's/https\?:\/\///' | cut -d ':' -f 1 | anew Results/$domain/sub-url-stripped.txt

    # Apache Subdomains
    echo "${GREEN}Apache Subdomains: ${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Apache' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Apache' | cut -d ',' -f 1 | anew Results/$domain/apache-urls.txt
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Tomcat' | cut -d ',' -f 1,2 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Tomcat' | cut -d ',' -f 1 | anew Results/$domain/apache-tomcat-urls.txt

    # Nginx Subdomains
    echo "${GREEN}Nginx  Subdomains: ${RESET}" 
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Nginx' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Nginx' | cut -d ',' -f 1 | anew Results/$domain/nginx-urls.txt

    # IIS Subdomains
    echo "${GREEN}IIS  Subdomains: ${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'IIS' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'IIS' | cut -d ',' -f 1 | anew Results/$domain/IIS-urls.txt

    # Wordpress Subdomains
    echo "${GREEN}Wordpress Subdomains: ${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Wordpress|WordPress' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Wordpress|WordPress' | cut -d ',' -f 1 | anew Results/$domain/wordpress-urls.txt

    # Joomla Subdomains
    echo "${GREEN}Joomla Subdomains: ${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Joomla' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Joomla' | cut -d ',' -f 1 | anew Results/$domain/joomla-urls.txt

    # Drupal Subdomains
    echo "${GREEN}Drupal Subdomains: ${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Drupal' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Drupal' | cut -d ',' -f 1 | anew Results/$domain/drupal-urls.txt

    # Jira Subdomains
    echo "${GREEN}Jira Subdomains: ${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Jira' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'Jira' | cut -d ',' -f 1 | anew Results/$domain/jira-urls.txt

    # Gitlab Subdomains
    echo "${GREEN}GitLab  Subdomains: ${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'GitLab' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'GitLab' | cut -d ',' -f 1 | anew Results/$domain/gitlab-urls.txt

    # JBoss Subdomains
    echo "${GREEN}JBoss Subdomains: ${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'JBoss' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'JBoss' | cut -d ',' -f 1 | anew Results/$domain/jboss-urls.txt

    # BigIP Subdomains
    echo "${GREEN}BigIP Subdomains: ${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'BigIP' | cut -d ',' -f 1,2 --output-delimiter="${MAGENTA}>>>${RESET}"
    csvcut -c url,technologies Results/$domain/$domain-probed.csv | grep -E 'BigIP' | cut -d ',' -f 1 | anew Results/$domain/bigip-urls.txt

    # Delete Empty Files in domain Folder
    find Results/$domain -type f -empty -print -delete

    counter
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
            cat Results/$domain/Subdomains/$URL/P-URL.txt | sed 's/.*.?//' | sed 's/&/\n/' | sed 's/=.*//' | anew Results/$domain/Subdomains/$URL/JustParameters.txt
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

    [ -z "$URL" ] && askurl || upcvalidator
    echo Got this $URL
    
}

askurl(){
        read -p "${RED}URL: ${RESET}" URL && echo -e
        parametercrawler
    }

runnparamconall(){
    while IFS= read subdo
    do 
        URL=$subdo
        parametercrawler
    done < "Results/$domain/sub-url-stripped.txt"
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
    fi
    
}

function checker(){
    
    is_subdomain_checker(){
        test -f "Results/$domain/subdomains.txt"
        test -f "Results/$domain/$domain-probed.csv"
    }
    
    is_dnsbrute_checker(){
        test -f "Results/$domain/dnsbrute.txt"
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
}



function getsubdomains(){
    if is_subdomain_checker; then
        echo "Results/$domain/subdomains.txt File Already Exist" || return

        # Todo: ReRun if requested in argument if rerun=yes then run again

    else
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
    echo "  4. Gather All Subdomain URLs and run GF Patterns - Auto"
    echo "  5. ReRun, Do Assessment Again on the given Domain"
    echo "  ---"
    echo "  6. Exit"
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
    4) allopt;;
    5) rerun;;
    6) exit 0;;
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
      getsubdomains
      shift 
      ;;
    -dnsr|--dnsrecon)
      dnsreconbrute="true"
      dnsreconbrute
      shift 
      ;;
    -gau|--getallurls)
      getallurls
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
