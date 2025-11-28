#!/bin/bash
####################################################
#               Vuln Scanner 2.0                   #
####################################################
#                                                  #
# Por: Doug Ingham (doug@bakis.io)                 #
#                                                  #
####################################################

#######################################
#             Variaveis               #
#######################################

cachedir=".cachedir"
conf_a10_remote="a10data/partconf/INTERNA/pri_default/startup-config"
conf_a10="${cachedir}/${conf_a10_remote}"
scanner_log="vuln-scanner.log"

#######################################
#           Manual de Uso             #
#######################################

print_help(){ echo '

ncat -kl -p8080 > vuln-scanner.log

';}

#######################################
#              Ambiente               #
#######################################

# Verificar dependências
if ! which sshpass >/dev/null; then
        echo "Erro: Instale sshpass para continuar"
        exit 1
fi

if ! which sqlite3 >/dev/null; then
        echo "Erro: Instale sqlite3 para continuar"
        exit 1
fi

if [[ ! -d "$cachedir" ]]; then
        mkdir -p $cachedir
        if [[ $? != 0 ]]; then
                echo "Erro: Não foi possível criar $cachedir"
                exit 1
        fi
elif [[ ! -w "$cachedir" ]]; then
                echo "Erro: Sem permissões de escrita no $cachedir"
                exit 1
fi
mkdir ${cachedir}/nist

if [[ ! -e "$scanner_log" ]]; then
        echo "Erro: $scanner_log não encontrado. Gere um log para continuar."
        print_help
        exit 1
fi

db="$(mktemp -p $cachedir)"
sql="sqlite3 -column $db"
dbcve="$cachedir/cve.db"
sqlcve="sqlite3 -column $dbcve"

# Fazer uma limpeza antes de encerrar o script
function cleanup {
        rm -f "$db"
}
trap cleanup EXIT


#######################################
#               Funções               #
#######################################

# This function is just for reference, it's to be executed on the hosts and isn't called within this script
function identificar_pacotes {
        exit

        include="/opt"
        if [[ -z "$include" ]]; then include="/"; fi
        exclude="(/usr/share)"
        while IFS= read -r -d $'\0' line; do
                # Identify files & folders that match our regex
                if [[ "$line" =~ [a-z0-9._-]+(/|-|.so.)[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                        # Identify non-empty files & folders
                        file=$(find "$line" -maxdepth 0 ! -empty -print0);
                        if [[ -n "$file" ]]; then
                                package=$(printf '%q' "$file" | sed -r 's#.*/([a-z0-9._-]+)(/|-)([0-9]+\.[0-9]+\.[0-9]+)$#\1#');
                                version=$(printf '%q' "$file" | sed -r 's#.*/([a-z0-9._-]+)(/|-)([0-9]+\.[0-9]+\.[0-9]+)$#\3#');
                                echo "{{ ansible_default_ipv4.address }}|$(hostname)|${file}|${package}|${version}" | curl -m1 telnet://10.0.8.12:8080
                                unset file package version
                        fi
                fi
        done < <(locate -0 $include | grep -vE "$exclude")

        ## OUTPUT ##
        ip      |       hostname        |       package |       version
        10.123.123.54|kafka-center|/opt/apache-ranger-2.1.0/knox-agent/target/services/zeppelinws/0.6.0|zeppelinws|0.6.0

        ########################################################################
        ## REF ##
        # locate -0; xargs -0; find -print0; while IFS= read -r -d $'\0' line;
        #if locate --regex 'log4j-(core-)?([0-9]+\.){2}[0-9]+' >/dev/null; then version="$(for i in $(locate --regex 'log4j-(core-)?([0-9]+\.){2}[0-9]+'); do basename $i | grep -Eo '^log4j-(core-)?([0-9]+\.){2}[0-9]+' | grep -Eo '([0-9]+\.){2}[0-9]+'; done | sort -t . -k 1,1n -k 2,2n -k 3,3n | uniq | tr '\n' ' ')"; curl -fs -m1 -d "$(hostname) {{ ansible_default_ipv4.address }} 1 $version -" 10.0.8.12:8080; else curl -fs -m1 -d "$(hostname) {{ ansible_default_ipv4.address }} 0 -" 10.0.8.12:8080; fi; echo -n
        if locate --regex 'log4j-(core-)?([0-9]+\.){2}[0-9]+' >/dev/null; then
                version="$(for i in $(locate --regex 'log4j-(core-)?([0-9]+\.){2}[0-9]+'); do
                                        basename $i | grep -Eo '^log4j-(core-)?([0-9]+\.){2}[0-9]+' | grep -Eo '([0-9]+\.){2}[0-9]+';
                                done | sort -t . -k 1,1n -k 2,2n -k 3,3n | uniq | tr '\n' ' ')";
                curl -q -fs -m1 -d "$(hostname) {{ ansible_default_ipv4.address }} 1 $version -" 10.0.8.12:8080;
        else
                curl -q -fs -m1 -d "$(hostname) {{ ansible_default_ipv4.address }} 0 -" 10.0.8.12:8080;
        fi;
        echo -n
        ########################################################################
}

function initiate_db {
        $sql 'CREATE TABLE service_groups (service_group TEXT, ip TEXT, port INTEGER);' &&
        $sql 'CREATE TABLE domains (domain TEXT, service_group TEXT, ip TEXT, hostname TEXT, port INTEGER);' &&
        $sql 'CREATE TABLE hosts (ip TEXT, hostname TEXT, file TEXT, package TEXT, version TEXT);'
}

# Read service groups & their members, line by line, and save to table "service_groups"
function get_service_groups {
        declare -a service_groups
    while IFS= read -r line; do
                service_groups+=($line)
        done < <(grep -n "^slb service-group " ${conf_a10} | cut -f1,3 -d ' ' | sed 's/slb //g')

        for i in ${!service_groups[@]}; do
                line_num=$(echo ${service_groups[$i]} | cut -d \: -f1)
                service_group=$(echo ${service_groups[$i]} | cut -d \: -f2)

                line=NULL
                until [[ "$line" = "!" ]]; do
                        line=($(sed -n ${line_num}p ${conf_a10}))
                        if [[ "${line[0]}" = "member" ]]; then
                                ip=$(grep "slb server ${line[1]} " ${conf_a10} | cut -d ' ' -f4)
                                port="${line[2]}"
                                $sql "INSERT INTO service_groups VALUES ('$service_group','$ip','$port');"
                        fi
                        let line_num++
                done
        done
}

function insert_log_data {
    while read -r -a line; do
        ip="$(echo $line | cut -d '|' -f1)"
        hostname="$(echo $line | cut -d '|' -f2 | sed 's/.example.local//g')"
        file="$(echo $line | cut -d '|' -f3)"
        package="$(echo $line | cut -d '|' -f4)"
        version="$(echo $line | cut -d '|' -f5)"

                if [[ -z $file ]]; then
                        $sql "INSERT INTO hosts (ip,hostname) VALUES ('$ip','$hostname');"
                else
                        $sql "INSERT INTO hosts (ip,hostname,file,package,version) VALUES ('$ip','$hostname','$file','$package','$version');"
                fi
        done < "${scanner_log}"
}

function search_cves {
        limit=0
        while read -r -a line; do
                package="${line[0]}"
                version="${line[1]}"
                json="${cachedir}/nist/${package}-${version}.json"
                if [[ ! -e "$json" ]]; then
                        curl "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=${package}%20${version}&resultsPerPage=${limit}" --output "$json"
                fi
                #totalResults=$(sed -r 's#.*"totalResults":([0-9]+).*#\1#' $json)
                totalResults=$(jq '.totalResults' $json)
                i=0
                until (( $i == $totalResults )); do
                        local cve=$(jq ".result.CVE_Items[${i}].cve.CVE_data_meta.ID" nist.json)
                        local lastModifiedDate=$(jq ".result.CVE_Items[${i}].lastModifiedDate" nist.json)

                        if $sqlcve "SELECT cve FROM cves WHERE cve='$cve';"; then
                                if [[ $($sqlcve "SELECT lastModifiedDate FROM cves WHERE cve='$cve';") ]];

                        local url=$(jq ".result.CVE_Items[${i}].cve.references.reference_data[0].url" nist.json)
                        local description=$(jq ".result.CVE_Items[${i}].cve.description.description_data[0].value" nist.json)
                        local score=$(jq ".result.CVE_Items[${i}].impact.baseMetricV3.cvssV3.baseScore" nist.json)
                        local severity=$(jq ".result.CVE_Items[${i}].impact.baseMetricV3.cvssV3.baseSeverity" nist.json)
                        local publishedDate=$(jq ".result.CVE_Items[${i}].publishedDate" nist.json)
                        $sqlcve "INSERT INTO cves (cve,score,severity,description,url,publishedDate,lastModifiedDate) VALUES ('$cve','$score','$severity','$description','$url','$publishedDate','$lastModifiedDate');"
                        let i++
                done
        done < <($sql 'SELECT DISTINCT package,version FROM hosts')
}

# Read domains & their service groups, line by line, correlating with the data from the table
# "service_groups" & saving the merged data to the table "hosts"
function get_domains {
    while read -r -a line; do
        domain="${line[0]}"
        service_group="${line[1]}"

                while read -r -a line; do
                        ip="${line[0]}"
                        port="${line[1]}"
                        $sql "INSERT INTO domains (domain,service_group,ip,port) VALUES ('$domain','$service_group','$ip','$port');"
                done < <($sql "SELECT ip,port FROM service_groups WHERE service_group='$service_group';")

        done < <(grep -E "^\s+host-switching contains " "${conf_a10}" | cut -f5,7 -d ' ')
}

function merge_log_data {
    while read -r -a line; do
        ip="$(echo $line | cut -d '|' -f1)"
        hostname="$(echo $line | cut -d '|' -f2 | sed 's/.pjmt.local//g')"
        file="$(echo $line | cut -d '|' -f3)"
        package="$(echo $line | cut -d '|' -f4)"
        version="$(echo $line | cut -d '|' -f5)"

        if [[ -z "$version" ]]; then
                        $sql "UPDATE hosts SET hostname='$hostname',present='$present' WHERE ip='$ip';"
                else
                        $sql "UPDATE hosts SET hostname='$hostname',present='$present',version='$version' WHERE ip='$ip';"
                fi
        done < "${scanner_log}"
}

function export_csv {
        csv="results-$(date +%y%m%d).csv"
        sqlite3 -header -csv $db 'SELECT DISTINCT domain,hostname,ip,present,version FROM hosts WHERE present IS NOT NULL' > $csv
        #sqlite3 -header -csv $db 'SELECT DISTINCT domain,hostname,ip,version FROM hosts WHERE present=1' > $csv
        #sqlite3 -header -csv $db 'SELECT DISTINCT * FROM hosts WHERE present=1' > $csv
}

function check_config_a10 {
        if [[ ! -e "$conf_a10" ]] || [[ -z $(find "${conf_a10}" -mtime +1) ]]; then
        #if [[ ! -e "$conf_a10" ]]; then
                echo -e "\b\bx]"

                echo -en "Baixando configuração A10:\t[ ]"
                file="$(sshpass -p "<pass>" ssh <user>@<ip> 'ls -t /backupa10/A10-CTJ-131_backup_system* | head -n1')"
                sshpass -p "<pass>" scp <user>@<ip>:"${file}" "${cachedir}/" &&
                success || fail

                echo -en "Extraindo configuração A10:\t[ ]"
                file="$(basename $file)"
                tar --directory="${cachedir}" --gzip --extract --file="${cachedir}/${file}" backup_system.tar &&
                rm -f "${cachedir}/${file}" &&
                tar --directory="${cachedir}" --extract --file="${cachedir}"/backup_system.tar "${conf_a10_remote}" &&
                rm -f "${cachedir}/backup_system.tar" &&
                success || fail

        else
                echo -e "\b\b✓]"
        fi
}

#######################################
#              Execução               #
#######################################

if [[ "$1" = "-h" ]] || [[ "$1" = "--help" ]]; then
        print_help
        exit
fi

# Falhar se algo dar erro ou uma variável não está definida
set -u

success(){ echo -e "\b\b✓]"; }
fail(){ echo -e "\b\bx]"; exit 1; }

echo -en "Validando configuração A10:\t[ ]"
check_config_a10
echo -en "Initializando DB sqlite:\t[ ]"
initiate_db && success || fail
echo "Analisando configuração A10..."
echo -en "\t- service groups:\t[ ]"
get_service_groups && success || fail
echo -en "\t- domains:\t\t[ ]"
get_domains && success || fail
echo -en "Analisando relatório dos hosts:\t[ ]"
merge_log_data && success || fail
echo -en "INSERTING LEFTOVER DATA:\t[ ]"
insert_log_data && success || fail
echo "Gerando relatório..."
echo -en "\t- CSV:\t\t\t"
export_csv &&
echo "$csv" || echo Error!
echo -en "\t- DB:\t\t\t"
dbexport="results-$(date +%y%m%d).db"
cp $db $dbexport &&
echo "$dbexport" || echo Error!

exit
