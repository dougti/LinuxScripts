#!/bin/bash
####################################################
#                 Vuln Scanner 1                   #
####################################################
#                                                  #
# By: Doug Ingham (doug@bakis.io)                  #
# Ver: 1.0 (14/01/22)                              #
#                                                  #
####################################################

#######################################
#             Variaveis               #
#######################################

confdir=".confdir"
conf_a10_remote="a10data/partconf/INTERNA/pri_default/startup-config"
conf_a10="${confdir}/${conf_remote}"
scanner_log="vuln-scanner.log"
pkg_qtd=1
bck_a10_srv="<ip>"
bck_a10_usr="<user>"
bck_a10_pass="<pass>"

#######################################
#           Manual de Uso             #
#######################################

# Analise dos JARs
# https://raw.githubusercontent.com/wso2/security-tools/master/internal/update-scripts/CVE-2021-44228-mitigation.sh

#print_help(){ echo '
#Server:
#       ncat -kl -p8080 > vuln-scanner.log
#
#Client:
#       if which locate >/dev/null; then
#               if locate --regex 'log4j-(core-)?([0-9]+\.){2}[0-9]+' >/dev/null; then
#                       version="$(for i in $(locate --regex 'log4j-(core-)?([0-9]+\.){2}[0-9]+'); do
#                                               basename $i | grep -Eo '^log4j-(core-)?([0-9]+\.){2}[0-9]+' | grep -Eo '([0-9]+\.){2}[0-9]+';
#                                       done | sort -t . -k 1,1n -k 2,2n -k 3,3n | uniq | tr '\n' ' ')";
#                       curl -q -fs -m1 -d "$(hostname) {{ ansible_default_ipv4.address }} 1 $version -" 10.0.8.12:8080;
#               else
#                       curl -q -fs -m1 -d "$(hostname) {{ ansible_default_ipv4.address }} 0 -" 10.0.8.12:8080;
#               fi;
#               echo -n
#       else
#               if [[ -n $(find / -regextype posix-extended -regex '.*log4j-(core-)?([0-9]+\.){2}[0-9]+.*' -print -quit) ]]; then
#                       version="$(for i in $(find / -regextype posix-extended -regex '.*log4j-(core-)?([0-9]+\.){2}[0-9]+.*'); do
#                                               basename $i | grep -Eo '^log4j-(core-)?([0-9]+\.){2}[0-9]+' | grep -Eo '([0-9]+\.){2}[0-9]+';
#                                       done | sort -t . -k 1,1n -k 2,2n -k 3,3n | uniq | tr '\n' ' ')";
#                       curl -q -fs -m1 -d "$(hostname) {{ ansible_default_ipv4.address }} 1 $version -" 10.0.8.12:8080;
#               else
#                       curl -q -fs -m1 -d "$(hostname) {{ ansible_default_ipv4.address }} 0 -" 10.0.8.12:8080;
#               fi;
#               echo -n
#       fi
#
#       ## REF ##
#       # locate -0; xargs -0; find -print0; while IFS= read -r -d $'\0' line;
#';}


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

if [[ ! -d "$confdir" ]]; then
        mkdir -p $confdir
        if [[ $? != 0 ]]; then
                echo "Erro: Não foi possível criar $confdir"
                exit 1
        fi
elif [[ ! -w "$confdir" ]]; then
                echo "Erro: Sem permissões de escrita no $confdir"
                exit 1
fi

if [[ ! -e "$scanner_log" ]]; then
        echo "Erro: $scanner_log não encontrado. Gere um log para continuar."
        print_help
        exit 1
fi

db="$(mktemp -p $confdir)"
sql="sqlite3 -column $db"

# Fazer uma limpeza antes de encerrar o script
function cleanup {
        rm -f "$db"
}
trap cleanup EXIT


#######################################
#               Funções               #
#######################################

function initiate_db {
        $sql 'CREATE TABLE service_groups (service_group TEXT, ip TEXT, port INTEGER);' &&
        $sql 'CREATE TABLE hosts (domain TEXT, service_group TEXT, ip TEXT, hostname TEXT, port INTEGER, present INTEGER, version TEXT);'
#       i=0; until (( $i == $pkg_qtd )); do
#               $sql "ALTER TABLE hosts ADD COLUMN pkg${i} TEXT, pkg${i}ver TEXT;"
#               let i++
#       done
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

# Read domains & their service groups, line by line, correlating with the data from the table
# "service_groups" & saving the merged data to the table "hosts"
function get_domains {
    while read -r -a line; do
        domain="${line[0]}"
        service_group="${line[1]}"

                while read -r -a line; do
                        ip="${line[0]}"
                        port="${line[1]}"
                        $sql "INSERT INTO hosts (domain,service_group,ip,port) VALUES ('$domain','$service_group','$ip','$port');"
                done < <($sql "SELECT ip,port FROM service_groups WHERE service_group='$service_group';")

        done < <(grep -E "^\s+host-switching contains " "${conf_a10}" | cut -f5,7 -d ' ')
}

function insert_log_data {
    while read -r -a line; do
        hostname="$(echo ${line[0]} | sed 's/.pjmt.local//g')"
        ip="${line[1]}"
        present="${line[2]}"
        #version="${line[3]}"
        version=$(echo ${line[*]} | cut -d ' ' -f 4- | sed 's#-POST / HTTP/1.1##g' | tr -d '\r')
                if [[ -z $($sql "SELECT ip FROM hosts WHERE ip='$ip';") ]]; then
                        if [[ "$version" = "-POST" ]]; then
                                $sql "INSERT INTO hosts (hostname,ip,present) VALUES ('$hostname','$ip','$present');"
                        else
                                $sql "INSERT INTO hosts (hostname,ip,present,version) VALUES ('$hostname','$ip','$present','$version');"
                        fi
                fi
        done < <(grep -- '-POST' "${scanner_log}")
}

function merge_log_data {
    while read -r -a line; do
        hostname="$(echo ${line[0]} | sed 's/.domain.local//g')"
        ip="${line[1]}"
        present="${line[2]}"
        #version="${line[3]}"
        version=$(echo ${line[*]} | cut -d ' ' -f 4- | sed 's#-POST / HTTP/1.1##g' | tr -d '\r')
        if [[ -z "$version" ]]; then
                        $sql "UPDATE hosts SET hostname='$hostname',present='$present' WHERE ip='$ip';"
                else
                        $sql "UPDATE hosts SET hostname='$hostname',present='$present',version='$version' WHERE ip='$ip';"
                fi
#       if [[ "$version" = "-POST" ]]; then
#                       $sql "UPDATE hosts SET hostname='$hostname',present='$present' WHERE ip='$ip';"
#               else
#                       $sql "UPDATE hosts SET hostname='$hostname',present='$present',version='$version' WHERE ip='$ip';"
#               fi
        done < <(grep -- '-POST' "${scanner_log}")
}

function export_csv {
        csv="results-$(date +%y%m%d).csv"
        sqlite3 -header -csv $db 'SELECT DISTINCT domain,hostname,ip,present,version FROM hosts WHERE present IS NOT NULL' > $csv
        #sqlite3 -header -csv $db 'SELECT DISTINCT domain,hostname,ip,version FROM hosts WHERE present=1' > $csv
        #sqlite3 -header -csv $db 'SELECT DISTINCT * FROM hosts WHERE present=1' > $csv
}

function check_config_a10 {
        if [[ ! -e "$conf_a10" ]] || [[ $(find "${conf_a10}" -mtime +1) ]]; then
        #if [[ ! -e "$conf_a10" ]] || [[ -z $(find "${conf_a10}" -mtime +1) ]]; then
        #if [[ ! -e "$conf_a10" ]]; then
                echo -e "\b\bx]"

                echo -en "Baixando configuração A10:\t[ ]"
                file="$(sshpass -p "${a10_bck_pass}" ssh ${a10_bck_usr}@${a10_bck_srv} 'ls -t /backupa10/A10-*_backup_system* | head -n1' 2>/dev/null)"
                sshpass -p "${a10_bck_pass}" scp ${a10_bck_usr}@${a10_bck_srv}:"${file}" "${confdir}/" 2>/dev/null &&
                success || fail

                echo -en "Extraindo configuração A10:\t[ ]"
                file="$(basename $file)"
                tar --directory="${confdir}" --gzip --extract --file="${confdir}/${file}" backup_system.tar &&
                rm -f "${confdir}/${file}" &&
                tar --directory="${confdir}" --extract --file="${confdir}"/backup_system.tar "${conf_a10_remote}" &&
                rm -f "${confdir}/backup_system.tar" &&
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
