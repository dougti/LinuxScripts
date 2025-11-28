#!/bin/bash
####################################################
#                                                  #
# Por: Doug Ingham (doug@bakis.io)                 #
# Ver: 1.0 (07/07/21)                              #
#                                                  #
####################################################
#                Script Template                   #
#                                                  #
# Este script inclua uma estrutura básica e        #
# examplos de funções comuns que podem ser         #
# reutilizados em outros scripts.                  #
#                                                  #
####################################################
exit

#######################################
#             Variaveis               #
#######################################

HOSTS="datacenter-comarcas-srv.txt"
ALVOS="comarcas-msrpc-open.txt"
VULNS="comarcas-msrpc-vuln.txt"
THREADS=10
TMPDIR="$(mktemp -d .tmpXXX)"
TMPFILE="$(mktemp -p ${TMPDIR})"


#######################################
#              Ambiente               #
#######################################

# Falha se algo dar erro ou uma variável não está definida
set -eu

# Fazer uma limpeza antes de encerrar o script
function cleanup {
        rm -rf "$TMPDIR"
}
trap cleanup EXIT

# Desabilitar Ctrl+C, Ctrl-Z, etc
trap '' SIGINT SIGTSTP SIGXCPU

# Iníciar com permissões elevadas
if [[ $EUID != 0 ]]; then
    exec sudo "$0" "$@"
fi

# Enable output if shell is interactive
[[ -z $PS1 ]] && silent=1 || silent=0

#######################################
#               Funções               #
#######################################

# Traceroute
for ((TTL=1;TTL<30;TTL++)); do
        ping -c 1 -t $TTL <IP>;
done

function _colour(){
         case $1 in
                white) echo -e "\033[01;37m$2\033[0m";;
                yellow) echo -e "\033[01;33m$2\033[0m";;
                red) echo -e "\033[01;31m$2\033[0m";;
                blue) echo -e "\033[01;34m$2\033[0m";;
                green) echo -e "\033[01;32m$2\033[0m";;
        esac
}

# Sim ou Não? Loop até receber resposta válida.
# Ao responder, a var $SIMNAO retorna "s" ou "n".
# ARG1=Pergunta; ARG2=Resposta padrão (opcional)
# Uso: simnao "<Pergunta>" [s/n]
# Ex. simnao "Você quer continuar?" s
function simnao {
        if [[ -z $1 ]] || [[ -n $3 ]]; then
                echo "simnao: Argumento inválido"
                exit 255
        fi

        unset SIMNAO;
        if [[ "$2" = "s" ]]; then
                # Resposta padrão = s
                until echo "$SIMNAO" | egrep -qi "[sn]"; do
                        read -r -n1 -p "$1 (S/n): " SIMNAO
                        if [[ -z "$SIMNAO" ]]; then SIMNAO=s; fi
                done
        elif [[ "$2" = "n" ]]; then
                # Resposta padrão = n
                until echo "$SIMNAO" | egrep -qi "[sn]"; do
                        read -r -n1 -p "$1 (s/N): " SIMNAO
                        if [[ -z "$SIMNAO" ]]; then SIMNAO=n; fi
                done
        else
                # Perguntar até o usuário responder com s ou n
                until echo "$SIMNAO" | egrep -qi "[sn]"; do
                        read -r -n1 -p "$1 (s/n): " SIMNAO
                done
        fi

        # Retornar resposta pelo código de saída (opcional)
        if [[ "$SIMNAO" = "s" ]]; then
                return 0
        else
                return 1
        fi
}

function validar_ip {
        if [[ ! "$1" =~ ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]]; then
                echo "IP inválido: $1"
                return 1
        fi
}

_validarSubnet() {
        if [[ ! "$1" =~ ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/(0|[12][0-9]|3[0-2])$ ]]; then
                echo "Subnet inválido: $1"
        fi
}

function validar_hostname {
        if echo "$1" | LANG=C egrep -vq "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"; then
                echo "Hostname não válido"
                return 1
        fi
        #isDNS=$(echo ${cip} | grep -P "^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$" )
}

function validar_host {
        # Identificar hostnames
        if echo "$1" | egrep -iq "[a-z\-]"; then
                # Identificar caracteres inválidos
                if echo "$1" | grep -o "." | LANG=C egrep -vqi "[a-z0-9\.-]"; then
                        echo "inválido"
                        return 1
                # Validar hostnames
                elif echo "$1" | egrep -q "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"; then
                        echo hostname
                #elif echo "$1" | egrep -q "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"; then
                #       echo fqdn
                else
                        echo "inválido"
                        return 1
                fi
        # Identificar IPs
        elif echo "$1" | egrep -q "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"; then
                echo ip
        else
                echo "inválido"
                return 1
        fi
}

_validarString() {
        if echo "$1" | grep -o "." | LANG=C egrep -vqi "[a-z0-9. -]"; then
                echo "Erro: String contem caracteres inválidos."
        fi
}

function scan_rede {
        nmap -iL ${HOSTS} -T4 --open -p 135 -oG ${TMPFILE}
        awk '{print $2}' ${TMPFILE} | grep -E "^[0-9]" | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n | uniq > ${ALVOS}
}

function scan_rpc {
        while IFS= read -r -d '' IP; do
                if [[ 0 = "$(impacket-rpcdump $IP 2>/dev/null | grep -q 'MS-RPRN'; echo $?)" ]]; then
                        echo "$IP" >> ${VULNS};
                        echo "$IP WARN!";
                else
                        echo "$IP ok";
                fi;
        done < <(cat $1)
}

_gerarNumero() {
        # Gerar número aleatório de 1-9
        RAN=$(echo $RANDOM | tr -d 0 | rev | cut -c1)

        # Gerar número aleatório de 01-15 em base-10
        # 10# permite base-10 no cálculo
        until [[ -n $RAN ]] && (( 10#$RAN < 16 )); do RAN=$(echo $RANDOM | grep -Eo '(0[1-9]|1[0-5])'); done
}


#######################################
#              Execução               #
#######################################

if [[ ! -f $HOSTS ]] && [[ ! -f $ALVOS ]] && [[ ! -f $VULNS ]]; then
        echo "ERRO: A lista de hosts não foi encontrado!"
        exit 1
fi

if [[ ! -f $ALVOS ]] && [[ ! -f $VULNS ]]; then
        scan_rede
fi

if [[ ! -f $VULNS ]]; then
        cd $TMPDIR
        split -d -en l/${THREADS} ../${ALVOS} ALVOS
        cd ../

        for ALVO in $(realpath ${TMPDIR}/ALVOS*); do
                scan_rpc "$ALVO" &
        done
else
        cd $TMPDIR
        split -d -en l/${THREADS} ../${VULNS} ALVOS
        cd ../

        mv "${VULNS}" "${VULNS}-old"

        for ALVO in $(realpath ${TMPDIR}/ALVOS*); do
                scan_rpc "$ALVO" &
        done
fi
wait

exit
