#!/bin/bash

##################################################################################
#                           checkadmin.sh v1.0.0                                 #
#                                                                                #
# Script which lists all priveleged Linux users:                                 #
# - Users with uid/gid 0                                                         #
# - All users with priveleges granted via sudoers                                #
#                                                                                #
# To integrate this script in a monitoring system running under a                #
# non-priveleged user, eg. Zabbix:                                               #
# 1) Generate a SHA-256 hash of the current script:                              #
#    sha256sum checkadmin.sh                                                     #
# 2) Include the following line in your sudoers, including the hash:             #
#    /etc/sudoers:                                                               #
#    zabbix ALL= NOPASSWD: sha256:<scripthash> /etc/zabbix/scripts/checkadmin.sh #
# 3) Add the following UserParameter under your zabbix_agent config:             #
#    /etc/zabbix/zabbix_agent2.d/secops.conf:                                    #
#    UserParameter=linux.sudoers,/etc/zabbix/scripts/checkadmin.sh               #
#                                                                                #
# By: Doug Ingham (doug@bakis.io)                                                #
##################################################################################
PATH="/usr/sbin:/usr/bin:/sbin:/bin"

# Iniciar com permissões elevadas
if [[ $EUID != 0 ]]; then exec sudo "$0"; fi

declare -a USERS

# Extrair todos os usuarios com uid e grupo root
extract_root() {
        # Extrair usuarios com uid/gid 0
        for USER in $(cut -f1,3,4 -d ':' /etc/passwd | grep -E ':0(:|$)' | cut -f1 -d ':'); do
                USERS+=("$USER")
        done

        # Extrair membros do grupo 0
        for USER in $(cut -f3,4 -d\: /etc/group | grep '^0:' | cut -f2 -d\: | tr ',' ' '); do
                USERS+=("$USER")
        done
}

# Extrair todos os usuarios definidos nos arquivos sudoers
extract_sudoers() {
        while IFS= read -r LINE; do

                # Extrair os grupos sudoers
                if [[ "$LINE" =~ ^% ]]; then
                        GROUP="$(echo "$LINE" | sed -r 's/^\s*%(\S+).*$/\1/')"
                        for USER in $(grep "^${GROUP}:" /etc/group | cut -f4 -d\: | tr ',' ' '); do
                                USERS+=("$USER")
                        done

                # Extrair os includes sudoers
                elif [[ "$LINE" =~ ^@ ]]; then

                        INCLUDE_TYPE="$(echo "$LINE" | sed -r 's/^\s*@(\S+).*$/\1/')"
                        INCLUDE="$(echo "$LINE" | awk '{print $2}')"

                        if [[ "$INCLUDE_TYPE" = "includedir" ]]; then
                                for FILE in $(find "$INCLUDE" -type f); do
                                        if [[ -n "$FILE" ]]; then
                                                extract_sudoers "$FILE"
                                        fi
                                done
                        elif [[ "$INCLUDE_TYPE" = "include" ]]; then
                                extract_sudoers "$INCLUDE"
                        fi

                # Extrair os usuarios sudoers
                else
                        USER="$(echo "$LINE" | awk '{print $1}')"
                        USERS+=("$USER")
                fi

        # Extrair apenas as linhas de configuracao que definem permissoes
        done < <(grep -Ev '^\s*(Defaults|#|$)' "$1")
}

extract_root
extract_sudoers /etc/sudoers

for USER in "${USERS[@]}"; do echo "$USER"; done | sort | uniq
