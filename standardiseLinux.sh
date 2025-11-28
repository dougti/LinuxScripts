#!/bin/bash
##################################################################################
#                           standardiseLinux.sh v1.0.0                           #
#                                                                                #
# Script to do some basic post hardening and standardisation for a specific      #
# environment:                                                                   #
# - Users with uid/gid 0                                                         #
# - All users with priveleges granted via sudoers                                #
#                                                                                #
# By: Doug Ingham (doug@bakis.io)                                                #
##################################################################################

default_users=(<user1> <user2>)
default_groups=(<group1> <group2>)
pass_user1='<password_hash>'

# Iniciar com permissoes elevadas
if [[ $EUID != 0 ]]; then
        exec sudo "$0" "$@"
fi
cd $(dirname $0)

if [[ -s extras ]]; then
        echo "Executando extras..."
        bash extras
fi

# Criar os grupos padroes
echo "Padronizando os grupos..."
for i in ${default_groups[@]}; do grep -q "^${i}:" /etc/group || groupadd $i; done

# Criar os usuarios padroes
echo "Padronizando os usuarios..."
for i in ${default_users[@]}; do grep -q "^${i}:" /etc/passwd || useradd -m $i; done
#
for i in ${default_users[@]}; do grep -qE "^${i}:${pass_user1}:" /etc/shadow || sed -ri "s/^(user1:)[^:]+/\\1${pass_user1}/" /etc/shadow
usermod -s /bin/bash -g <user1> -G group1,group2 user1

# Adicionar conta funcional e grupo n3 ao sudoers
for i in '%<group1>' '<group2>'; do grep -qE "^\s+?${i}\s+ALL=\(ALL\)\s+NOPASSWD:\s+ALL" /etc/sudoers || echo -e "${i}\tALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers; done

echo "Padronizando o ambiente Linux TJ..."

# Renomear chattr
if [[ -e /bin/chattr ]]; then mv /bin/chattr /bin/rttahc; fi

# Criar users_historylogs
if [[ ! -d /var/log/users_historylogs/ ]]; then mkdir -pm 0755 /var/log/user_historylogs/; fi

# Corrigir permissoes dos historylogs
for i in $(find /var/log/users_historylogs/ -name history-*); do
       if [[ -n $i ]]; then
               username="$(echo $i | sed 's#/var/log/users_historylogs/history-##')"
               chown "$username" "$i" 2>/dev/null
               chmod 600 "$i" 2>/dev/null
               rttahc +a "$i" 2>/dev/null
       fi
done

# Copiar o arquivo aliasGeral
aliasDir='/usr/local/dcon/confs/alias.d'
if [[ ! -d ${aliasDir} ]]; then mkdir -p ${aliasDir}; fi
if [[ -e ${aliasDir}/aliasGeral ]] && [[ "$(md5sum linux/aliasGeral | awk '{print $1}')" != "$(md5sum ${aliasDir}/aliasGeral | awk '{print $1}')" ]]; then
        mv ${aliasDir}/aliasGeral ${aliasDir}/aliasGeral-$(date +%y%m%d)
fi
if [[ ! -e ${aliasDir}/aliasGeral ]]; then cat linux/aliasGeral > ${aliasDir}/aliasGeral; fi
chmod 444 ${aliasDir}/aliasGeral

# Copiar o arquivo profile
if [[ -e /etc/profile ]] && [[ "$(md5sum linux/profile | awk '{print $1}')" != "$(md5sum /etc/profile | awk '{print $1}')" ]]; then
        mv /etc/profile /etc/profile-$(date +%y%m%d)
fi
if [[ ! -e /etc/profile ]]; then cat linux/profile > /etc/profile; fi
chmod 444 /etc/profile

echo "Padronizando o SSH..."
# Alterar a porta do SSH
if ! grep -q '^Port 12235$' /etc/ssh/sshd_config; then
        sed -ri 's/^#?Port 22$/Port 12235/' /etc/ssh/sshd_config
        semanage port -a -t ssh_port_t -p tcp 12235
        systemctl restart sshd
fi

# Liberar a porta 12235 no firewall
if type firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --add-port=12235/tcp --permanent >/dev/null 2>&1; then
                firewall-cmd --reload >/dev/null 2>&1
        else
                firewall-offline-cmd --add-port=12235/tcp --permanent >/dev/null 2>&1
        fi
fi

# Instalar Trend
echo "Instalando Trend..."
cd trend
./Deploy_DeepSecurity_Linux.sh
