#!/bin/bash
####################################################################
#                           websum.sh                              #
####################################################################
#                                                                  #
# Por: Doug Ingham (doug@bakis.io)                                 #
#                                                                  #
####################################################################

for domain in $(cut -f1 -d, migrate.txt); do
        response="$(curl -sILm 10 "http://${domain}.example.com" | grep "^HTTP" | tail -n1 | cut -f2 -d\ )"
        if [[ "$response" = "200" ]]; then
                body="$(curl -Lsm 10 "http://${domain}.example.com")"
                title="\"$(echo "$body" | grep -Eo '<title>.*</title>' | sed -r 's#.*<title>\s+?(.*)</title>.*#\1#g')\""
                js="$(if echo "$body" | grep -qE "(habilitar o JavaScript|Aguarde enquanto concluimos a inicial)"; then echo -n 1; else echo 0; fi)"
                md5="$(echo "$body" | md5sum | cut -f1 -d\ )"
        fi
        echo "$domain,$response,$title,$js,$md5" >> status.txt
        unset domain title response js md5
done
