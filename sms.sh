#!/bin/bash
####################################################################
#                                                                  #
# Por: Doug Ingham (doug@bakis.io)                                 #
# Ver: 1.0 (26/10/21)                                              #
#                                                                  #
####################################################################
#                             sms.sh                               #
#                                                                  #
# Este script envia mensagens SMS pela API REST/JSON da MaxxMobi.  #
# https://www.maxxmobi.com.br/documentacao/api-sms/index.html?json #
#                                                                  #
# O primeiro argumento é a mensagem a ser enviada, todos os        #
# argumentos depois são os números destinatários.                  #
#                                                                  #
# Números inválidos são excluídos silenciosamente.                 #
# É obrigatório o uso do código do pais e DD, ex. 556512345678.    #
# SMS tem um limite de 160 caracteres por mensagem.                #
#                                                                  #
####################################################################

api='https://api.maxx.mobi/ws/maxxmobi/envios/' # URL da API
user='************'             # Usuário da api
pass='************'             # Senha da API
msg="$1"                        # Corpo da mensagem
log="/var/log/sms.log"

echo -e "\n########## $(date) ###########" >> $log

if (( 160 < $(echo "$msg" | wc -m) )); then
        echo "ERROR: A mensagem excede 160 caracteres" >> $log
        echo "$msg" >> $log
        exit 1
fi

function definir_destinatarios {
        # O primeiro argumento é a mensagem, o resto são os números
        to=("$@")

        # Tirar o primeiro argumento da lista dos números
        unset to[0]

        # Tirar os números inválidos do matriz
        for i in "${!to[@]}"; do
                # Tirar números com caracteres não numéricos
                if [[ -n "$(echo ${to[$i]} | sed 's/[0-9]//g')" ]]; then
                        unset to[$i]
                # Tirar números com menos de 11 dígitos e mais de 16
                # 0 (00) 0000-0000
                elif (( 11 > $(echo ${to[$i]} | wc -m) )) || (( 16 < $(echo ${to[$i]} | wc -m) )); then
                        unset to[$i]
                fi
        done

        # Redefinir os índices do matriz limpo
        to=("${to[@]}")
}

function criar_json {
        json="{\"usuario\":\"$user\", \"senha\":\"$pass\", \"requisicao\":["

        i=0
        until (( $i == ${#to[@]} )); do
                json+="{\"numero\":\"${to[$i]}\",\"mensagem\":\"$msg\"}"
                if (( $i != ${#to[@]}-1 )); then
                        json+=","
                fi
                let i++
        done

        json+="]}"
}

definir_destinatarios "$@"
criar_json

echo "curl -S -d '$json' -H 'Content-Type: application/json' -X POST '$api'" >> $log
curl -S -d "$json" -H "Content-Type: application/json" -X POST "$api" >> $log
echo "" >> $log

#curl -S -d "$json" -H "Content-Type: application/json" -X POST "$api" >/dev/null
#while IFS= read -r line curl -S -d "$json" -H "Content-Type: application/json" -X POST "$api"; do
#       if [[

#{"status":0,"resposta":"OK","lote":16762383}
