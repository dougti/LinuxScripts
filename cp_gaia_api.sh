#!/bin/bash
####################################################################
#                                                                  #
# Por: Doug Ingham (doug@bakis.io)                                 #
# Ver: 1.0 (17/08/22)                                              #
#                                                                  #
####################################################################
#                        cp_gaia_api.sh                            #
#                                                                  #
# Este script gerencia o Check Point pela GAIA API REST/JSON.      #
# https://sc1.checkpoint.com/documents/latest/GaiaAPIs/index.html  #
#                                                                  #
####################################################################

_printHelp() {
        echo "
        Usage: $0 <target> <command> <arguments>

        Targets: mercurio venus terra marte
        Commands:
                show-static-route <ip>/<mask>
                show-static-routes
                set-static-route <ip>/<mask> <gw> [comment]
                delete-static-route <ip>/<mask>
                show-cluster-state

        Example: $0 marte set-static-route 10.0.0.0/8 10.0.0.1 Default gateway for 10/8
        "
        exit 1
}


#######################################
#             Variaveis               #
#######################################

user='<user>'                                                   # Usuário da API
pass='********************'                                     # Senha da API
apiMercurio='https://10.0.5.211:4434/gaia_api/v1.5'             # URL da API
apiVenus='https://marte.example.com:4434/gaia_api/v1.5'                # URL da API
apiTerra='https://terra.example.com:443/gaia_api/v1.6'                 # URL da API
apiMarte='https://marte.example.com:443/gaia_api/v1.6'                 # URL da API
apiJupiter='https://jupiter.example.com/gaia_api/v1.5'                    # URL da API
apiSatrun='https://saturn.example.com/gaia_api/v1.5'                      # URL da API
cpExterno=(merucrio venus)
cpInterno=(terra marte)
cpP2P=(jupiter saturn)


#######################################
#              Ambiente               #
#######################################

target="$1"         # Target Check Points
cmd="$2"            # API command

args=($@)           # Load command arguments into array
unset args[0]       # Remove $1 from array
unset args[1]       # Remove $2 from array
args=(${args[@]})   # Reset array's index


#######################################
#               Funções               #
#######################################

_send() {
    if [[ -n "$1" ]]; then
        local cmd="$1"
    fi

    unset sendResult
    while IFS= read -r line; do
        if [[ -z "$sendResult" ]]; then
            if [[ "$line" = "fail" ]]; then
                # Curl falhou
                exit
            # Processa os cabeçalhos
            elif [[ "$line" =~ ^HTTP/1\.1 ]]; then
                sendStatus="$(echo $line | cut -d ' ' -f2)"
            fi
        fi

        # Começou o JSON
        if [[ "$line" = "{" ]]; then local jsonStart=1; fi
        if [[ "$jsonStart" = "1" ]]; then sendResult+="$line"; fi

    done < <(eval curl --connect-timeout 30 -i -k -sS -d \'${data}\' -H \'Content-Type: application/json\' -H \'X-chkp-sid: ${sid}\' -X POST \'${api}/${cmd}\' || echo "fail")

    # Limpa a bagunça
    local sendResultLimpo=$(echo "${sendResult}" | tr -s ' ')
    sendResult="${sendResultLimpo}"

    if [[ "$sendStatus" != "200" ]]; then
        #sendResult=$(echo $sendResult | sed -r 's/.*"message": "(.*)".*/\1/g')
        echo "ERRO ${sendStatus}: ${sendResult}"
        return 1
    fi
}

_login() {
    data="{\"user\":\"${user}\",\"password\":\"${pass}\"}"
    _send login

    # Capturar o Session ID
    if [[ "$sendStatus" = "200" ]]; then
        sid=$(echo $sendResult | sed -r 's/.*"sid": "([0-9]+)".*/\1/g')
    else
        return 1
    fi
}

_logout() {
    if [[ -n "$sid" ]]; then
        data="{}"
        _send logout
    fi
}

_validarIP() {
    if [[ ! "$1" =~ ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]]; then
        echo "IP inválido: $1"
        _printHelp
    fi
}

_validarSubnet() {
    if [[ ! "$1" =~ ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/(0|[12][0-9]|3[0-2])$ ]]; then
        echo "Subnet inválido: $1"
        _printHelp
    fi
}

_validarString() {
    if echo "$1" | grep -o "." | LANG=C egrep -vqi "[a-z0-9. -]"; then
        echo "Erro: String contem caracteres inválidos."
        _printHelp
    fi
}

_showStaticRoute() {
    # show-static-route <ip>/<mask>
    if (( ${#args[@]} != 1 )); then _printHelp; fi

    _validarSubnet ${args[0]}
    local address="$(echo ${args[0]} | cut -d '/' -f1)"
    local mask="$(echo ${args[0]} | cut -d '/' -f2)";

    data="{\"mask-length\":\"${mask}\",\"address\":\"${address}\"}"
}

_showStaticRoutes() {
    # show-static-routes
    if (( ${#args[@]} != 0 )); then _printHelp; fi

    data="{}"
}

_setStaticRoute() {
    # set-static-route <ip>/<mask> <gw> [comment]
    if (( ${#args[@]} < 2 )); then _printHelp;  fi

    _validarSubnet ${args[0]}
    local address="$(echo ${args[0]} | cut -d '/' -f1)"
    local mask="$(echo ${args[0]} | cut -d '/' -f2)"
    local gateway="${args[1]}"; _validarIP "$gateway"

        if (( ${#args[@]} > 2 )); then
                local comment="${args[@]:2}"; _validarString "$comment"
                data="{\"comment\":\"${comment}\",\"mask-length\":${mask},\"address\":\"${address}\",\"next-hop\":{\"gateway\":\"${gateway}\"},\"type\":\"gateway\"}"
        else
                data="{\"mask-length\":${mask},\"address\":\"${address}\",\"next-hop\":{\"gateway\":\"${gateway}\"},\"type\":\"gateway\"}"
        fi
}

_deleteStaticRoute() {
    # delete-static-route <ip>/<mask>
    if (( ${#args[@]} != 1 )); then _printHelp; fi

    _validarSubnet ${args[0]}
    local address="$(echo ${args[0]} | cut -d '/' -f1)"
    local mask="$(echo ${args[0]} | cut -d '/' -f2)"

    data="{\"mask-length\":\"${mask}\",\"address\":\"${address}\"}"
}

_showClusterState() {
    # show-cluster-state
    if (( ${#args[@]} != 0 )); then _printHelp; fi

    data="{}"
}


#######################################
#              Execução               #
#######################################

case "$target" in
    mercurio)
        api="${apiMercurio}"
        ;;
    venus)
        api="${apiVenus}"
        ;;
    terra)
        api="${apiTerra}"
        ;;
    marte)
        api="${apiMarte}"
        ;;
    jupiter)
        api="${apiJupiter}"
        ;;
    saturn)
        api="${apiSaturn}"
        ;;
    *)
        if [[ -n $target ]]; then echo "Target inválido: $target"; fi
        _printHelp
esac

case "$cmd" in
    show-static-route)
        _showStaticRoute &&
        _login &&
        _showStaticRoute &&
        _send &&
        echo "$sendResult"
        _logout
        ;;
    show-static-routes)
        _showStaticRoutes &&
        _login &&
        _showStaticRoutes &&
        _send &&
        echo "$sendResult"
        _logout
        ;;
    set-static-route)
        _setStaticRoute &&
        _login &&
        _setStaticRoute &&
        _send
        _logout
        ;;
    delete-static-route)
        _deleteStaticRoute &&
        _login &&
        _deleteStaticRoute &&
        _send
        _logout
        ;;
    show-cluster-state)
        _showClusterState &&
        _login &&
        _showClusterState &&
        _send &&
        echo "$sendResult"
        _logout
        ;;
    *)
        if [[ -n $cmd ]]; then echo "Command inválido: $cmd"; fi
        _printHelp
esac

exit

####################################
#            ANOTAÇÕES             #
####################################

+ result='{
  "code": "generic_bad_request",
  "message": "400 Bad Request: The browser (or proxy) sent a request that this server could not understand."
}'
+ result='{
  "code": "generic_err_session_expired",
  "errors": "Unauthorized sid, session may have expired",
  "message": "Session Expired"
}'

HTTP/1.1 200 OK
Date: Sun, 14 Aug 2022 19:06:34 GMT
Server: gunicorn/19.7.1
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: SAMEORIGIN
Content-Type: application/json
Content-Length: 22
X-UA-Compatible: IE=EmulateIE8

{
  "message": "OK"
}
