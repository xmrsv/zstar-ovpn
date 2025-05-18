#!/bin/bash

# --- modules/01-install-server.sh ---
# Módulo para Instalar y Configurar un Nuevo Servidor OpenVPN con ZStar OVPN

# Obtener la ruta absoluta del directorio donde reside este script de módulo
SCRIPT_DIR_MODULE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Ruta al directorio de librerías (subiendo un nivel desde modules/)
LIB_DIR="${SCRIPT_DIR_MODULE}/../lib"
COMMON_FUNCTIONS_PATH="${LIB_DIR}/common-functions.sh"

if [ -f "$COMMON_FUNCTIONS_PATH" ]; then
    source "$COMMON_FUNCTIONS_PATH"
else
    echo "[FATAL] Módulo de Instalación: Archivo de funciones comunes no encontrado: $COMMON_FUNCTIONS_PATH" >&2
    exit 1
fi

# --- Verificaciones Iniciales ---
check_root

log_info "--- Iniciando Módulo de Instalación del Servidor OpenVPN ---"

# --- Variables de Configuración Globales (Defaults y para guardar decisiones) ---
DEFAULT_VPN_PORT="443"
DEFAULT_VPN_PROTO="tcp"
DEFAULT_VPN_NETWORK="10.8.0.0"
DEFAULT_VPN_NETMASK="255.255.255.0"
DEFAULT_DNS_1="1.1.1.1" # Cloudflare
DEFAULT_DNS_2="1.0.0.1" # Cloudflare
DEFAULT_CLIENT_NAME="client1"
DEFAULT_EASYRSA_ALGO="rsa"
DEFAULT_RSA_KEY_SIZE="4096"
DEFAULT_EC_CURVE="secp384r1"
DEFAULT_CA_EXPIRE="3650"    # Días (10 años)
DEFAULT_CERT_EXPIRE="365"   # Días (1 AÑO) <--- AJUSTADO
DEFAULT_CRL_DAYS="180"

OPENVPN_DIR="/etc/openvpn"
EASYRSA_DIR="${OPENVPN_DIR}/easy-rsa"
SERVER_CONFIG_DIR="${OPENVPN_DIR}/server"
CLIENT_OVPN_OUTPUT_DIR="/root/ovpn-clients"
LOG_DIR="/var/log/openvpn"

PUBLIC_IP_OR_DOMAIN=""
VPN_PORT=""
VPN_PROTO=""
VPN_PROTO_SERVER_CONF=""
VPN_PROTO_CLIENT_CONF=""
VPN_NETWORK=""
VPN_NETMASK=""
DNS_SERVERS=()
FIRST_CLIENT_NAME=""
MAIN_NETWORK_INTERFACE=""
EASYRSA_ALGO=""
EASYRSA_KEY_SIZE=""
EASYRSA_EC_CURVE=""

# --- 1. Verificar si ya existe una configuración ---
log_info "Verificando configuración existente de ZStar OVPN..."
if [ -f "$VPN_CONFIG_VARS_FILE" ]; then
    log_warn "¡ATENCIÓN! Ya existe un archivo de configuración ZStar OVPN: $VPN_CONFIG_VARS_FILE"
    if ! ask_yes_no "¿Deseas continuar con una nueva instalación? Esto SOBREESCRIBIRÁ la configuración existente." "n"; then
        log_info "Instalación cancelada."
        exit 0
    fi
    log_info "Procediendo con la nueva instalación. La configuración anterior será sobrescrita."
    # Considerar hacer un backup automático aquí
    # sudo cp "$VPN_CONFIG_VARS_FILE" "${VPN_CONFIG_VARS_FILE}.bak.$(date +%s)"
fi

# --- 2. Recopilación de Información del Usuario (Como en la versión anterior) ---
log_info "--- Recopilando Información para la Configuración ---"
# IP Pública o Dominio
PUBLIC_IP_OR_DOMAIN=$(get_public_ip)
if [ -z "$PUBLIC_IP_OR_DOMAIN" ]; then
    PUBLIC_IP_OR_DOMAIN=$(ask_value "No se pudo detectar la IP pública. Ingrésala o un dominio" "" "^[a-zA-Z0-9.-]+$" "Entrada inválida." "noempty")
else
    log_info "IP pública detectada: $PUBLIC_IP_OR_DOMAIN"
    if ! ask_yes_no "¿Es correcta esta IP/Dominio ($PUBLIC_IP_OR_DOMAIN)?" "s"; then
        PUBLIC_IP_OR_DOMAIN=$(ask_value "Ingresa la IP pública o dominio correctos" "$PUBLIC_IP_OR_DOMAIN" "^[a-zA-Z0-9.-]+$" "Entrada inválida." "noempty")
    fi
fi
if [ -z "$PUBLIC_IP_OR_DOMAIN" ]; then log_fatal "La IP pública o dominio es requerida."; fi

# Puerto
VPN_PORT=$(ask_value "Puerto para OpenVPN (1-65535)" "$DEFAULT_VPN_PORT" "^([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$" "Puerto inválido.")

# Protocolo
while true; do
    VPN_PROTO=$(ask_value "Protocolo para OpenVPN (udp/tcp)" "$DEFAULT_VPN_PROTO" "^(udp|tcp)$" "Protocolo inválido.")
    if [[ "$VPN_PROTO" == "tcp" && "$VPN_PORT" == "1194" ]]; then
        if ! ask_yes_no "Usar TCP en el puerto 1194 (usualmente UDP) es atípico. ¿Continuar?" "n"; then continue; fi
    elif [[ "$VPN_PROTO" == "udp" && "$VPN_PORT" == "443" ]]; then
        if ! ask_yes_no "Usar UDP en el puerto 443 (usualmente TCP) podría ser bloqueado. ¿Continuar?" "n"; then continue; fi
    fi
    break
done
if [[ "$VPN_PROTO" == "tcp" ]]; then VPN_PROTO_SERVER_CONF="tcp-server"; VPN_PROTO_CLIENT_CONF="tcp"; else VPN_PROTO_SERVER_CONF="udp"; VPN_PROTO_CLIENT_CONF="udp"; fi

# Servidores DNS
log_info "Configuración de DNS para los clientes VPN:"
echo "  1) Cloudflare ($DEFAULT_DNS_1, $DEFAULT_DNS_2) (Recomendado)"
echo "  2) Google (8.8.8.8, 8.8.4.4)"
echo "  3) OpenDNS (208.67.222.222, 208.67.220.220)"
echo "  4) Personalizado"
echo "  5) Ninguno (no recomendado)"
DNS_CHOICE=$(ask_value "Elige una opción de DNS" "1" "^[1-5]$" "Opción inválida.")
case "$DNS_CHOICE" in
    1) DNS_SERVERS=("$DEFAULT_DNS_1" "$DEFAULT_DNS_2");;
    2) DNS_SERVERS=("8.8.8.8" "8.8.4.4");;
    3) DNS_SERVERS=("208.67.222.222" "208.67.220.220");;
    4)
        DNS1=$(ask_value "Ingresa el primer DNS personalizado" "" "^([0-9]{1,3}\.){3}[0-9]{1,3}$" "IP de DNS inválida." "noempty")
        DNS_SERVERS+=("$DNS1")
        if ask_yes_no "¿Añadir un segundo DNS personalizado?" "s"; then
            DNS2=$(ask_value "Ingresa el segundo DNS personalizado" "" "^([0-9]{1,3}\.){3}[0-9]{1,3}$" "IP de DNS inválida." "noempty")
            DNS_SERVERS+=("$DNS2")
        fi;;
    5) DNS_SERVERS=();;
esac

# Nombre del primer cliente
FIRST_CLIENT_NAME=$(ask_value "Nombre para el primer perfil de cliente" "$DEFAULT_CLIENT_NAME" "^[a-zA-Z0-9_.-]+$" "Nombre de cliente inválido." "noempty")

# Algoritmo EasyRSA (Simplificado por ahora a RSA, se puede expandir)
EASYRSA_ALGO=$DEFAULT_EASYRSA_ALGO # Forzamos RSA por ahora
EASYRSA_KEY_SIZE=$DEFAULT_RSA_KEY_SIZE
# Si se quisiera preguntar:
# EASYRSA_ALGO_CHOICE=$(ask_value "Algoritmo para EasyRSA (rsa/ec)" "$DEFAULT_EASYRSA_ALGO" "^(rsa|ec)$")
# if [[ "$EASYRSA_ALGO_CHOICE" == "rsa" ]]; then EASYRSA_ALGO="rsa"; EASYRSA_KEY_SIZE=$DEFAULT_RSA_KEY_SIZE; else EASYRSA_ALGO="ec"; EASYRSA_EC_CURVE=$DEFAULT_EC_CURVE; fi

log_info "--- Resumen de Configuración ---"
log_info "IP/Dominio Servidor: $PUBLIC_IP_OR_DOMAIN"
log_info "Puerto: $VPN_PORT, Protocolo: $VPN_PROTO (Servidor: $VPN_PROTO_SERVER_CONF, Cliente: $VPN_PROTO_CLIENT_CONF)"
log_info "Red VPN: $DEFAULT_VPN_NETWORK/$DEFAULT_VPN_NETMASK"
log_info "DNS para clientes: ${DNS_SERVERS[*]}"
log_info "Primer cliente: $FIRST_CLIENT_NAME"
log_info "Algoritmo PKI: $EASYRSA_ALGO ($([[ "$EASYRSA_ALGO" == "rsa" ]] && echo "${EASYRSA_KEY_SIZE}-bit" || echo "$EASYRSA_EC_CURVE"))"
log_info "Expiración de Certificados de Cliente/Servidor: $DEFAULT_CERT_EXPIRE días (aprox. 1 año)."

if ! ask_yes_no "¿Son correctos estos parámetros para continuar con la instalación?" "s"; then
    log_fatal "Instalación cancelada por el usuario."
fi

# --- 3. Instalación de Paquetes ---
log_info "--- Instalando Paquetes Necesarios ---"
PACKAGES_NEEDED="openvpn easy-rsa curl ufw iptables-persistent haveged" # haveged para mejorar entropía en VMs
# Comprobar si ya están instalados para evitar reinstalaciones innecesarias
PACKAGES_TO_INSTALL=""
for pkg in $PACKAGES_NEEDED; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        PACKAGES_TO_INSTALL+="$pkg "
    fi
done

if [ -n "$PACKAGES_TO_INSTALL" ]; then
    log_info "Paquetes a instalar: $PACKAGES_TO_INSTALL"
    run_cmd apt-get update -qq || log_fatal "Falló apt-get update."
    run_cmd apt-get install -y $PACKAGES_TO_INSTALL || log_fatal "Falló la instalación de paquetes."
    log_info "Instalación de paquetes completada."
else
    log_info "Todos los paquetes necesarios ya están instalados."
fi
# Asegurar que haveged esté corriendo si se instaló (mejora generación de claves en VMs)
if dpkg -s "haveged" >/dev/null 2>&1; then
    run_cmd systemctl enable haveged
    run_cmd systemctl start haveged
fi


# --- 4. Configuración del Sistema (IP Forwarding) ---
log_info "--- Configurando IP Forwarding ---"
# Descomentar o añadir la línea net.ipv4.ip_forward=1
if grep -q "^\s*#\s*net.ipv4.ip_forward\s*=\s*1" /etc/sysctl.conf; then
    run_cmd sed -i 's/^\s*#\s*net.ipv4.ip_forward\s*=\s*1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
elif ! grep -q "^\s*net.ipv4.ip_forward\s*=\s*1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
run_cmd sysctl -p /etc/sysctl.conf || log_warn "sysctl -p falló, pero el cambio podría aplicarse en el próximo reinicio."
log_info "IP Forwarding habilitado."

# --- 5. Configuración de Easy-RSA y Generación de PKI ---
log_info "--- Configurando Easy-RSA y Generando PKI ---"
# Limpiar directorio Easy-RSA anterior si existe (ya que estamos sobrescribiendo)
if [ -d "$EASYRSA_DIR" ]; then
    log_warn "Eliminando directorio Easy-RSA existente: $EASYRSA_DIR"
    run_cmd rm -rf "$EASYRSA_DIR"
fi
run_cmd mkdir -p "$EASYRSA_DIR" || log_fatal "No se pudo crear $EASYRSA_DIR."
run_cmd cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR/" || log_fatal "No se pudo copiar los scripts de Easy-RSA."
run_cmd chmod +x "$EASYRSA_DIR/easyrsa"

# Crear archivo vars o usar set-var
# EasyRSA 3 prefiere que no se edite 'vars' directamente, sino que se pasen variables
# o se use un archivo vars personalizado. Por simplicidad, crearemos uno.
log_info "Creando archivo de variables para Easy-RSA..."
cat << EOF > "${EASYRSA_DIR}/vars"
# Easy-RSA 3 vars file
# Comenta y ajusta según sea necesario

set_var EASYRSA_REQ_COUNTRY    "US"
set_var EASYRSA_REQ_PROVINCE   "California"
set_var EASYRSA_REQ_CITY       "San Francisco"
set_var EASYRSA_REQ_ORG        "ZStar OVPN CA"
set_var EASYRSA_REQ_EMAIL      "admin@example.com"
set_var EASYRSA_REQ_OU         "ZStar OVPN EasyRSA"

set_var EASYRSA_ALGO           "$EASYRSA_ALGO"
set_var EASYRSA_KEY_SIZE       "$EASYRSA_KEY_SIZE"  # Usado si ALGO es rsa
# set_var EASYRSA_EC_CURVE     "$EASYRSA_EC_CURVE" # Usado si ALGO es ec

set_var EASYRSA_CA_EXPIRE      "$DEFAULT_CA_EXPIRE"
set_var EASYRSA_CERT_EXPIRE    "$DEFAULT_CERT_EXPIRE"
set_var EASYRSA_CRL_DAYS       "$DEFAULT_CRL_DAYS"
EOF

# Cambiar al directorio de Easy-RSA para ejecutar comandos
cd "$EASYRSA_DIR" || log_fatal "No se pudo cambiar al directorio $EASYRSA_DIR."

log_info "Inicializando PKI..."
run_cmd ./easyrsa --vars=./vars init-pki || log_fatal "Falló init-pki."

log_info "Construyendo Autoridad Certificadora (CA)... (Esto puede tardar)"
# Usar --batch para no pedir confirmaciones, nopass para CA sin contraseña
run_cmd ./easyrsa --batch --vars=./vars build-ca nopass || log_fatal "Falló build-ca."

log_info "Generando solicitud y clave para el servidor OpenVPN..."
run_cmd ./easyrsa --batch --vars=./vars gen-req server nopass || log_fatal "Falló gen-req server."

log_info "Firmando solicitud del servidor..."
run_cmd ./easyrsa --batch --vars=./vars sign-req server server || log_fatal "Falló sign-req server."

log_info "Generando parámetros Diffie-Hellman (DH)... (Esto tomará MUCHO tiempo para ${EASYRSA_KEY_SIZE}-bit)"
run_cmd ./easyrsa --vars=./vars gen-dh || log_fatal "Falló gen-dh."

log_info "Generando clave TLS-Crypt (ta.key)..."
# Guardar ta.key directamente en el directorio del servidor para simplificar
run_cmd openvpn --genkey --secret "${SERVER_CONFIG_DIR}/ta.key" || log_fatal "Falló la generación de ta.key."

log_info "Generando Lista de Revocación de Certificados (CRL)..."
run_cmd ./easyrsa --vars=./vars gen-crl || log_fatal "Falló gen-crl."

# Volver al directorio original del script
cd "$SCRIPT_DIR_MODULE/.." || log_warn "No se pudo volver al directorio del script manager."

# Copiar archivos necesarios al directorio del servidor OpenVPN
log_info "Copiando archivos de PKI al directorio del servidor: $SERVER_CONFIG_DIR"
run_cmd mkdir -p "$SERVER_CONFIG_DIR" || log_fatal "No se pudo crear $SERVER_CONFIG_DIR."
run_cmd cp "${EASYRSA_DIR}/pki/ca.crt" "${SERVER_CONFIG_DIR}/"
run_cmd cp "${EASYRSA_DIR}/pki/issued/server.crt" "${SERVER_CONFIG_DIR}/"
run_cmd cp "${EASYRSA_DIR}/pki/private/server.key" "${SERVER_CONFIG_DIR}/"
run_cmd cp "${EASYRSA_DIR}/pki/dh.pem" "${SERVER_CONFIG_DIR}/" # EasyRSA 3.x usa dh.pem
run_cmd cp "${EASYRSA_DIR}/pki/crl.pem" "${SERVER_CONFIG_DIR}/"
# ta.key ya se generó en SERVER_CONFIG_DIR

# Establecer permisos restrictivos para las claves privadas
log_info "Estableciendo permisos para archivos de claves..."
run_cmd chmod 600 "${SERVER_CONFIG_DIR}/server.key"
run_cmd chmod 600 "${SERVER_CONFIG_DIR}/ta.key"
# ca.crt, server.crt, dh.pem, crl.pem pueden ser 644

# --- 6. Creación de server.conf ---
log_info "--- Creando Archivo de Configuración del Servidor (server.conf) ---"
SERVER_CONF_PATH="${SERVER_CONFIG_DIR}/server.conf"

# Construir las opciones de DNS para push
PUSH_DNS_OPTIONS=""
if [ ${#DNS_SERVERS[@]} -gt 0 ]; then
    for dns_ip in "${DNS_SERVERS[@]}"; do
        PUSH_DNS_OPTIONS+="push \"dhcp-option DNS $dns_ip\"\n"
    done
fi

cat << EOF > "$SERVER_CONF_PATH"
# Configuración del Servidor OpenVPN generada por ZStar OVPN
# Fecha: $(date)

port $VPN_PORT
proto $VPN_PROTO_SERVER_CONF
dev tun
topology subnet

ca ${SERVER_CONFIG_DIR}/ca.crt
cert ${SERVER_CONFIG_DIR}/server.crt
key ${SERVER_CONFIG_DIR}/server.key
dh ${SERVER_CONFIG_DIR}/dh.pem
crl-verify ${SERVER_CONFIG_DIR}/crl.pem
tls-crypt ${SERVER_CONFIG_DIR}/ta.key

server $DEFAULT_VPN_NETWORK $DEFAULT_VPN_NETMASK
ifconfig-pool-persist ${LOG_DIR}/ipp.txt 3600 # Persistir IPs de clientes por 1 hora

# --- Opciones de Red y Cliente ---
push "redirect-gateway def1 bypass-dhcp"
${PUSH_DNS_OPTIONS}
push "block-outside-dns" # Para clientes Windows

keepalive 10 120 # Ping cada 10s, asumir muerto después de 120s

# --- Seguridad ---
cipher AES-256-GCM
auth SHA256
# data-ciphers AES-256-GCM:AES-128-GCM # Para clientes que soportan negociación
# data-ciphers-fallback AES-256-CBC # Para clientes muy viejos (no recomendado)

tls-version-min 1.2
remote-cert-tls client # Asegura que el cliente presenta un cert de cliente

# --- Privilegios y Persistencia ---
user nobody
group nogroup # En Debian/Ubuntu, 'nogroup' es común. En otros, 'nobody'.
persist-key
persist-tun

# --- Logging ---
status ${LOG_DIR}/openvpn-status.log
log-append ${LOG_DIR}/openvpn.log
verb 3 # Nivel de verbosidad (0-11)
# mute 20 # No registrar más de 20 mensajes idénticos consecutivos

# --- Opcionales (Comentados por defecto) ---
# client-to-client
# duplicate-cn # No recomendado, usar un cert por cliente
# compress lz4-v2
# push "compress lz4-v2"
# explicit-exit-notify 1
EOF

run_cmd mkdir -p "$LOG_DIR" # Crear directorio de logs si no existe
run_cmd chown nobody:nogroup "$LOG_DIR" # Dar permisos al usuario de OpenVPN

log_info "Archivo server.conf creado en $SERVER_CONF_PATH."

# --- 7. Creación de vpn_config.vars ---
log_info "--- Creando Archivo de Configuración de ZStar OVPN ($VPN_CONFIG_VARS_FILE) ---"
# Asegurarse de que el directorio /etc/openvpn exista (debería por el paquete)
run_cmd mkdir -p "$(dirname "$VPN_CONFIG_VARS_FILE")"

# Eliminar el archivo si existe para empezar de nuevo
[ -f "$VPN_CONFIG_VARS_FILE" ] && run_cmd rm "$VPN_CONFIG_VARS_FILE"

cat << EOF > "$VPN_CONFIG_VARS_FILE"
# Archivo de configuración de ZStar OVPN - NO EDITAR MANUALMENTE A MENOS QUE SEPAS LO QUE HACES
# Generado el: $(date)

export ZSTAR_INSTALL_DATE="$(date)"
export PUBLIC_IP_OR_DOMAIN="$PUBLIC_IP_OR_DOMAIN"
export VPN_PORT="$VPN_PORT"
export VPN_PROTO="$VPN_PROTO" # udp o tcp
export VPN_PROTO_SERVER_CONF="$VPN_PROTO_SERVER_CONF" # udp o tcp-server
export VPN_PROTO_CLIENT_CONF="$VPN_PROTO_CLIENT_CONF" # udp o tcp (o tcp-client)
export VPN_NETWORK="$DEFAULT_VPN_NETWORK"
export VPN_NETMASK="$DEFAULT_VPN_NETMASK"
export DNS_SERVERS_STRING="${DNS_SERVERS[*]}" # Guardar como string, se puede parsear después
export EASYRSA_DIR="$EASYRSA_DIR"
export SERVER_CONFIG_FILE="$SERVER_CONF_PATH"
export SERVER_CONFIG_DIR="$SERVER_CONFIG_DIR"
export CLIENT_OVPN_OUTPUT_DIR="$CLIENT_OVPN_OUTPUT_DIR"
export LOG_DIR="$LOG_DIR"
export DEFAULT_CLIENT_CERT_EXPIRE="$DEFAULT_CERT_EXPIRE" # Para el script de gestión de clientes
# Añadir más variables según sea necesario
EOF
run_cmd chmod 600 "$VPN_CONFIG_VARS_FILE" # Solo root debería leer/escribir
log_info "Archivo $VPN_CONFIG_VARS_FILE creado."

# --- 8. Configuración del Firewall ---
log_info "--- Configurando Firewall ---"
MAIN_NETWORK_INTERFACE=$(get_main_network_interface)
if [ -z "$MAIN_NETWORK_INTERFACE" ]; then
    MAIN_NETWORK_INTERFACE=$(ask_value "No se pudo detectar la interfaz de red principal. Ingrésala (ej: eth0, ens3)" "" "^[a-zA-Z0-9]+$" "Nombre de interfaz inválido." "noempty")
fi
if [ -z "$MAIN_NETWORK_INTERFACE" ]; then log_fatal "Se requiere la interfaz de red principal para el firewall."; fi
log_info "Usando interfaz de red principal: $MAIN_NETWORK_INTERFACE"

# Guardar interfaz en vpn_config.vars para uso futuro (ej: reconfiguración)
echo "export MAIN_NETWORK_INTERFACE=\"$MAIN_NETWORK_INTERFACE\"" >> "$VPN_CONFIG_VARS_FILE"


if command -v ufw >/dev/null 2>&1; then
    log_info "Configurando UFW..."
    # Permitir SSH para no bloquearse (si no está ya permitido)
    if ! ufw status | grep -qw "22/tcp"; then # Simple check, puede ser más robusto
        run_cmd ufw allow ssh
    fi
    # Permitir el puerto OpenVPN
    run_cmd ufw allow "${VPN_PORT}/${VPN_PROTO}"
    # Configurar política de FORWARD y NAT
    if grep -q "^\s*DEFAULT_FORWARD_POLICY\s*=\s*\"DROP\"" /etc/default/ufw; then
        run_cmd sed -i 's/^\s*DEFAULT_FORWARD_POLICY\s*=\s*"DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    elif ! grep -q "^\s*DEFAULT_FORWARD_POLICY\s*=\s*\"ACCEPT\"" /etc/default/ufw; then
        echo -e "\n# Added by ZStar OVPN for OpenVPN forwarding\nDEFAULT_FORWARD_POLICY=\"ACCEPT\"" >> /etc/default/ufw
    fi
    # Añadir reglas de NAT a before.rules
    UFW_BEFORE_RULES="/etc/ufw/before.rules"
    NAT_RULE_COMMENT="# ZStar OVPN NAT rules for $DEFAULT_VPN_NETWORK (OpenVPN)"
    NAT_RULE_CONTENT="*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s $DEFAULT_VPN_NETWORK/$DEFAULT_VPN_NETMASK -o $MAIN_NETWORK_INTERFACE -j MASQUERADE\nCOMMIT"
    # Eliminar reglas antiguas de ZStar si existen para evitar duplicados
    if grep -qF "$NAT_RULE_COMMENT" "$UFW_BEFORE_RULES"; then
        # Esto es complejo de hacer con sed de forma idempotente.
        # Por ahora, si ya existe el comentario, asumimos que las reglas están o el usuario las maneja.
        # Una mejor forma sería usar un marcador de inicio/fin y reemplazar el bloque.
        log_warn "Reglas de NAT de ZStar OVPN ya podrían existir en $UFW_BEFORE_RULES. Verifica manualmente."
    else
        # Añadir al principio del archivo, después de la línea *filter o si no existe.
        # Esto es delicado. Una forma más segura es añadirlo justo antes de un 'COMMIT' final si existe,
        # o al final del bloque *nat.
        # Por simplicidad, lo añadimos al principio del archivo si no está el comentario.
        # Esto podría no ser ideal para todos los before.rules.
        TEMP_BEFORE_RULES=$(mktemp)
        echo -e "$NAT_RULE_COMMENT\n$NAT_RULE_CONTENT\n$(cat $UFW_BEFORE_RULES)" > "$TEMP_BEFORE_RULES"
        run_cmd cp "$TEMP_BEFORE_RULES" "$UFW_BEFORE_RULES"
        rm "$TEMP_BEFORE_RULES"
        log_info "Reglas de NAT añadidas a $UFW_BEFORE_RULES (revisar si es necesario)."
    fi
    run_cmd ufw disable # Deshabilitar para aplicar cambios de before.rules
    run_cmd ufw enable  # Volver a habilitar
    log_info "UFW configurado. Estado: $(ufw status verbose | head -n 1)"
else
    log_info "UFW no encontrado. Configurando iptables..."
    # Permitir puerto OpenVPN
    run_cmd iptables -A INPUT -i "$MAIN_NETWORK_INTERFACE" -m state --state NEW -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT
    # Permitir tráfico establecido y relacionado (generalmente ya existe o es bueno tenerlo)
    run_cmd iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    run_cmd iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    # Permitir forwarding desde la red VPN
    run_cmd iptables -A FORWARD -s "$DEFAULT_VPN_NETWORK/$DEFAULT_VPN_NETMASK" -o "$MAIN_NETWORK_INTERFACE" -j ACCEPT
    # Permitir forwarding hacia la red VPN (si los clientes necesitan ser accedidos desde la LAN del servidor)
    run_cmd iptables -A FORWARD -i "$MAIN_NETWORK_INTERFACE" -d "$DEFAULT_VPN_NETWORK/$DEFAULT_VPN_NETMASK" -m state --state RELATED,ESTABLISHED -j ACCEPT
    # NAT (Masquerade)
    run_cmd iptables -t nat -A POSTROUTING -s "$DEFAULT_VPN_NETWORK/$DEFAULT_VPN_NETMASK" -o "$MAIN_NETWORK_INTERFACE" -j MASQUERADE
    # Guardar reglas
    if command -v netfilter-persistent >/dev/null 2>&1; then
        run_cmd netfilter-persistent save
        run_cmd netfilter-persistent start # Asegurar que esté activo
    elif command -v iptables-save >/dev/null 2>&1; then
        run_cmd mkdir -p /etc/iptables
        run_cmd bash -c "iptables-save > /etc/iptables/rules.v4"
        # Considerar ip6tables si es necesario
    else
        log_error "No se pudo guardar las reglas de iptables de forma persistente."
    fi
    log_info "Reglas de iptables configuradas."
fi

# --- 9. Generación del Primer Perfil de Cliente ---
log_info "--- Generando Primer Perfil de Cliente ($FIRST_CLIENT_NAME) ---"
run_cmd mkdir -p "$CLIENT_OVPN_OUTPUT_DIR"

cd "$EASYRSA_DIR" || log_fatal "No se pudo cambiar al directorio $EASYRSA_DIR para generar cliente."
log_info "Generando solicitud y clave para el cliente '$FIRST_CLIENT_NAME'..."
run_cmd ./easyrsa --batch --vars=./vars --req-cn="$FIRST_CLIENT_NAME" gen-req "$FIRST_CLIENT_NAME" nopass || log_fatal "Falló gen-req para $FIRST_CLIENT_NAME."
log_info "Firmando solicitud del cliente '$FIRST_CLIENT_NAME'..."
run_cmd ./easyrsa --batch --vars=./vars sign-req client "$FIRST_CLIENT_NAME" || log_fatal "Falló sign-req para $FIRST_CLIENT_NAME."
cd "$SCRIPT_DIR_MODULE/.." || log_warn "No se pudo volver al directorio del script manager."

# Crear archivo .ovpn
CLIENT_OVPN_FILE="${CLIENT_OVPN_OUTPUT_DIR}/${FIRST_CLIENT_NAME}.ovpn"
log_info "Creando archivo de configuración del cliente: $CLIENT_OVPN_FILE"
# Obtener contenido de los archivos (manejar errores si los archivos no existen)
CA_CONTENT=$(cat "${SERVER_CONFIG_DIR}/ca.crt") || log_fatal "No se pudo leer ca.crt"
CLIENT_CERT_CONTENT=$(cat "${EASYRSA_DIR}/pki/issued/${FIRST_CLIENT_NAME}.crt") || log_fatal "No se pudo leer ${FIRST_CLIENT_NAME}.crt"
CLIENT_KEY_CONTENT=$(cat "${EASYRSA_DIR}/pki/private/${FIRST_CLIENT_NAME}.key") || log_fatal "No se pudo leer ${FIRST_CLIENT_NAME}.key"
TLS_CRYPT_CONTENT=$(cat "${SERVER_CONFIG_DIR}/ta.key") || log_fatal "No se pudo leer ta.key"

cat << EOF > "$CLIENT_OVPN_FILE"
client
dev tun
proto $VPN_PROTO_CLIENT_CONF
remote $PUBLIC_IP_OR_DOMAIN $VPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server # Verifica que el certificado del servidor es para un servidor
cipher AES-256-GCM
auth SHA256
verb 3
# key-direction 1 # No necesario para tls-crypt, sí para tls-auth

<ca>
$CA_CONTENT
</ca>
<cert>
$CLIENT_CERT_CONTENT
</cert>
<key>
$CLIENT_KEY_CONTENT
</key>
<tls-crypt>
$TLS_CRYPT_CONTENT
</tls-crypt>
EOF
run_cmd chmod 600 "$CLIENT_OVPN_FILE" # Proteger el archivo .ovpn
log_info "Perfil de cliente generado: $CLIENT_OVPN_FILE"
log_warn "Transfiere este archivo de forma segura a tu dispositivo cliente."

# --- 10. Inicio y Habilitación del Servicio OpenVPN ---
log_info "--- Iniciando y Habilitando Servicio OpenVPN ---"
# El nombre del servicio depende de cómo systemd maneje openvpn y el nombre del .conf
# Usualmente es openvpn-server@<nombre_sin_conf>.
# Si nuestro archivo es /etc/openvpn/server/server.conf, el servicio es openvpn-server@server.service
SERVICE_NAME="openvpn-server@server.service" # Asumiendo que el server.conf se llama 'server.conf'
run_cmd systemctl daemon-reload # Por si acaso
run_cmd systemctl restart "$SERVICE_NAME" || log_fatal "Falló el reinicio del servicio OpenVPN ($SERVICE_NAME)."
run_cmd systemctl enable "$SERVICE_NAME" || log_warn "Falló la habilitación del servicio OpenVPN ($SERVICE_NAME)."

# Verificar estado
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_info "Servicio OpenVPN ($SERVICE_NAME) iniciado y activo."
else
    log_error "El servicio OpenVPN ($SERVICE_NAME) no parece estar activo después del inicio."
    log_error "Revisa los logs: journalctl -u $SERVICE_NAME  y  cat ${LOG_DIR}/openvpn.log"
fi

# --- 11. Mensaje Final ---
log_info "---------------------------------------------------------------------"
log_info "¡Instalación del Servidor OpenVPN con ZStar OVPN Completada!"
log_info "---------------------------------------------------------------------"
log_info "Resumen Rápido:"
log_info "  - IP/Dominio del Servidor: $PUBLIC_IP_OR_DOMAIN"
log_info "  - Puerto: $VPN_PORT, Protocolo: $VPN_PROTO"
log_info "  - Primer perfil de cliente: $CLIENT_OVPN_FILE"
log_info "  - Certificados de cliente expiran en: $DEFAULT_CERT_EXPIRE días (aprox. 1 año)."
log_warn "RECORDATORIOS IMPORTANTES:"
log_warn "  1. Transfiere el archivo '${FIRST_CLIENT_NAME}.ovpn' a tu dispositivo cliente de forma SEGURA."
log_warn "  2. Asegúrate de que tu firewall externo (router, proveedor de cloud) esté configurado para"
log_warn "     REENVIAR el puerto $VPN_PORT ($VPN_PROTO) a la IP LAN de este servidor OpenVPN."
log_warn "  3. Revisa los logs de OpenVPN en ${LOG_DIR}/openvpn.log si encuentras problemas."
log_warn "  4. Para gestionar clientes (añadir/revocar), usa la opción correspondiente en ZStar OVPN Manager."
log_info "---------------------------------------------------------------------"

exit 0
