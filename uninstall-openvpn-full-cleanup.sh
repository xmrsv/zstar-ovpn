#!/bin/bash

# --- Script para Desinstalar Completamente OpenVPN y sus Configuraciones en Debian ---
# ADVERTENCIA: Este script es destructivo y eliminará datos de OpenVPN.
# Úsalo bajo tu propio riesgo y asegúrate de tener backups si es necesario.

# --- Funciones Auxiliares (simplificadas para este script) ---
log_info() { echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1"; }
log_warn() { echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') - $1"; }
log_error() { echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2; }

run_cmd() {
    log_info "Ejecutando: $@"
    "$@"
    local status=$?
    if [ $status -ne 0 ]; then
        log_error "Comando falló con estado $status: $@"
    fi
    return $status
}

ask_yes_no() {
    local question="$1"
    local default_answer="${2:-n}"
    local answer
    while true; do
        read -rp "$question [S/n] (Default: $default_answer): " answer
        answer="${answer:-$default_answer}"
        case "$answer" in
            [SsYy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) log_warn "Respuesta inválida. Por favor, responde 's' o 'n'.";;
        esac
    done
}

# --- Verificación de Root ---
if [[ $EUID -ne 0 ]]; then
   log_error "Este script debe ser ejecutado como root."
   exit 1
fi

# --- Confirmación Crítica ---
log_warn "--------------------------------------------------------------------"
log_warn "¡ADVERTENCIA! Este script desinstalará OpenVPN y eliminará TODAS"
log_warn "sus configuraciones, incluyendo /etc/openvpn (PKI, claves, certs),"
log_warn "logs, y potencialmente reglas de firewall relacionadas."
log_warn "Esto es IRREVERSIBLE si no tienes backups externos."
log_warn "--------------------------------------------------------------------"
if ! ask_yes_no "¿Estás ABSOLUTAMENTE SEGURO de que quieres continuar?" "n"; then
    log_info "Operación cancelada por el usuario."
    exit 0
fi
if ! ask_yes_no "ÚLTIMA OPORTUNIDAD: ¿Realmente quieres borrar todo lo de OpenVPN?" "n"; then
    log_info "Operación cancelada por el usuario."
    exit 0
fi

log_info "--- Iniciando Desinstalación Completa de OpenVPN ---"

# --- 1. Detener y Deshabilitar Servicios OpenVPN ---
log_info "Intentando detener y deshabilitar servicios OpenVPN..."
# Intentar con nombres comunes de servicio. systemctl no falla si el servicio no existe.
# El @* es un comodín para cualquier instancia de servicio.
run_cmd systemctl stop 'openvpn@*.service' 'openvpn-server@*.service' openvpn.service
run_cmd systemctl disable 'openvpn@*.service' 'openvpn-server@*.service' openvpn.service
# Forzar la recarga de systemd por si acaso
run_cmd systemctl daemon-reload

# --- 2. Purgar Paquetes ---
log_info "Purgando paquetes openvpn y easy-rsa..."
run_cmd apt-get update -qq
run_cmd apt-get purge -y openvpn easy-rsa
run_cmd apt-get autoremove -y
run_cmd apt-get clean

# --- 3. Eliminar Directorios de Configuración y PKI ---
log_info "Eliminando directorios de configuración de OpenVPN..."
if [ -d "/etc/openvpn" ]; then
    run_cmd rm -rf /etc/openvpn/
    log_info "/etc/openvpn/ eliminado."
else
    log_info "/etc/openvpn/ no encontrado, omitiendo."
fi

# Eliminar otras ubicaciones comunes o antiguas de Easy-RSA
if [ -d "/etc/ssl/easy-rsa" ]; then
    run_cmd rm -rf /etc/ssl/easy-rsa/
    log_info "/etc/ssl/easy-rsa/ eliminado."
fi
if [ -d "/usr/share/easy-rsa" ]; then
    # El paquete easy-rsa puede ponerlo aquí, pero apt purge debería manejarlo.
    # No obstante, si se copió manualmente a otro lado...
    # Este es el directorio de los scripts de easy-rsa, no una PKI usualmente.
    # Si el usuario creó una PKI aquí, es su responsabilidad.
    # Por seguridad, no lo borramos a menos que el usuario lo pida específicamente.
    log_info "El directorio /usr/share/easy-rsa/ (scripts de EasyRSA) usualmente es manejado por el paquete."
    log_info "Si creaste una PKI allí manualmente, deberás borrarla tú."
fi
# Si sabes de otras ubicaciones personalizadas de Easy-RSA, añádelas aquí
# Ejemplo:
# if [ -d "/root/easy-rsa-custom-pki" ]; then
#    run_cmd rm -rf /root/easy-rsa-custom-pki/
#    log_info "/root/easy-rsa-custom-pki/ eliminado."
# fi

# --- 4. Eliminar Logs ---
log_info "Eliminando logs de OpenVPN..."
if [ -d "/var/log/openvpn" ]; then
    run_cmd rm -rf /var/log/openvpn/
    log_info "/var/log/openvpn/ eliminado."
else
    log_info "/var/log/openvpn/ no encontrado, omitiendo."
fi
if [ -f "/var/log/openvpn.log" ]; then
    run_cmd rm -f /var/log/openvpn.log
    log_info "/var/log/openvpn.log eliminado."
fi
if [ -f "/var/log/openvpn-status.log" ]; then
    run_cmd rm -f /var/log/openvpn-status.log
    log_info "/var/log/openvpn-status.log eliminado."
fi

# --- 5. Limpiar Reglas de Firewall (Intento Básico) ---
# Esto es complicado de automatizar perfectamente sin conocer las reglas exactas.
# Se enfoca en el puerto y protocolo más comunes que ZStar OVPN podría usar.
VPN_PORT_GUESS="1194" # Puerto por defecto de OpenVPN
VPN_PROTO_GUESS="udp" # Protocolo por defecto de OpenVPN
ZSTAR_PORT_GUESS="443" # Puerto que ZStar OVPN usará por defecto
ZSTAR_PROTO_GUESS="tcp" # Protocolo que ZStar OVPN usará por defecto
VPN_NETWORK_GUESS="10.8.0.0/24" # Red VPN común

log_info "Intentando limpiar reglas de firewall comunes de OpenVPN..."
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    log_info "UFW está activo. Intentando eliminar reglas comunes..."
    # Intentar eliminar reglas por puerto/protocolo
    run_cmd ufw delete allow ${VPN_PORT_GUESS}/${VPN_PROTO_GUESS} >/dev/null 2>&1
    run_cmd ufw delete allow ${ZSTAR_PORT_GUESS}/${ZSTAR_PROTO_GUESS} >/dev/null 2>&1
    # La eliminación de reglas de NAT en before.rules es manual.
    log_warn "Si tenías reglas de NAT en /etc/ufw/before.rules para OpenVPN (ej: para ${VPN_NETWORK_GUESS}),"
    log_warn "deberás eliminarlas manualmente editando ese archivo y luego ejecutando 'sudo ufw reload'."
    run_cmd ufw reload
else
    log_info "UFW no está activo o no está instalado. Intentando con iptables..."
    # Para iptables, solo eliminamos algunas reglas comunes si existen.
    # No intentamos un flush completo aquí para no afectar otras reglas del sistema.
    # El usuario debería revisar y limpiar manualmente si tiene configuraciones complejas.
    MAIN_INTERFACE_GUESS=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -n1)
    if [ -n "$MAIN_INTERFACE_GUESS" ]; then
        # Reglas de INPUT
        iptables -D INPUT -i "${MAIN_INTERFACE_GUESS}" -p "${VPN_PROTO_GUESS}" --dport "${VPN_PORT_GUESS}" -j ACCEPT >/dev/null 2>&1
        iptables -D INPUT -i "${MAIN_INTERFACE_GUESS}" -p "${ZSTAR_PROTO_GUESS}" --dport "${ZSTAR_PORT_GUESS}" -j ACCEPT >/dev/null 2>&1
        # Reglas de NAT
        iptables -t nat -D POSTROUTING -s "${VPN_NETWORK_GUESS}" -o "${MAIN_INTERFACE_GUESS}" -j MASQUERADE >/dev/null 2>&1
        # Reglas de FORWARD
        iptables -D FORWARD -s "${VPN_NETWORK_GUESS}" -j ACCEPT >/dev/null 2>&1
        iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 # Esta es genérica, cuidado

        log_info "Se intentó eliminar reglas comunes de iptables. Verifica con 'sudo iptables -L -v -n' y 'sudo iptables -t nat -L -v -n'."
        log_warn "Si usas iptables-persistent, guarda los cambios: 'sudo netfilter-persistent save' o equivalente."
    else
        log_warn "No se pudo detectar la interfaz de red principal para limpiar reglas de iptables."
    fi
fi

# --- 6. Deshabilitar IP Forwarding (Opcional, si el usuario lo desea) ---
if [ -f /etc/sysctl.conf ] && grep -q "^\s*net.ipv4.ip_forward\s*=\s*1" /etc/sysctl.conf; then
    if ask_yes_no "¿Deseas deshabilitar net.ipv4.ip_forward en /etc/sysctl.conf?" "n"; then
        log_info "Deshabilitando net.ipv4.ip_forward..."
        # Comentar la línea o cambiarla a 0. Comentar es más seguro para revertir.
        run_cmd sed -i 's/^\(\s*net.ipv4.ip_forward\s*=\s*1\)/#\1 # Deshabilitado por ZStar Cleanup/' /etc/sysctl.conf
        # O para cambiar a 0:
        # run_cmd sed -i 's/^\s*net.ipv4.ip_forward\s*=\s*1/\net.ipv4.ip_forward=0/' /etc/sysctl.conf
        run_cmd sysctl -p
        log_info "IP forwarding deshabilitado (o línea comentada)."
    else
        log_info "IP forwarding no fue modificado."
    fi
else
    log_info "IP forwarding no parece estar habilitado en /etc/sysctl.conf, o el archivo no existe."
fi

log_info "--- Desinstalación Completa de OpenVPN Finalizada ---"
log_warn "Se recomienda reiniciar el sistema para asegurar que todos los cambios se apliquen limpiamente."
log_warn "sudo reboot"

exit 0
