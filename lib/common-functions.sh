#!/bin/bash

# --- lib/common-functions.sh ---
# Funciones comunes para los scripts de ZStar OVPN

# Archivo de configuración central de OpenVPN (generado por el módulo de instalación)
VPN_CONFIG_VARS_FILE="/etc/openvpn/vpn_config.vars"

# --- Funciones de Logging ---
# Formato de fecha y hora para los logs
LOG_DATETIME_FORMAT='+%Y-%m-%d %H:%M:%S'

# Colores (opcional, pero útil para la legibilidad)
# Comenta o elimina estas líneas si prefieres sin colores o si causan problemas
# en terminales muy limitadas.
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'

log_info() {
    echo -e "${C_GREEN}[INFO] $(date "$LOG_DATETIME_FORMAT") - $1${C_RESET}"
}
log_warn() {
    echo -e "${C_YELLOW}[WARN] $(date "$LOG_DATETIME_FORMAT") - $1${C_RESET}"
}
log_error() {
    # Errores a stderr
    echo -e "${C_RED}[ERROR] $(date "$LOG_DATETIME_FORMAT") - $1${C_RESET}" >&2
}
log_fatal() {
    log_error "$1"
    log_error "Saliendo debido a un error fatal."
    exit 1
}
log_debug() {
    # Para mensajes de depuración, solo se muestran si ZSTAR_DEBUG está seteado
    if [[ -n "$ZSTAR_DEBUG" && "$ZSTAR_DEBUG" -eq 1 ]]; then
        echo -e "${C_BLUE}[DEBUG] $(date "$LOG_DATETIME_FORMAT") - $1${C_RESET}"
    fi
}

# --- Verificación de Root ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
       log_fatal "Este script/módulo debe ser ejecutado como root."
    fi
}

# --- Ejecución de Comandos ---
run_cmd() {
    log_debug "Ejecutando (run_cmd): $@"
    # Ejecutar el comando, redirigiendo stdout y stderr a un log si ZSTAR_DEBUG está activo,
    # o solo mostrar un mensaje de "Ejecutando..."
    # Por ahora, simple:
    # log_info "Ejecutando: $@" # Puede ser muy verboso, usar log_debug
    "$@"
    local status=$?
    if [ $status -ne 0 ]; then
        log_error "Comando falló con estado $status: $@"
    fi
    return $status
}

# --- Funciones de Interacción con el Usuario ---
ask_yes_no() {
    # $1: Pregunta
    # $2: Default (s/n)
    local question="$1"
    local default_answer="${2:-n}" # Default a 'n' si no se especifica
    local answer_prompt
    local answer

    if [[ "$default_answer" == "s" ]]; then
        answer_prompt="[S/n]"
    else
        answer_prompt="[s/N]"
    fi

    while true; do
        # Usar -e para interpretar escapes de color si se usan en la pregunta
        read -rp "$(echo -e "${question}") ${answer_prompt}: " answer
        answer="${answer:-$default_answer}" # Aplicar default si la entrada está vacía
        case "$answer" in
            [SsYy]* ) return 0;; # Aceptar S, s, Y, y
            [Nn]* ) return 1;;   # Aceptar N, n
            * ) log_warn "Respuesta inválida. Por favor, responde 's' o 'n'.";;
        esac
    done
}

ask_value() {
    # $1: Pregunta
    # $2: Valor por defecto
    # $3: (Opcional) Regex de validación
    # $4: (Opcional) Mensaje de error para validación fallida
    # $5: (Opcional) 'noempty' para no permitir valor vacío incluso si no hay default
    local question="$1"
    local default_value="$2"
    local validation_regex="$3"
    local error_message="$4"
    local no_empty_flag="$5"
    local value

    local prompt_default_text=""
    if [ -n "$default_value" ]; then
        prompt_default_text=" (Default: $default_value)"
    fi

    while true; do
        read -rp "$(echo -e "${question}")${prompt_default_text}: " value
        value="${value:-$default_value}" # Aplicar default si la entrada está vacía

        if [[ "$no_empty_flag" == "noempty" && -z "$value" ]]; then
            log_warn "Este valor no puede estar vacío."
            continue # Volver a preguntar
        fi

        if [[ -n "$validation_regex" ]]; then
            if [[ "$value" =~ $validation_regex ]]; then
                echo "$value" # Devolver valor validado
                return 0
            else
                log_warn "${error_message:-Valor inválido. Inténtalo de nuevo.}"
            fi
        else
            echo "$value" # Devolver valor sin validación específica de regex
            return 0
        fi
    done
}

# --- Detección de IP Pública ---
get_public_ip() {
    local ip
    # Intentar con varios servicios, con timeouts cortos
    ip=$(curl -s --max-time 5 https://api.ipify.org)
    if [[ -z "$ip" ]]; then ip=$(curl -s --max-time 5 https://icanhazip.com); fi
    if [[ -z "$ip" ]]; then ip=$(curl -s --max-time 5 https://ifconfig.me/ip); fi
    # Añadir más si es necesario

    if [[ -z "$ip" ]]; then
        log_warn "No se pudo detectar la IP pública automáticamente."
        # La función que llama a get_public_ip deberá manejar el caso de IP vacía
        # y preguntar al usuario.
        echo "" # Devolver vacío para indicar fallo
        return 1
    else
        # Validar que parezca una IP (simple validación)
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "$ip"
            return 0
        else
            log_warn "El valor obtenido ($ip) no parece una IP válida. Se pedirá manualmente."
            echo ""
            return 1
        fi
    fi
}

# --- Detección de Interfaz de Red Principal (para NAT) ---
get_main_network_interface() {
    local interface
    # Intenta obtener la interfaz usada por la ruta por defecto
    interface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -n1)
    if [ -z "$interface" ]; then
        # Fallback: listar interfaces y tratar de adivinar (esto es más propenso a errores)
        # Podríamos listar interfaces activas y excluir lo, docker0, virbr0, tun, etc.
        # Por ahora, si el primer método falla, devolvemos vacío.
        log_warn "No se pudo detectar automáticamente la interfaz de red principal."
        echo ""
        return 1
    else
        echo "$interface"
        return 0
    fi
}

log_info "Funciones comunes de ZStar OVPN cargadas."
# Fin de lib/common-functions.sh
