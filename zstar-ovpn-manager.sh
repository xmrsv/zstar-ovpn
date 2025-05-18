#!/bin/bash

# --- zstar-ovpn-manager.sh ---
# Script principal para gestionar el servidor OpenVPN con ZStar OVPN

# Obtener la ruta absoluta del directorio donde reside este script
SCRIPT_DIR_MANAGER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Definir rutas a los subdirectorios de módulos y librerías
MODULES_DIR="${SCRIPT_DIR_MANAGER}/modules"
LIB_DIR="${SCRIPT_DIR_MANAGER}/lib"

# --- Cargar Funciones Comunes ---
COMMON_FUNCTIONS_PATH="${LIB_DIR}/common-functions.sh"
if [ -f "$COMMON_FUNCTIONS_PATH" ]; then
    source "$COMMON_FUNCTIONS_PATH"
else
    # Usar echo aquí ya que las funciones de log aún no están cargadas
    echo "[FATAL] Archivo de funciones comunes no encontrado: $COMMON_FUNCTIONS_PATH" >&2
    echo "Asegúrate de que la estructura del proyecto ZStar OVPN sea correcta." >&2
    exit 1
fi

# --- Verificación de Root (desde common-functions.sh) ---
check_root

# --- Bucle del Menú Principal ---
while true; do
    clear # Limpiar pantalla para el menú
    # Usar las variables de color definidas en common-functions.sh
    echo -e "${C_CYAN} ZStar OVPN Manager v0.1${C_RESET}"
    echo "------------------------------------"
    echo -e "Usr: ${C_YELLOW}$(whoami)@$(hostname)${C_RESET}"
    echo -e "Date: ${C_YELLOW}$(date '+%Y-%m-%d %H:%M')${C_RESET}"
    echo "------------------------------------"
    echo -e "     ${C_BLUE}-= Main Menu =-${C_RESET}"
    echo ""
    echo -e "${C_GREEN}[1]${C_RESET} Install New Server"
    echo -e "${C_GREEN}[2]${C_RESET} Manage Clients"
    echo -e "${C_GREEN}[3]${C_RESET} Reconfig Server"
    echo -e "${C_GREEN}[4]${C_RESET} Backup Config"
    echo -e "${C_YELLOW}[5]${C_RESET} Server Status ${C_BLUE}(Soon)${C_RESET}"
    echo -e "${C_YELLOW}[s]${C_RESET} Settings ${C_BLUE}(Adv/Soon)${C_RESET}"
    echo -e "${C_RED}[q]${C_RESET} Quit"
    echo ""
    echo "------------------------------------"

    # CORRECCIÓN APLICADA AQUÍ: Se eliminó 'local' antes de 'choice'
    choice=$(ask_value "Choice" "" "^[1-5sSqQ]$" "Opción inválida.")

    case "$choice" in
        1)
            log_info "Lanzando: Módulo de Instalación del Servidor..."
            if [ -x "${MODULES_DIR}/01-install-server.sh" ]; then
                bash "${MODULES_DIR}/01-install-server.sh"
            else
                log_error "Módulo no encontrado o no ejecutable: ${MODULES_DIR}/01-install-server.sh"
            fi
            ;;
        2)
            log_info "Lanzando: Módulo de Gestión de Clientes..."
            if [ -x "${MODULES_DIR}/02-manage-clients.sh" ]; then
                bash "${MODULES_DIR}/02-manage-clients.sh"
            else
                log_error "Módulo no encontrado o no ejecutable: ${MODULES_DIR}/02-manage-clients.sh"
            fi
            ;;
        3)
            log_info "Lanzando: Módulo de Reconfiguración del Servidor..."
            if [ -x "${MODULES_DIR}/03-reconfigure-server.sh" ]; then
                bash "${MODULES_DIR}/03-reconfigure-server.sh"
            else
                log_error "Módulo no encontrado o no ejecutable: ${MODULES_DIR}/03-reconfigure-server.sh"
            fi
            ;;
        4)
            log_info "Lanzando: Módulo de Backup de Configuración..."
            if [ -x "${MODULES_DIR}/04-backup-openvpn-config.sh" ]; then
                bash "${MODULES_DIR}/04-backup-openvpn-config.sh"
            else
                log_error "Módulo no encontrado o no ejecutable: ${MODULES_DIR}/04-backup-openvpn-config.sh"
            fi
            ;;
        5)
            log_warn "Módulo de Estado del Servidor aún no implementado."
            ;;
        [Ss]) # Para la opción 's' o 'S'
            log_warn "Módulo de Configuración de ZStar aún no implementado."
            ;;
        [Qq]) # Para la opción 'q' o 'Q'
            log_info "Saliendo de ZStar OVPN Manager."
            exit 0
            ;;
        *)
            # Esto no debería ocurrir si ask_value con regex funciona bien, pero por si acaso.
            log_warn "Opción no válida procesada: '$choice'. Esto es inesperado."
            ;;
    esac

    # Pausa antes de volver a mostrar el menú, solo si no se salió
    if [[ "$choice" != [Qq]* ]]; then # Comprobar si la elección NO FUE 'q' o 'Q'
        echo "" # Línea extra para espaciado
        read -rp "Presiona Enter para volver al menú..."
    fi
done
