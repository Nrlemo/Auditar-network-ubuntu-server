#!/usr/bin/env bash
# Auditoría de red – versión dinámica / interactiva
# Ejecutar con:  sudo ./audit_net_dynamic.sh
set -euo pipefail

#######################
# COLORES Y PROGRESO
#######################
C_RESET="\033[0m"
C_INFO="\033[1;34m"
C_OK="\033[1;32m"
C_WARN="\033[1;33m"
C_ERR="\033[1;31m"

progress() {
  local level="$1"; shift
  local msg="$*"
  local now
  now="$(date +'%Y-%m-%d %H:%M:%S')"
  case "$level" in
    INFO) echo -e "${C_INFO}[${now}] [INFO]${C_RESET} $msg" ;;
    OK)   echo -e "${C_OK}[${now}] [ OK ]${C_RESET} $msg" ;;
    WARN) echo -e "${C_WARN}[${now}] [WARN]${C_RESET} $msg" ;;
    ERR)  echo -e "${C_ERR}[${now}] [ERR ]${C_RESET} $msg" ;;
    *)    echo "[${now}] $msg" ;;
  esac
  echo "[${now}] [$level] $msg" >> "$LOGFILE"
}

#######################
# PREPARACIÓN
#######################
TS="$(date +'%Y%m%d_%H%M%S')"
OUTDIR="/var/tmp/audit_red_${TS}"
mkdir -p "$OUTDIR"
SUMMARY_CSV="${OUTDIR}/audit_resumen_${TS}.csv"
DETAIL_CSV="${OUTDIR}/audit_detalle_${TS}.csv"
LOGFILE="${OUTDIR}/audit.log"

echo "categoria,item,estado,detalle" > "$SUMMARY_CSV"
echo "categoria,clave,valor" > "$DETAIL_CSV"

add_summary() {
  printf '%s,"%s",%s,"%s"\n' "$1" "$2" "$3" "$4" >> "$SUMMARY_CSV"
}
add_detail() {
  local val="${3//$'\n'/' | '}"
  printf '%s,"%s","%s"\n' "$1" "$2" "$val" >> "$DETAIL_CSV"
}
note_ok()   { add_summary "$1" "$2" "OK" "$3"; progress OK "$1 - $2: $3"; }
note_warn() { add_summary "$1" "$2" "WARN" "$3"; progress WARN "$1 - $2: $3"; }
note_fail() { add_summary "$1" "$2" "FAIL" "$3"; progress ERR "$1 - $2: $3"; }

run_cmd_out() {
  local out
  if ! out="$("$@" 2>&1)"; then
    echo "$out"
  else
    echo "$out"
  fi
}

#######################
# PREGUNTAS INTERACTIVAS
#######################
# NOTA: si queda vacío, se omite ese check

read -r -p "Nombre del servidor (ENTER para autodetectar): " SERVER_NAME
if [ -z "${SERVER_NAME:-}" ]; then
  SERVER_NAME="$(hostname -f 2>/dev/null || hostname)"
fi

read -r -p "IP de este servidor (ENTER para autodetectar de eno1): " SERVER_IP
if [ -z "${SERVER_IP:-}" ]; then
  # mejor esfuerzo: tomar primera inet que no sea 127
  SERVER_IP="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"
fi

read -r -p "IP de gateway/pasarela (ENTER para omitir ping a gateway): " GATEWAY_IP || true

read -r -p "IP de otro servidor para probar (ej. DNS secundario) (ENTER para omitir): " SERVER2_IP || true

read -r -p "¿Probar conectividad a Internet? (y/N): " ANSW_INTERNET || true
CHECK_INTERNET="no"
[ "${ANSW_INTERNET,,}" = "y" ] && CHECK_INTERNET="yes"

read -r -p "¿Chequear Zerotier? (y/N): " ANSW_ZT || true
CHECK_ZT="no"
[ "${ANSW_ZT,,}" = "y" ] && CHECK_ZT="yes"
ZT_NET_ID=""
if [ "$CHECK_ZT" = "yes" ]; then
  read -r -p "ID de red Zerotier (ENTER para sólo verificar servicio): " ZT_NET_ID || true
fi

read -r -p "Email de destino para enviar reporte (ENTER para NO enviar): " EMAIL_TO || true
EMAIL_FROM="root@${SERVER_NAME}"

read -r -p "Horas de logs a revisar (ENTER = 24): " LOG_WINDOW_HOURS || true
[ -z "${LOG_WINDOW_HOURS:-}" ] && LOG_WINDOW_HOURS=24

progress INFO "Iniciando auditoría dinámica en $SERVER_NAME"
add_detail "sistema" "hostname" "$SERVER_NAME"
add_detail "sistema" "fecha" "$(date -Is)"

#######################
# 1) SISTEMA / INTERFACES
#######################
progress INFO "Recolectando info de sistema e interfaces..."
add_detail "sistema" "kernel" "$(uname -r)"

ip_addr="$(run_cmd_out ip -brief addr)"
add_detail "interfaces" "ip -brief addr" "$ip_addr"

ip_route="$(run_cmd_out ip route)"
add_detail "rutas" "ip route" "$ip_route"

if [ -n "${GATEWAY_IP:-}" ]; then
  if grep -q "default via ${GATEWAY_IP}" <<< "$ip_route"; then
    note_ok "rutas" "Gateway" "Gateway por defecto: ${GATEWAY_IP}"
  else
    note_warn "rutas" "Gateway" "Default route no apunta a ${GATEWAY_IP}"
  fi
else
  note_warn "rutas" "Gateway" "No se proporcionó gateway; se omite validación"
fi

# IPv6
ip6_addr="$(run_cmd_out ip -6 addr || true)"
if grep -qi 'inet6' <<< "$ip6_addr"; then
  add_detail "interfaces" "ip -6 addr" "$ip6_addr"
  note_ok "interfaces" "IPv6" "Se detectó IPv6"
else
  note_warn "interfaces" "IPv6" "No se detectó IPv6 o está deshabilitado"
fi

#######################
# 2) SALUD BÁSICA
#######################
progress INFO "Verificando disco/memoria..."
df_root="$(df -h / | tail -1)"
add_detail "sistema" "df -h /" "$df_root"
used_pct="$(echo "$df_root" | awk '{print $(NF-1)}' | tr -d '%')"
if [ "${used_pct:-0}" -gt 90 ]; then
  note_warn "sistema" "Disco /" "Uso alto: ${used_pct}%"
else
  note_ok "sistema" "Disco /" "Uso ${used_pct}%"
fi
add_detail "sistema" "free -h" "$(free -h)"
add_detail "sistema" "loadavg" "$(cat /proc/loadavg)"

#######################
# 3) FIREWALL
#######################
progress INFO "Comprobando firewall..."
ufw_state="$( (ufw status 2>/dev/null || true) | head -n1 )"
add_detail "firewall" "ufw status" "$ufw_state"
if grep -qi "inactive" <<< "$ufw_state"; then
  note_ok "firewall" "UFW" "UFW inactivo"
else
  note_warn "firewall" "UFW" "UFW activo; revisar reglas"
fi
iptables_list="$(run_cmd_out iptables -S || true)"
add_detail "firewall" "iptables -S" "$iptables_list"

#######################
# 4) DNS / PUERTO 53
#######################
progress INFO "Verificando DNS y conflictos en 53..."
if systemctl list-unit-files | grep -q 'pihole-FTL.service'; then
  pihole_state="$(systemctl is-active pihole-FTL || true)"
  add_detail "pihole" "systemctl is-active pihole-FTL" "$pihole_state"
  [ "$pihole_state" = "active" ] && note_ok "pihole" "Servicio" "pihole-FTL activo" || note_fail "pihole" "Servicio" "pihole-FTL no activo"
else
  note_warn "pihole" "Servicio" "No se encontró unidad pihole-FTL (instalación no estándar o no hay Pi-hole)."
fi

ss53="$(ss -lpun 'sport = :53' 2>/dev/null || true)"
add_detail "dns" "ss -lpun :53" "$ss53"
if grep -q ":53" <<< "$ss53"; then
  proc53="$(echo "$ss53" | awk 'NR>1 {print $NF}' | sort -u)"
  note_ok "dns" "Puerto 53" "53 en escucha por: ${proc53}"
else
  note_fail "dns" "Puerto 53" "Nadie está escuchando en 53"
fi

if systemctl is-active systemd-resolved >/dev/null 2>&1; then
  add_detail "dns" "systemd-resolved" "activo"
  note_warn "dns" "systemd-resolved" "systemd-resolved activo: puede competir con Pi-hole o con resolv.conf"
else
  add_detail "dns" "systemd-resolved" "inactivo"
fi

if [ -f /etc/resolv.conf ]; then
  resolv="$(cat /etc/resolv.conf)"
  add_detail "dns" "/etc/resolv.conf" "$resolv"
  ns_count="$(grep -c '^nameserver ' /etc/resolv.conf || true)"
  if [ "${ns_count:-0}" -gt 3 ]; then
    note_warn "dns" "resolv.conf" "Demasiados nameservers (${ns_count})"
  else
    note_ok "dns" "resolv.conf" "Cantidad de nameservers razonable (${ns_count})"
  fi
else
  note_fail "dns" "resolv.conf" "No existe /etc/resolv.conf"
fi

# pruebas dig contra los que tengamos
test_domains=("google.com" "cloudflare.com")
dns_targets=()
# siempre probá contra loopback
dns_targets+=("127.0.0.1")
# si el server IP estaba definido, probalo
[ -n "${SERVER_IP:-}" ] && dns_targets+=("${SERVER_IP}")
# si el server2 estaba definido, probalo
[ -n "${SERVER2_IP:-}" ] && dns_targets+=("${SERVER2_IP}")

for d in "${test_domains[@]}"; do
  for srv in "${dns_targets[@]}"; do
    out_udp="$(dig @"$srv" "$d" +time=2 +tries=1 2>&1 || true)"
    add_detail "dns" "dig_udp_${srv}_${d}" "$out_udp"
    if grep -qi "status: NOERROR" <<< "$out_udp"; then
      note_ok "dns" "dig @$srv $d (UDP)" "OK"
    else
      note_warn "dns" "dig @$srv $d (UDP)" "Falla o timeout"
    fi
  done
done

#######################
# 5) CONECTIVIDAD
#######################
progress INFO "Probando conectividad..."

ping_host() {
  local label="$1" ip="$2"
  if ping -c1 -W1 "$ip" >/dev/null 2>&1; then
    note_ok "conectividad" "ping ${label} (${ip})" "OK"
  else
    note_warn "conectividad" "ping ${label} (${ip})" "Falla"
  fi
}

if [ -n "${GATEWAY_IP:-}" ]; then
  ping_host "gateway" "$GATEWAY_IP"
fi

if [ -n "${SERVER2_IP:-}" ]; then
  ping_host "servidor_remoto" "$SERVER2_IP"
fi

if [ "$CHECK_INTERNET" = "yes" ]; then
  if ping -c1 -W1 8.8.8.8 >/dev/null 2>&1; then
    note_ok "conectividad" "Internet (8.8.8.8)" "OK"
  else
    note_warn "conectividad" "Internet (8.8.8.8)" "Falla"
  fi
fi

#######################
# 6) ZEROTIER
#######################
progress INFO "Verificando Zerotier (si aplica)..."
if systemctl list-unit-files | grep -q 'zerotier-one.service'; then
  zt_state="$(systemctl is-active zerotier-one || true)"
  add_detail "zerotier" "systemctl is-active zerotier-one" "$zt_state"
  if [ "$zt_state" = "active" ]; then
    note_ok "zerotier" "Servicio" "zerotier-one activo"
    if [ "$CHECK_ZT" = "yes" ] && command -v zerotier-cli >/dev/null 2>&1; then
      zt_status="$(zerotier-cli status 2>&1 || true)"
      add_detail "zerotier" "zerotier-cli status" "$zt_status"
      zt_nets="$(zerotier-cli listnetworks 2>&1 || true)"
      add_detail "zerotier" "zerotier-cli listnetworks" "$zt_nets"
      if [ -n "${ZT_NET_ID:-}" ]; then
        if grep -q "$ZT_NET_ID" <<< "$zt_nets"; then
          note_ok "zerotier" "Red" "Conectado a ${ZT_NET_ID}"
        else
          note_warn "zerotier" "Red" "NO se ve la red ${ZT_NET_ID}"
        fi
      fi
    fi
  else
    note_warn "zerotier" "Servicio" "zerotier-one no activo"
  fi
else
  note_warn "zerotier" "Servicio" "No se encontró zerotier-one.service"
fi

#######################
# 7) NGINX
#######################
progress INFO "Verificando Nginx..."
if systemctl list-unit-files | grep -q 'nginx.service'; then
  ng_state="$(systemctl is-active nginx || true)"
  add_detail "nginx" "systemctl is-active nginx" "$ng_state"
  [ "$ng_state" = "active" ] && note_ok "nginx" "Servicio" "nginx activo" || note_warn "nginx" "Servicio" "nginx no activo"
fi
ss_web="$(ss -lnt 'sport = :80 or sport = :443' 2>/dev/null || true)"
add_detail "nginx" "ss -lnt (:80/:443)" "$ss_web"

#######################
# 8) DOCKER
#######################
progress INFO "Verificando Docker y posibles conflictos..."
if command -v docker >/dev/null 2>&1; then
  dps="$(docker ps --format '{{.Names}} {{.Ports}}' || true)"
  add_detail "docker" "docker ps" "$dps"
  if grep -E '(:53->|:53/udp|:53/tcp)' <<< "$dps" >/dev/null 2>&1; then
    note_warn "docker" "Puerto 53" "Algún contenedor está exponiendo 53 -> posible conflicto DNS"
  else
    note_ok "docker" "Puerto 53" "Ningún contenedor parece publicar 53"
  fi
else
  note_warn "docker" "Estado" "Docker no instalado o no disponible"
fi

#######################
# 9) /etc/hosts
#######################
progress INFO "Revisando /etc/hosts..."
if [ -f /etc/hosts ]; then
  hosts_content="$(cat /etc/hosts)"
  add_detail "sistema" "/etc/hosts" "$hosts_content"
  if ! grep -q "$SERVER_NAME" <<< "$hosts_content"; then
    note_warn "sistema" "/etc/hosts" "No hay entrada para el hostname local; se usará DNS"
  else
    note_ok "sistema" "/etc/hosts" "Hostname presente en /etc/hosts"
  fi
else
  note_warn "sistema" "/etc/hosts" "No existe /etc/hosts"
fi

#######################
# 10) LOGS
#######################
progress INFO "Extrayendo logs de las últimas ${LOG_WINDOW_HOURS}h..."
collect_logs() {
  local hours="$1"
  journalctl --since "${hours} hours ago" -o short-iso 2>/dev/null | \
    grep -Ei 'error|fail|dns|pihole|dnsmasq|zerotier|nginx|link is (down|up)|port 53|network'
}
logs_main="$(collect_logs "${LOG_WINDOW_HOURS}")"
if [ -n "$logs_main" ]; then
  add_detail "logs" "eventos_${LOG_WINDOW_HOURS}h" "$logs_main"
  note_ok "logs" "Revisión ${LOG_WINDOW_HOURS}h" "Se encontraron eventos; revisar detalle CSV"
else
  note_ok "logs" "Revisión" "Sin eventos relevantes en ${LOG_WINDOW_HOURS}h"
fi

#######################
# 11) EMAIL (OPCIONAL)
#######################
if [ -n "${EMAIL_TO:-}" ]; then
  progress INFO "Enviando reporte por mail a ${EMAIL_TO}..."
  BOUNDARY="====AUDIT_BOUNDARY_${TS}===="
  SUBJECT="[AUDITORIA RED] ${SERVER_NAME} ${TS}"
  {
  echo "From: ${EMAIL_FROM}"
  echo "To: ${EMAIL_TO}"
  echo "Subject: ${SUBJECT}"
  echo "MIME-Version: 1.0"
  echo "Content-Type: multipart/mixed; boundary=\"${BOUNDARY}\""
  echo
  echo "--${BOUNDARY}"
  echo "Content-Type: text/plain; charset=UTF-8"
  echo
  echo "Adjunto resultados de auditoría de red (${SERVER_NAME})."
  echo "Directorio local: ${OUTDIR}"
  echo
  echo "--${BOUNDARY}"
  echo "Content-Type: text/csv; name=\"$(basename "$SUMMARY_CSV")\""
  echo "Content-Transfer-Encoding: base64"
  echo "Content-Disposition: attachment; filename=\"$(basename "$SUMMARY_CSV")\""
  base64 "$SUMMARY_CSV"
  echo
  echo "--${BOUNDARY}"
  echo "Content-Type: text/csv; name=\"$(basename "$DETAIL_CSV")\""
  echo "Content-Transfer-Encoding: base64"
  echo "Content-Disposition: attachment; filename=\"$(basename "$DETAIL_CSV")\""
  base64 "$DETAIL_CSV"
  echo
  echo "--${BOUNDARY}--"
  } | sendmail -t || progress WARN "No se pudo enviar mail (sendmail falló). Ver log."
else
  progress WARN "No se envía mail porque no se ingresó dirección de destino."
fi

progress OK "Auditoría terminada. Resultados en: ${OUTDIR}"
exit 0
