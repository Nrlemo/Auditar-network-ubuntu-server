# Auditar-network-ubuntu-server
Script dinamico interactivo para evaluar la red de servidor ubuntu.

“Si lo corrés sin sudo, algunas comprobaciones (iptables, systemd, journalctl) van a fallar.”

“Si no instalaste dnsutils (para dig), el script sigue, pero te marca WARN.”

“El envío de mail es opcional: si dejás vacío, no sale a Internet.”

Si el usuario aprieta ENTER → se omite ese test.

progreso en colores

CSV de resumen y detalle

log en /var/tmp/.../audit.log

detección de conflicto en puerto 53

chequeo de systemd-resolved

chequeos docker
logs 24h

