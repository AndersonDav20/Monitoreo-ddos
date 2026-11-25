#!/bin/sh
# Descarga el ruleset abierto de Emerging Threats (tal como quedo descrito en
# el Marco metodologico del documento) y agrega dos reglas propias para que
# el escaneo de puertos (nmap) y la denegacion de servicio (hping3) del
# laboratorio generen una alerta clara, sin depender solo de firmas genericas.
set -e

mkdir -p /var/lib/suricata/rules /var/lib/suricata/update

# suricata-update viene incluido en la imagen jasonish/suricata
if command -v suricata-update >/dev/null 2>&1; then
  suricata-update --no-test \
    --data-dir /var/lib/suricata/update \
    --output /var/lib/suricata/rules \
    || echo "[update-rules] suricata-update fallo (sin internet?); se sigue con las reglas locales"
fi

LOCAL_RULES=/var/lib/suricata/rules/local.rules
cat > "$LOCAL_RULES" <<'EOF'
# Reglas propias del laboratorio (ademas de las de Emerging Threats)

# Escaneo de puertos: muchos intentos de conexion TCP distintos desde el
# mismo origen hacia puertos del objetivo distintos del servicio (80) en poco
# tiempo (patron tipico de nmap). Se excluye el 80 para que un flood contra el
# servicio no se clasifique como escaneo.
alert tcp any any -> $HOME_NET !80 (msg:"LAB Escaneo de puertos detectado (posible nmap)"; flags:S; threshold: type both, track by_src, count 15, seconds 5; classtype:attempted-recon; sid:9000001; rev:2;)

# Denegacion de servicio: volumen alto de paquetes TCP SYN hacia el mismo
# destino Y al mismo puerto (80) en poco tiempo (patron tipico de hping3 --flood).
# Se fija el puerto para no confundir un escaneo (1 SYN por puerto) con un DoS.
# "type both": una sola alerta por ventana de 5 s, no una cada N paquetes.
alert tcp any any -> $HOME_NET 80 (msg:"LAB Posible ataque de denegacion de servicio (SYN flood)"; flags:S; threshold: type both, track by_dst, count 500, seconds 5; classtype:attempted-dos; sid:9000002; rev:2;)

# Denegacion de servicio por ICMP (hping3 --icmp --flood)
alert icmp any any -> $HOME_NET any (msg:"LAB Posible ataque de denegacion de servicio (ICMP flood)"; itype:8; threshold: type both, track by_dst, count 100, seconds 5; classtype:attempted-dos; sid:9000003; rev:2;)
EOF

# Aseguramos que suricata.rules (la salida de suricata-update, si corrio bien)
# incluya tambien nuestras reglas locales.
if [ -f /var/lib/suricata/rules/suricata.rules ]; then
  cat "$LOCAL_RULES" >> /var/lib/suricata/rules/suricata.rules
else
  cp "$LOCAL_RULES" /var/lib/suricata/rules/suricata.rules
fi

echo "[update-rules] reglas listas en /var/lib/suricata/rules/suricata.rules"
