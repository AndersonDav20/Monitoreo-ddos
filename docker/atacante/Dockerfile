# Atacante del laboratorio: Kali con nmap, hping3 y curl ya instalados,
# para que la instalacion de paquetes no genere trafico (ni alertas) durante el ataque.
FROM kalilinux/kali-rolling
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends nmap hping3 curl ca-certificates iproute2 \
 && rm -rf /var/lib/apt/lists/*
