#!/bin/bash
# load_flows.sh - Registrar flows DDoS en sFlow-RT vía API REST

SFLOW_RT_HOST="localhost"
SFLOW_RT_PORT="8008"
BASE_URL="http://${SFLOW_RT_HOST}:${SFLOW_RT_PORT}"

echo "[*] Esperando a que sFlow-RT esté arriba en ${BASE_URL} ..."

# Esperar hasta que /version responda o 30s
for i in {1..30}; do
  if curl -s "${BASE_URL}/version" >/dev/null 2>&1; then
    echo "[*] sFlow-RT responde en ${BASE_URL}"
    break
  fi
  echo "   - intento $i: aún no responde, esperando 1s..."
  sleep 1
done

if ! curl -s "${BASE_URL}/version" >/dev/null 2>&1; then
  echo "[!] No se pudo contactar con sFlow-RT en ${BASE_URL} (timeout)"
  exit 1
fi

echo "[*] Registrando flows DDoS..."

# Flow 1: Tráfico por pares IP (origen → destino) en bytes
curl -s -X PUT "${BASE_URL}/flow/ddos_bytes/json" \
  -d '{
    "keys": "ipsource,ipdestination",
    "value": "bytes",
    "log": false
  }' >/dev/null

# Flow 2: Tráfico por pares IP en paquetes
curl -s -X PUT "${BASE_URL}/flow/ddos_frames/json" \
  -d '{
    "keys": "ipsource,ipdestination",
    "value": "frames",
    "log": false
  }' >/dev/null

# Flow 3: Top talkers (origen) por bytes
curl -s -X PUT "${BASE_URL}/flow/ddos_talkers/json" \
  -d '{
    "keys": "ipsource",
    "value": "bytes",
    "log": false
  }' >/dev/null

# Flow 4: Top destinations (destino) por bytes
curl -s -X PUT "${BASE_URL}/flow/ddos_destinations/json" \
  -d '{
    "keys": "ipdestination",
    "value": "bytes",
    "log": false
  }' >/dev/null

# Flow 5: Tráfico por protocolo IP
curl -s -X PUT "${BASE_URL}/flow/ddos_protocols/json" \
  -d '{
    "keys": "ipsource,ipdestination,ipprotocol",
    "value": "frames",
    "log": false
  }' >/dev/null

# Flow 6: Puertos destino más atacados (TCP)
curl -s -X PUT "${BASE_URL}/flow/ddos_ports/json" \
  -d '{
    "keys": "ipdestination,tcpdestinationport",
    "value": "frames",
    "log": false
  }' >/dev/null

echo "[*] Flows registrados. Comprobando definiciones:"

curl -s "${BASE_URL}/flow/json" | jq || curl -s "${BASE_URL}/flow/json"
