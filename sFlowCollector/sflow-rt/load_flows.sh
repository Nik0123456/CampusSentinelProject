#!/bin/bash
# load_flows_v3.sh

SFLOW_RT_URL="http://localhost:8008"

echo "[*] Esperando sFlow-RT..."

for i in {1..30}; do
  if curl -s "${SFLOW_RT_URL}/version" >/dev/null 2>&1; then
    echo "[*] ✓ sFlow-RT disponible"
    break
  fi
  sleep 1
done

echo "[*] Registrando flows optimizados..."

# Flow 1: Frames detallado (con agent e inputifindex)
curl -s -X PUT "${SFLOW_RT_URL}/flow/ddos_frames_detailed/json" \
  -H "Content-Type: application/json" \
  -d '{
    "keys": "ipsource,ipdestination,agent,inputifindex",
    "value": "frames",
    "log": false,
    "timeout": 2,
    "flowTimeout": 2
  }' >/dev/null

# Flow 2: Bytes detallado
curl -s -X PUT "${SFLOW_RT_URL}/flow/ddos_bytes_detailed/json" \
  -H "Content-Type: application/json" \
  -d '{
    "keys": "ipsource,ipdestination,agent,inputifindex",
    "value": "bytes",
    "log": false,
    "timeout": 2,
    "flowTimeout": 2
  }' >/dev/null

# Flow 3: Frames simple (compatibilidad)
curl -s -X PUT "${SFLOW_RT_URL}/flow/ddos_frames/json" \
  -H "Content-Type: application/json" \
  -d '{
    "keys": "ipsource,ipdestination",
    "value": "frames",
    "log": false
  }' >/dev/null

# Flow 4: Bytes simple
curl -s -X PUT "${SFLOW_RT_URL}/flow/ddos_bytes/json" \
  -H "Content-Type: application/json" \
  -d '{
    "keys": "ipsource,ipdestination",
    "value": "bytes",
    "log": false
  }' >/dev/null

# Flow 5: Por protocolo (diagnóstico)
curl -s -X PUT "${SFLOW_RT_URL}/flow/ddos_protocols/json" \
  -H "Content-Type: application/json" \
  -d '{
    "keys": "ipsource,ipdestination,ipprotocol",
    "value": "frames",
    "log": false
  }' >/dev/null

# Flow 6: Puertos TCP
curl -s -X PUT "${SFLOW_RT_URL}/flow/ddos_tcp_ports/json" \
  -H "Content-Type: application/json" \
  -d '{
    "keys": "ipsource,ipdestination,tcpdestinationport",
    "value": "frames",
    "log": false
  }' >/dev/null

echo "[*] ✅ Flows registrados"
echo ""
echo "Flows activos:"
curl -s "${SFLOW_RT_URL}/flow/json" | jq -r 'keys[]' 2>/dev/null || curl -s "${SFLOW_RT_URL}/flow/json"
