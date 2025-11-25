#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
import requests
import mysql.connector
import uuid
from datetime import datetime, timedelta
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet
import logging
from threading import Lock
import json

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

# ========= CONFIGURACIÓN =========
FLOODLIGHT_URL = "http://127.0.0.1:8080/wm/staticflowpusher/json"
SESSION_HOURS = 4
VLAN_AUTH = 100
FLOW_PRIORITY = 200

# RADIUS client
radius_client = Client(server="127.0.0.1", secret=b"testing123",
                       dict=Dictionary("/home/ubuntu/Desktop/CampusSentinelProject/PythonModules/dictionary_simple"))

# Almacén temporal: IP → información de red del cliente
pending_clients = {}
pending_lock = Lock()

# DB MySQL
def get_db():
    return mysql.connector.connect(
        host="localhost", user="campus", password="SQLgrupo3?", database="DB_Permissions"
    )

def cleanup_pending_clients():
    """Elimina entradas antiguas (>60s)"""
    with pending_lock:
        now = datetime.utcnow()
        expired = [ip for ip, data in pending_clients.items()
                   if (now - data['timestamp']).seconds > 60]
        for ip in expired:
            del pending_clients[ip]

# ========= INSTALACIÓN DE FLOWS =========
def install_auth_flow(dpid, in_port, src_ip, src_mac):
    flow_name = f"auth_{src_mac.replace(':', '')}_{dpid[-4:]}"
    flow = {
        "switch": dpid,
        "name": flow_name,
        "priority": FLOW_PRIORITY,
        "active": "true",
        "eth_type": "0x0800",
        "ipv4_src": src_ip,
        "in_port": in_port,
        "eth_src": src_mac,
        "table": 1,
        "hard_timeout": SESSION_HOURS * 3600,
        #"instruction_apply_actions": "push_vlan=0x8100,set_field=eth_vlan_vid->0x1064",
        "actions": "push_vlan=0x8100,set_vlan_vid=0x0064",
        "instruction_goto_table": "2"
    }
    try:
        r = requests.post(FLOODLIGHT_URL, json=flow, timeout=5)
        if r.status_code == 200:
            logging.info(f"✓ Flow instalado: {flow_name}")
            return flow_name
        else:
            logging.error(f"✗ Floodlight respondió con código {r.status_code}: {r.text}")
    except Exception as e:
        logging.error(f"✗ Error instalando flow: {e}")
    return None

def delete_flow(flow_name, dpid):
    if not flow_name or not dpid:
        logging.warning(f"✗ delete_flow recibido sin flow_name o dpid")
        return

    url = FLOODLIGHT_URL
    data = {"name": flow_name, "switch": dpid}
    headers = {'Content-Type': 'application/json'}

    try:
        r = requests.delete(url, data=json.dumps(data), headers=headers, timeout=5)
        if r.status_code == 200:
            logging.info(f"✓ Flow eliminado: {flow_name}")
        else:
            logging.warning(f"⚠ Error eliminando flow {flow_name}: {r.status_code} {r.text}")
    except Exception as e:
        logging.error(f"✗ Error eliminando flow {flow_name}: {e}")

# ========= ENDPOINT: RECIBE PACKET-IN DE FLOODLIGHT =========
@app.route('/packetin', methods=['POST'])
def packetin():
    data = request.get_json(force=True)
    mac = data['mac']
    ip = data['ip']
    dpid = data['dpid']
    port = data['in_port']

    logging.info(f"→ PacketIn: IP={ip}, MAC={mac}, DPID={dpid}, Puerto={port}")

    cleanup_pending_clients()

    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT username, session_expiry, flow_name FROM User 
        WHERE current_mac=%s AND current_ip=%s AND session_active=1
    """, (mac, ip))
    user = cur.fetchone()
    conn.close()

    if user and user['session_expiry'] and user['session_expiry'] > datetime.utcnow():
        logging.info(f"✓ Cliente ya autenticado: {user['username']}")
        return jsonify({
            "status": "authenticated",
            "user": user['username']
        })

    with pending_lock:
        pending_clients[ip] = {
            'mac': mac,
            'ip': ip,
            'dpid': dpid,
            'port': port,
            'timestamp': datetime.utcnow()
        }

    logging.info(f"⏳ Cliente pendiente de autenticación: {ip}")
    return jsonify({
        "status": "need_auth",
        "client": {
            "mac": mac,
            "ip": ip,
            "dpid": dpid,
            "port": port
        }
    })

# ========= ENDPOINT: OBTENER INFO DEL CLIENTE =========
@app.route('/api/client_info', methods=['GET'])
def client_info():
    client_ip = request.remote_addr
    logging.info(f"← Solicitud de info desde: {client_ip}")
    cleanup_pending_clients()

    with pending_lock:
        client_data = pending_clients.get(client_ip)

    if client_data:
        logging.info(f"✓ Info encontrada en memoria para {client_ip}")
        return jsonify({
            "success": True,
            "client": {
                "mac": client_data['mac'],
                "ip": client_data['ip'],
                "dpid": client_data['dpid'],
                "port": client_data['port']
            }
        })

    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT current_mac as mac, current_ip as ip,
               current_dpid as dpid, current_in_port as port
        FROM User 
        WHERE current_ip=%s
        ORDER BY session_expiry DESC LIMIT 1
    """, (client_ip,))
    user_data = cur.fetchone()
    conn.close()

    if user_data:
        logging.info(f"✓ Info encontrada en DB para {client_ip}")
        return jsonify({
            "success": True,
            "client": {
                "mac": user_data['mac'],
                "ip": user_data['ip'],
                "dpid": user_data['dpid'],
                "port": user_data['port']
            }
        })

    logging.warning(f"✗ No hay información disponible para {client_ip}")
    return jsonify({
        "error": "No se encontró información de red. Intenta navegar primero."
    }), 404

# ========= LOGIN via RADIUS =========
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data['email'].lower()
    password = data['password']
    client = data['client']

    logging.info(f"← Login: {email} desde {client['ip']}")

    try:
        req = radius_client.CreateAuthPacket(code=pyrad.packet.AccessRequest)
        req["User-Name"] = email
        req["NAS-Identifier"] = "campus-sentinel"
        req["User-Password"] = req.PwCrypt(password)
        reply = radius_client.SendPacket(req)
    except Exception as e:
        logging.error(f"✗ Error RADIUS: {e}")
        return jsonify({"error": "Error de autenticación RADIUS"}), 500

    if reply.code != pyrad.packet.AccessAccept:
        logging.warning(f"✗ Login fallido: {email} - RADIUS code {reply.code}")
        return jsonify({"error": "Credenciales inválidas"}), 401

    token = str(uuid.uuid4())
    expiry = datetime.utcnow() + timedelta(hours=SESSION_HOURS)

    flow_name = install_auth_flow(client['dpid'], client['port'], client['ip'], client['mac'])
    if not flow_name:
        logging.error(f"✗ No se pudo instalar flow para {email}")
        return jsonify({"error": "Error instalando flow en el switch"}), 500

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE User SET 
        session_active=1, session_token=%s, session_expiry=%s,
        current_ip=%s, current_mac=%s, current_dpid=%s, current_in_port=%s,
        flow_name=%s
        WHERE username=%s
    """, (token, expiry, client['ip'], client['mac'], client['dpid'],
          client['port'], flow_name, email))

    if cur.rowcount == 0:
        logging.warning(f"⚠ Usuario {email} no existe en DB, creando...")
        cur.execute("""
            INSERT INTO User (username, session_active, session_token, session_expiry,
            current_ip, current_mac, current_dpid, current_in_port, flow_name)
            VALUES (%s, 1, %s, %s, %s, %s, %s, %s, %s)
        """, (email, token, expiry, client['ip'], client['mac'], client['dpid'],
              client['port'], flow_name))

    conn.commit()
    conn.close()

    with pending_lock:
        pending_clients.pop(client['ip'], None)

    logging.info(f"✓ Login exitoso: {email}")
    return jsonify({
        "success": True,
        "token": token,
        "expires_in": SESSION_HOURS * 3600,
        "user": email
    })

# ========= GUEST =========
@app.route('/api/guest', methods=['POST'])
def guest():
    data = request.json
    email = data['email'].lower()
    client = data['client']

    logging.info(f"← Invitado: {email} desde {client['ip']}")

    token = str(uuid.uuid4())
    expiry = datetime.utcnow() + timedelta(hours=SESSION_HOURS)

    flow_name = install_auth_flow(client['dpid'], client['port'], client['ip'], client['mac'])
    if not flow_name:
        logging.error(f"✗ No se pudo instalar flow para invitado {email}")
        return jsonify({"error": "Error instalando flow"}), 500

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO User (username, session_active, session_token, session_expiry,
        current_ip, current_mac, current_dpid, current_in_port, flow_name, is_guest)
        VALUES (%s, 1, %s, %s, %s, %s, %s, %s, %s, 1)
        ON DUPLICATE KEY UPDATE 
        session_active=1, session_token=VALUES(session_token), 
        session_expiry=VALUES(session_expiry),
        current_ip=VALUES(current_ip), current_mac=VALUES(current_mac), 
        current_dpid=VALUES(current_dpid), current_in_port=VALUES(current_in_port),
        flow_name=VALUES(flow_name), is_guest=1
    """, (email, token, expiry, client['ip'], client['mac'], client['dpid'],
          client['port'], flow_name))
    conn.commit()
    conn.close()

    with pending_lock:
        pending_clients.pop(client['ip'], None)

    logging.info(f"✓ Invitado registrado: {email}")
    return jsonify({
        "success": True,
        "token": token,
        "expires_in": SESSION_HOURS * 3600
    })

# ========= LOGOUT =========
@app.route('/api/logout', methods=['POST'])
def logout():
    token = request.json.get('token')

    conn = get_db()
    cur = conn.cursor(dictionary=True)
    # Ahora traemos flow_name y current_dpid
    cur.execute("""
        SELECT flow_name, current_dpid, username 
        FROM User 
        WHERE session_token=%s
    """, (token,))
    row = cur.fetchone()

    if row:
        delete_flow(row['flow_name'], dpid=row['current_dpid'])
        logging.info(f"✓ Logout: {row['username']}")
    else:
        logging.warning(f"⚠ Token no encontrado: {token}")

    cur.execute("""
        UPDATE User SET session_active=0, session_token=NULL, flow_name=NULL 
        WHERE session_token=%s
    """, (token,))
    conn.commit()
    conn.close()

    return jsonify({"success": True})

# ========= STATUS =========
@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        "status": "online",
        "pending_clients": len(pending_clients),
        "timestamp": datetime.utcnow().isoformat()
    })

if __name__ == '__main__':
    logging.info("="*60)
    logging.info("    CAMPUS SENTINEL - Servidor de Autenticación SDN")
    logging.info("="*60)
    logging.info(f"Floodlight: {FLOODLIGHT_URL}")
    logging.info(f"VLAN autenticada: {VLAN_AUTH}")
    logging.info(f"Duración de sesión: {SESSION_HOURS} horas")
    logging.info("="*60)

    app.run(host='0.0.0.0', port=5000, threaded=True)

