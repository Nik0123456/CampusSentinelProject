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
import os
from pathlib import Path

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

def log_event(event_type, username, ip, mac, dpid, port, extra=None):
    """Registra eventos de autenticación en archivo logs/YYYY-MM-DD.log"""
    try:
        logs_dir = Path(__file__).parent.parent / 'logs'
        logs_dir.mkdir(exist_ok=True)
        
        today = datetime.now().strftime('%Y-%m-%d')
        log_file = logs_dir / f'{today}.log'
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_line = f"[{timestamp}] {event_type} | User: {username} | IP: {ip} | MAC: {mac} | DPID: {dpid} | Port: {port}"
        
        if extra:
            log_line += f" | Extra: {extra}"
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_line + '\n')
        
        logging.info(f"📝 Evento registrado: {event_type} - {username}")
    except Exception as e:
        logging.error(f"✗ Error guardando log: {e}")

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
    """Instala flow de autenticación en Table 1 (anti-spoofing)
    Nota: VLAN 100 se agrega proactivamente en Table 0 por SwitchesSetup.txt
    """
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
        "actions": "goto_table:2"  # Pasar a Table 2 (Permisos)
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

# ========= MÓDULO DE AUTORIZACIÓN (R2) =========
# Importar FloodlightClient
from floodlight_client import FloodlightClient

# Inicializar cliente de Floodlight para ruteo
floodlight = FloodlightClient("http://127.0.0.1:8080")

def get_user_permissions(user_id):
    """Obtiene todos los permisos de un usuario basado en sus atributos
    
    Returns:
        Lista de dicts con información del permiso
    """
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        
        # Consulta permisos basados en los atributos del usuario
        cur.execute("""
            SELECT DISTINCT p.id, p.serviceName, p.serviceIP, p.serviceMAC,
                   p.serviceProtocol, p.servicePort
            FROM Permission p
            JOIN User_has_AttributeValue uav ON p.attributevalue_id = uav.attributevalue_id
            WHERE uav.user_id = %s
        """, (user_id,))
        
        permissions = cur.fetchall()
        cur.close()
        conn.close()
        
        return permissions
    except Exception as e:
        logging.error(f"Error obteniendo permisos: {e}")
        return []

def get_top_used_permissions(user_id, limit=10):
    """Obtiene los permisos más usados por un usuario (carga proactiva)
    
    Returns:
        Lista de dicts con información del permiso ordenados por uso
    """
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        
        cur.execute("""
            SELECT p.id, p.serviceName, p.serviceIP, p.serviceMAC,
                   p.serviceProtocol, p.servicePort, upu.usage_count
            FROM User_Permission_Usage upu
            JOIN Permission p ON upu.permission_id = p.id
            WHERE upu.user_id = %s
            ORDER BY upu.usage_count DESC, upu.last_used DESC
            LIMIT %s
        """, (user_id, limit))
        
        permissions = cur.fetchall()
        cur.close()
        conn.close()
        
        return permissions
    except Exception as e:
        logging.error(f"Error obteniendo permisos más usados: {e}")
        return []

def install_permission_flows(user_ip, user_dpid, user_port, permission, flow_prefix="perm"):
    """Instala flows bidireccionales para un permiso específico
    
    Args:
        user_ip: IP del usuario
        user_dpid: DPID del switch del usuario
        user_port: Puerto del switch del usuario
        permission: Dict con datos del permiso (serviceIP, servicePort, serviceProtocol, etc.)
        flow_prefix: Prefijo para el nombre del flow
        
    Returns:
        Lista de nombres de flows instalados, o [] si falla
    """
    try:
        service_ip = permission['serviceIP']
        service_port = int(permission['servicePort'])
        protocol = permission['serviceProtocol'].lower()
        service_name = permission['serviceName'].replace(' ', '_')
        
        # Determinar protocolo IP
        ip_proto = 6 if protocol == 'tcp' else (17 if protocol == 'udp' else None)
        if ip_proto is None:
            logging.warning(f"Protocolo desconocido: {protocol}")
            return []
        
        # Obtener puntos de conexión del servicio
        service_ap = floodlight.get_attachment_points_by_ip(service_ip, first_only=True)
        if not service_ap:
            logging.warning(f"No se encontró attachment point para servicio {service_ip}")
            return []
        
        service_dpid = service_ap['DPID']
        service_port_hw = service_ap['port']
        
        # Obtener ruta entre usuario y servicio
        route = floodlight.get_route(user_dpid, user_port, service_dpid, service_port_hw)
        hops = floodlight.build_route(route)
        
        if not hops:
            logging.warning(f"No se pudo construir ruta entre {user_dpid}:{user_port} y {service_dpid}:{service_port_hw}")
            return []
        
        flow_names = []
        
        # Instalar flows en cada hop de la ruta
        for idx, hop in enumerate(hops):
            sw = hop['switch']
            in_p = hop['in_port']
            out_p = hop['out_port']
            
            # Flow usuario → servicio
            flow_u2s_name = f"{flow_prefix}_{service_name}_u2s_{idx}_{user_ip.replace('.', '_')}"
            flow_u2s = {
                "switch": sw,
                "name": flow_u2s_name,
                "table": "2",
                "priority": "100",
                "active": "true",
                "eth_type": "0x0800",
                "ipv4_src": user_ip,
                "ipv4_dst": service_ip,
                "ip_proto": str(ip_proto),
                "in_port": str(in_p),
                "idle_timeout": str(SESSION_HOURS * 3600),
                "actions": f"output={out_p}"
            }
            
            # Agregar match de puerto destino
            if protocol == 'tcp':
                flow_u2s["tcp_dst"] = str(service_port)
            else:
                flow_u2s["udp_dst"] = str(service_port)
            
            # Flow servicio → usuario (retorno)
            flow_s2u_name = f"{flow_prefix}_{service_name}_s2u_{idx}_{user_ip.replace('.', '_')}"
            flow_s2u = {
                "switch": sw,
                "name": flow_s2u_name,
                "table": "2",
                "priority": "100",
                "active": "true",
                "eth_type": "0x0800",
                "ipv4_src": service_ip,
                "ipv4_dst": user_ip,
                "ip_proto": str(ip_proto),
                "in_port": str(out_p),
                "idle_timeout": str(SESSION_HOURS * 3600),
                "actions": f"output={in_p}"
            }
            
            # Agregar match de puerto origen
            if protocol == 'tcp':
                flow_s2u["tcp_src"] = str(service_port)
            else:
                flow_s2u["udp_src"] = str(service_port)
            
            # Instalar flows
            if floodlight.push_flow(flow_u2s):
                flow_names.append(flow_u2s_name)
            if floodlight.push_flow(flow_s2u):
                flow_names.append(flow_s2u_name)
        
        return flow_names
        
    except Exception as e:
        logging.error(f"Error instalando flows de permiso: {e}")
        return []

def load_proactive_permissions(user_id, user_ip, user_dpid, user_port):
    """Carga proactivamente los top 10 permisos más usados del usuario
    
    Se ejecuta automáticamente después del login exitoso
    """
    try:
        top_perms = get_top_used_permissions(user_id, limit=10)
        
        if not top_perms:
            logging.info(f"No hay permisos previos para user_id={user_id}, omitiendo carga proactiva")
            return
        
        logging.info(f"Cargando {len(top_perms)} permisos proactivos para user_id={user_id}")
        
        for perm in top_perms:
            flows = install_permission_flows(user_ip, user_dpid, user_port, perm, flow_prefix="proactive")
            if flows:
                logging.info(f"  ✓ Permiso proactivo instalado: {perm['serviceName']} ({len(flows)} flows)")
        
    except Exception as e:
        logging.error(f"Error en carga proactiva: {e}")

def update_permission_usage(user_id, permission_id):
    """Actualiza estadísticas de uso de un permiso
    
    Incrementa usage_count y actualiza last_used
    """
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Insertar o actualizar registro
        cur.execute("""
            INSERT INTO User_Permission_Usage (user_id, permission_id, usage_count, last_used, first_used)
            VALUES (%s, %s, 1, NOW(), NOW())
            ON DUPLICATE KEY UPDATE
                usage_count = usage_count + 1,
                last_used = NOW()
        """, (user_id, permission_id))
        
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logging.error(f"Error actualizando estadísticas de uso: {e}")

# ========= ENDPOINT: RECIBE PACKET-IN DE FLOODLIGHT =========
@app.route('/packetin', methods=['POST'])
def packetin():
    """Maneja PACKET_IN de Floodlight para:
    1. Autenticación (Tabla 0): cliente no registrado → pending_clients
    2. Autorización (Tabla 2): cliente autenticado solicita permiso → install_permission_flows
    """
    data = request.get_json(force=True)
    mac = data['mac']
    ip = data['ip']
    dpid = data['dpid']
    port = data['in_port']
    
    # Información adicional para autorización (Tabla 2)
    dst_ip = data.get('dst_ip')
    dst_port = data.get('dst_port')
    protocol = data.get('protocol')  # 'TCP' o 'UDP'

    logging.info(f"→ PacketIn: IP={ip}, MAC={mac}, DPID={dpid}, Puerto={port}, Destino={dst_ip}:{dst_port}")

    cleanup_pending_clients()

    # Verificar si el usuario ya está autenticado
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, username, session_expiry, flow_name FROM User 
        WHERE current_mac=%s AND current_ip=%s AND session_active=1
    """, (mac, ip))
    user = cur.fetchone()

    # CASO 1: Usuario autenticado → solicitud de AUTORIZACIÓN (Tabla 2)
    if user and user['session_expiry'] and user['session_expiry'] > datetime.utcnow():
        logging.info(f"✓ Usuario autenticado: {user['username']} solicita acceso a {dst_ip}:{dst_port}")
        
        # Si no hay información de destino, es confirmación de autenticación
        if not dst_ip:
            cur.close()
            conn.close()
            return jsonify({
                "status": "authenticated",
                "user": user['username']
            })
        
        # Verificar si el usuario tiene permiso para el servicio solicitado
        cur.execute("""
            SELECT p.id, p.serviceName, p.serviceIP, p.serviceMAC, p.serviceProtocol, p.servicePort
            FROM Permission p
            JOIN User_has_AttributeValue uav ON p.attributevalue_id = uav.attributevalue_id
            WHERE uav.user_id = %s 
              AND p.serviceIP = %s 
              AND p.servicePort = %s
              AND p.serviceProtocol = %s
        """, (user['id'], dst_ip, dst_port, protocol.upper() if protocol else 'TCP'))
        
        permission = cur.fetchone()
        cur.close()
        conn.close()
        
        if not permission:
            logging.warning(f"✗ PERMISO DENEGADO: {user['username']} → {dst_ip}:{dst_port}")
            log_event('PERMISSION_DENIED', user['username'], ip, mac, dpid, port, 
                     extra=f"servicio={dst_ip}:{dst_port}")
            return jsonify({
                "status": "permission_denied",
                "message": f"No tienes permiso para acceder a {dst_ip}:{dst_port}"
            }), 403
        
        # Permiso encontrado → instalar flows reactivos
        logging.info(f"✓ PERMISO AUTORIZADO: {user['username']} → {permission['serviceName']}")
        flows = install_permission_flows(ip, dpid, port, permission, flow_prefix="reactive")
        
        if flows:
            # Actualizar estadísticas de uso
            update_permission_usage(user['id'], permission['id'])
            log_event('PERMISSION_GRANTED', user['username'], ip, mac, dpid, port,
                     extra=f"servicio={permission['serviceName']} flows={len(flows)}")
            
            return jsonify({
                "status": "permission_granted",
                "service": permission['serviceName'],
                "flows_installed": len(flows)
            })
        else:
            logging.error(f"✗ Error instalando flows para permiso {permission['serviceName']}")
            return jsonify({
                "status": "error",
                "message": "Error instalando flows de permiso"
            }), 500
    
    # CASO 2: Usuario NO autenticado → solicitud de AUTENTICACIÓN (Tabla 0)
    cur.close()
    conn.close()
    
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

# ========= LOGIN via RADIUS =========
@app.route('/api/login', methods=['POST'])
def login():
    """Autenticación RADIUS para usuarios registrados
    SEGURIDAD: Lee datos de red desde pending_clients (Floodlight), no del cliente
    """
    data = request.json
    email = data['email'].lower()
    password = data['password']
    client_ip = request.remote_addr

    logging.info(f"← Login: {email} desde {client_ip}")

    # Obtener datos de red desde pending_clients (fuente confiable: Floodlight)
    with pending_lock:
        client = pending_clients.get(client_ip)
    
    if not client:
        logging.error(f"✗ No hay datos de red para {client_ip}. Cliente debe navegar primero.")
        return jsonify({"error": "No se encontró información de red. Navega a http://10.0.0.2:5000 primero."}), 400

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

    # Obtener user_id para carga proactiva
    cur.execute("SELECT id FROM User WHERE username=%s", (email,))
    user_record = cur.fetchone()
    user_id = user_record[0] if user_record else None
    
    conn.commit()
    conn.close()

    # Registrar evento en archivo de log
    log_event('LOGIN_RADIUS', email, client['ip'], client['mac'], client['dpid'], client['port'])

    # Cargar proactivamente top 10 permisos más usados (R2 - Autorización Proactiva)
    if user_id:
        logging.info(f"→ Iniciando carga proactiva de permisos para {email}")
        load_proactive_permissions(user_id, client['ip'], client['dpid'], client['port'])

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
    """Registro de usuario invitado (temporal)
    SEGURIDAD: Lee datos de red desde pending_clients (Floodlight), no del cliente
    """
    data = request.json
    email = data['email'].lower()
    client_ip = request.remote_addr

    logging.info(f"← Invitado: {email} desde {client_ip}")

    # Obtener datos de red desde pending_clients
    with pending_lock:
        client = pending_clients.get(client_ip)
    
    if not client:
        logging.error(f"✗ No hay datos de red para {client_ip}")
        return jsonify({"error": "No se encontró información de red. Navega a http://10.0.0.2:5000 primero."}), 400

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
    
    # Obtener user_id para carga proactiva (invitados también pueden tener permisos previos si se reregistran)
    cur.execute("SELECT id FROM User WHERE username=%s", (email,))
    user_record = cur.fetchone()
    user_id = user_record[0] if user_record else None
    
    conn.commit()
    conn.close()

    # Registrar evento en archivo de log
    log_event('GUEST_ACCESS', email, client['ip'], client['mac'], client['dpid'], client['port'])

    # Cargar permisos proactivos (R2 - Autorización Proactiva)
    if user_id:
        logging.info(f"→ Iniciando carga proactiva de permisos para invitado {email}")
        load_proactive_permissions(user_id, client['ip'], client['dpid'], client['port'])

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
    """Cierre de sesión
    - Usuarios regulares: desactiva sesión
    - Usuarios invitados: elimina completamente el registro
    """
    token = request.json.get('token')

    conn = get_db()
    cur = conn.cursor(dictionary=True)
    
    # Obtener datos del usuario incluyendo is_guest
    cur.execute("""
        SELECT flow_name, current_dpid, username, is_guest, 
               current_ip, current_mac, current_in_port
        FROM User 
        WHERE session_token=%s
    """, (token,))
    row = cur.fetchone()

    if row:
        # Eliminar flow del switch
        delete_flow(row['flow_name'], dpid=row['current_dpid'])
        
        # Registrar evento en log
        log_event('LOGOUT', row['username'], row['current_ip'], row['current_mac'], 
                  row['current_dpid'], row['current_in_port'], 
                  extra=f"Guest={row['is_guest']}")
        
        if row['is_guest']:
            # Usuario invitado: eliminar completamente
            user_id = cur.execute("SELECT idUser FROM User WHERE session_token=%s", (token,))
            user_id = cur.fetchone()['idUser'] if cur.rowcount else None
            
            if user_id:
                # Eliminar relaciones primero
                cur.execute("DELETE FROM User_has_AttributeValue WHERE user_id=%s", (user_id,))
                cur.execute("DELETE FROM User_Permission_Usage WHERE user_id=%s", (user_id,))
                # Eliminar usuario
                cur.execute("DELETE FROM User WHERE idUser=%s", (user_id,))
                logging.info(f"✓ Usuario invitado eliminado: {row['username']}")
        else:
            # Usuario regular: solo desactivar sesión
            cur.execute("""
                UPDATE User SET session_active=0, session_token=NULL, flow_name=NULL 
                WHERE session_token=%s
            """, (token,))
            logging.info(f"✓ Logout: {row['username']}")
    else:
        logging.warning(f"⚠ Token no encontrado: {token}")

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

