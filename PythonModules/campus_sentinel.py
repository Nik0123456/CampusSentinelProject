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
from threading import Lock, Thread
import time
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

# Modo Híbrido: True = Proactivo + Reactivo | False = Solo Reactivo
HYBRID_MODE = False  # Cambia a False para desactivar carga proactiva

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

def cleanup_expired_sessions():
    """Limpia automáticamente sesiones expiradas y sus flows
    
    Ejecuta cada 5 minutos para:
    1. Identificar sesiones expiradas
    2. Eliminar flows de Tabla 1, 2 y 3
    3. Desactivar sesión en DB
    4. Eliminar usuarios invitados completamente
    """
    while True:
        try:
            time.sleep(300)  # 5 minutos
            
            conn = get_db()
            cur = conn.cursor(dictionary=True)
            
            # Buscar sesiones expiradas
            cur.execute("""
                SELECT id, username, current_ip, current_mac, current_dpid, 
                       current_in_port, is_guest, flow_name
                FROM User
                WHERE session_active = 1 
                  AND session_expiry < NOW()
            """)
            
            expired_users = cur.fetchall()
            
            if expired_users:
                logging.info(f"⏰ Limpieza automática: {len(expired_users)} sesiones expiradas")
                
                for user in expired_users:
                    # Eliminar TODOS los flows del usuario
                    deleted_count = delete_user_flows(user['current_ip'], user['username'])
                    
                    # Registrar evento
                    log_event('SESSION_EXPIRED', user['username'], 
                             user['current_ip'], user['current_mac'],
                             user['current_dpid'], user['current_in_port'],
                             extra=f"Guest={user['is_guest']} Flows={deleted_count}")
                    
                    if user['is_guest']:
                        # Invitado: eliminar completamente
                        cur.execute("DELETE FROM User_has_AttributeValue WHERE user_id=%s", (user['idUser'],))
                        cur.execute("DELETE FROM User_Permission_Usage WHERE user_id=%s", (user['idUser'],))
                        cur.execute("DELETE FROM User WHERE idUser=%s", (user['idUser'],))
                        logging.info(f"  ✓ Invitado eliminado: {user['username']}")
                    else:
                        # Usuario regular: desactivar sesión
                        cur.execute("""
                            UPDATE User 
                            SET session_active=0, session_token=NULL, flow_name=NULL
                            WHERE idUser=%s
                        """, (user['idUser'],))
                        logging.info(f"  ✓ Sesión desactivada: {user['username']}")
                
                conn.commit()
            
            cur.close()
            conn.close()
            
        except Exception as e:
            logging.error(f"✗ Error en limpieza automática: {e}")

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
        "instruction_goto_table": "2"  # Pasar a Table 2 (Permisos)
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

def install_server_auth_flow(service_dpid, service_port_hw, service_ip, service_mac, service_port, protocol):
    """Instala flow de autenticación GRANULAR para servicio en Tabla 1 (anti-spoofing)
    
    Valida que el tráfico de retorno sea de un SERVICIO AUTORIZADO específico (IP+Puerto+Protocolo)
    antes de ir a Tabla 3. Solo tráfico de servicios con permisos activos puede salir del servidor.
    
    Args:
        service_dpid: DPID del switch del servidor
        service_port_hw: Puerto físico donde está conectado el servidor
        service_ip: IP del servidor
        service_mac: MAC del servidor
        service_port: Puerto del SERVICIO (21, 8080, 22, etc.)
        protocol: Protocolo ('TCP' o 'UDP')
    
    Returns:
        Nombre del flow instalado o None si falla
    """
    # Determinar protocolo IP
    ip_proto = 6 if protocol.upper() == 'TCP' else 17
    
    # Nombre único por servicio (IP + Puerto + Protocolo)
    flow_name = f"auth_srv_{service_ip.replace('.', '_')}_{protocol.lower()}{service_port}_{service_dpid[-4:]}"
    
    flow = {
        "switch": service_dpid,
        "name": flow_name,
        "priority": str(FLOW_PRIORITY),
        "active": "true",
        "eth_type": "0x0800",
        "ipv4_src": service_ip,       # Match: IP del servidor
        "ip_proto": str(ip_proto),    # Match: Protocolo (TCP=6, UDP=17)
        "in_port": str(service_port_hw),  # Match: Puerto físico del servidor
        "eth_src": service_mac,       # Match: MAC del servidor
        "table": "1",
        "idle_timeout": str(SESSION_HOURS * 3600),
        "instruction_goto_table": "3"     # → Tabla 3 (Forwarding)
    }
    
    # Agregar match de puerto origen según protocolo
    if protocol.upper() == 'TCP':
        flow["tcp_src"] = str(service_port)  # Match: tráfico desde puerto TCP del servicio
    else:
        flow["udp_src"] = str(service_port)  # Match: tráfico desde puerto UDP del servicio
    
    try:
        r = requests.post(FLOODLIGHT_URL, json=flow, timeout=5)
        if r.status_code == 200:
            logging.debug(f"✓ Flow servicio instalado en Tabla 1: {flow_name} ({service_ip}:{service_port}/{protocol})")
            return flow_name
        else:
            logging.error(f"✗ Floodlight respondió con código {r.status_code}: {r.text}")
    except Exception as e:
        logging.error(f"✗ Error instalando flow servicio: {e}")
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

def delete_user_flows(user_ip, username):
    """Elimina TODOS los flows de un usuario:
    - Tabla 1: Flow de autenticación del usuario (1 flow) + Flows de autenticación de servidores (N flows)
    - Tabla 2: Flows de permisos granulares (N flows, primer hop)
    - Tabla 3: Flows de forwarding (M flows, intermedios + finales)
    
    Estrategia: Obtener lista completa de flows de Floodlight y filtrar por IP del usuario
    """
    try:
        # Obtener todos los flows de todos los switches
        list_url = FLOODLIGHT_URL.replace('/json', '/list/all/json')
        response = requests.get(list_url, timeout=5)
        
        if response.status_code != 200:
            logging.error(f"✗ Error obteniendo lista de flows: {response.status_code}")
            return 0
        
        all_flows = response.json()
        user_ip_clean = user_ip.replace('.', '_')
        deleted_count = 0
        
        # Recorrer todos los switches
        for dpid, flows_dict in all_flows.items():
            if not isinstance(flows_dict, dict):
                continue
                
            for flow_name, flow_data in flows_dict.items():
                # Filtrar flows que pertenecen al usuario:
                # 1. Flows proactivos/reactivos con la IP del usuario en el nombre
                # 2. Flows de autenticación (auth_)
                if (user_ip_clean in flow_name or 
                    (f"auth_" in flow_name and isinstance(flow_data, dict))):
                    
                    # Verificar que realmente pertenece al usuario (match por ipv4_src o ipv4_dst)
                    if isinstance(flow_data, dict):
                        match_src = flow_data.get('match', {}).get('ipv4_src', '')
                        match_dst = flow_data.get('match', {}).get('ipv4_dst', '')
                        
                        if user_ip in match_src or user_ip in match_dst or f"auth_" in flow_name:
                            delete_flow(flow_name, dpid)
                            deleted_count += 1
                    else:
                        # Si no podemos verificar el match, pero el nombre contiene la IP, eliminar
                        if user_ip_clean in flow_name:
                            delete_flow(flow_name, dpid)
                            deleted_count += 1
        
        logging.info(f"✓ Limpieza completa: {deleted_count} flows eliminados para {username} ({user_ip})")
        return deleted_count
        
    except Exception as e:
        logging.error(f"✗ Error en delete_user_flows: {e}")
        return 0

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
            SELECT p.id, p.serviceName, p.serviceIP, p.serviceMAC, p.serviceDPID, p.serviceInPort,
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
    """Instala flows bidireccionales para un permiso específico siguiendo el pipeline OpenFlow
    
    NOTA: user_port debe ser entero antes de llamar a esta función
    
    PIPELINE:
    - Tabla 2 (Permisos): Solo en switch inicial - match granular (src+dst+port)
    - Tabla 3 (Forwarding): Switches intermedios y finales - match solo dst_ip
    - pop_vlan: Solo en el último hop antes de entregar al destino
    
    Args:
        user_ip: IP del usuario
        user_dpid: DPID del switch del usuario
        user_port: Puerto del switch del usuario
        permission: Dict con datos del permiso (serviceIP, servicePort, serviceProtocol, serviceDPID, serviceInPort, serviceMAC)
        flow_prefix: Prefijo para el nombre del flow
        
    Returns:
        Lista de nombres de flows instalados, o [] si falla
    """
    try:
        service_ip = permission['serviceIP']
        service_port = int(permission['servicePort'])
        protocol = permission['serviceProtocol'].upper()
        service_name = permission['serviceName'].replace(' ', '_')
        
        # Obtener datos del servicio desde la BD (ya no se usa get_attachment_points)
        service_dpid = permission.get('serviceDPID')
        service_port_hw = permission.get('serviceInPort') #Puerto fisico del Switch OpenFlow al que esta conectado el servidor
        service_mac = permission.get('serviceMAC', '00:00:00:00:00:00')
        
        if not service_dpid or service_port_hw is None:
            logging.error(f"Servicio {service_name} sin DPID/InPort en BD")
            return []
        
        # Convertir puerto a entero (puede venir como string de la BD)
        service_port_hw = int(service_port_hw)
        
        # Determinar protocolo IP
        ip_proto = 6 if protocol == 'TCP' else (17 if protocol == 'UDP' else None)
        if ip_proto is None:
            logging.warning(f"Protocolo desconocido: {protocol}")
            return []
        
        # Instalar flow de autenticación GRANULAR del servicio en Tabla 2
        # Valida que solo tráfico de SERVICIOS AUTORIZADOS (IP+Puerto+Protocolo) pueda salir
        server_auth_flow = install_server_auth_flow(service_dpid, service_port_hw, 
                                                     service_ip, service_mac, 
                                                     service_port, protocol)
        
        # Obtener ruta usando API de Floodlight directamente
        # API: /wm/topology/route/<src-dpid>/<src-port>/<dst-dpid>/<dst-port>/json
        route = floodlight.get_route_direct(user_dpid, user_port, service_dpid, service_port_hw)
        
        if not route:
            logging.warning(f"No se pudo obtener ruta entre {user_dpid}:{user_port} y {service_dpid}:{service_port_hw}")
            return []
        
        hops = floodlight.build_route(route)
        
        if not hops:
            logging.warning(f"No se pudo construir ruta entre {user_dpid}:{user_port} y {service_dpid}:{service_port_hw}")
            return []
        
        flow_names = []
        if server_auth_flow:
            flow_names.append(server_auth_flow)  # Agregar flow del servidor a la lista
        
        num_hops = len(hops)
        
        # ========================================
        # DIRECCIÓN: USUARIO → SERVICIO
        # ========================================
        
        for idx, hop in enumerate(hops):
            sw = hop['switch']
            in_p = hop['in_port']
            out_p = hop['out_port']
            is_first_hop = (idx == 0)
            is_last_hop = (idx == num_hops - 1)
            
            if is_first_hop:
                # ====================================
                # TABLA 2: Switch inicial (usuario)
                # Match granular: src_ip + dst_ip + dst_port + protocol
                # ====================================
                flow_u2s_name = f"{flow_prefix}_{service_name}_u2s_t2_{user_ip.replace('.', '_')}"
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
                    "idle_timeout": str(SESSION_HOURS * 3600),
                    "actions": f"output={out_p}"
                }
                
                # Agregar match de puerto destino
                if protocol == 'TCP':
                    flow_u2s["tcp_dst"] = str(service_port)
                else:
                    flow_u2s["udp_dst"] = str(service_port)
                
                if floodlight.push_flow(flow_u2s):
                    flow_names.append(flow_u2s_name)
                    logging.debug(f"  → Tabla 2 (user switch): {flow_u2s_name}")
            
            else:
                # ====================================
                # TABLA 3: Switches intermedios y final
                # Match simplificado: solo dst_ip
                # pop_vlan en el último hop
                # ====================================
                flow_u2s_name = f"{flow_prefix}_{service_name}_u2s_t3_{idx}_{service_ip.replace('.', '_')}"
                
                # Construir acciones: pop_vlan si es último hop
                actions = "pop_vlan," if is_last_hop else ""
                actions += f"output={out_p}"
                
                flow_u2s = {
                    "switch": sw,
                    "name": flow_u2s_name,
                    "table": "3",
                    "priority": "100",
                    "active": "true",
                    "eth_type": "0x0800",
                    "eth_vlan_vid": "0x1064",  # Match VLAN 100 (agregada en Tabla 0)
                    "ipv4_dst": service_ip,  # Solo match destino
                    "idle_timeout": str(SESSION_HOURS * 3600),
                    "actions": actions
                }
                
                if floodlight.push_flow(flow_u2s):
                    flow_names.append(flow_u2s_name)
                    hop_type = "final (pop_vlan)" if is_last_hop else "intermedio"
                    logging.debug(f"  → Tabla 3 ({hop_type}): {flow_u2s_name}")
        
        # ========================================
        # DIRECCIÓN: SERVICIO → USUARIO (RETORNO)
        # ========================================
        
        # Ruta inversa: recorrer hops en orden inverso
        for idx, hop in enumerate(reversed(hops)):
            sw = hop['switch']
            in_p = hop['out_port']  # Invertido: out_port se vuelve in_port
            out_p = hop['in_port']  # Invertido: in_port se vuelve out_port
            
            # En la ruta inversa:
            # - Primer hop inverso = último switch de la ruta original (servidor)
            # - Último hop inverso = primer switch de la ruta original (usuario)
            is_first_hop_reverse = (idx == 0)  # Switch del servidor
            is_last_hop_reverse = (idx == num_hops - 1)  # Switch del usuario
            
            # ====================================
            # TABLA 3: Todos los switches en dirección de retorno
            # Match: dst_ip = user_ip
            # pop_vlan en el último hop (entrega al usuario)
            # ====================================
            flow_s2u_name = f"{flow_prefix}_{service_name}_s2u_t3_{idx}_{user_ip.replace('.', '_')}"
            
            # Construir acciones: pop_vlan solo en entrega final al usuario
            actions = "pop_vlan," if is_last_hop_reverse else ""
            actions += f"output={out_p}"
            
            flow_s2u = {
                "switch": sw,
                "name": flow_s2u_name,
                "table": "3",
                "priority": "100",
                "active": "true",
                "eth_type": "0x0800",
                "eth_vlan_vid": "0x1064",  # Match VLAN 100 (agregada en Tabla 0)
                "ipv4_dst": user_ip,  # Match destino = usuario
                "idle_timeout": str(SESSION_HOURS * 3600),
                "actions": actions
            }
            
            if floodlight.push_flow(flow_s2u):
                flow_names.append(flow_s2u_name)
                hop_type = "final (pop_vlan)" if is_last_hop_reverse else ("origen" if is_first_hop_reverse else "intermedio")
                logging.debug(f"  ← Tabla 3 retorno ({hop_type}): {flow_s2u_name}")
        
        logging.info(f"✓ Instalados {len(flow_names)} flows para {service_name}: "
                    f"1 en Tabla 2, {len(flow_names)-1} en Tabla 3")
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
            INSERT INTO User_Permission_Usage (user_id, permission_id, usage_count, last_used)
            VALUES (%s, %s, 1, NOW())
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
    port = int(data['in_port'])  # Convertir a entero
    
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
        SELECT idUser, username, session_expiry, flow_name FROM User 
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
            SELECT p.id, p.serviceName, p.serviceIP, p.serviceMAC, p.serviceDPID, p.serviceInPort,
                   p.serviceProtocol, p.servicePort
            FROM Permission p
            JOIN User_has_AttributeValue uav ON p.attributevalue_id = uav.attributevalue_id
            WHERE uav.user_id = %s 
              AND p.serviceIP = %s 
              AND p.servicePort = %s
              AND p.serviceProtocol = %s
        """, (user['idUser'], dst_ip, str(dst_port), protocol.upper()))
        
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
            update_permission_usage(user['idUser'], permission['id'])
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
    cur.execute("SELECT idUser FROM User WHERE username=%s", (email,))
    user_record = cur.fetchone()
    user_id = user_record[0] if user_record else None
    
    conn.commit()
    conn.close()

    # Registrar evento en archivo de log
    log_event('LOGIN_RADIUS', email, client['ip'], client['mac'], client['dpid'], client['port'])

    # Cargar proactivamente top 10 permisos más usados (R2 - Autorización Proactiva)
    if HYBRID_MODE and user_id:
        logging.info(f"→ [MODO HÍBRIDO] Iniciando carga proactiva de permisos para {email}")
        load_proactive_permissions(user_id, client['ip'], client['dpid'], client['port'])
    elif not HYBRID_MODE:
        logging.info(f"→ [MODO REACTIVO] Omitiendo carga proactiva para {email}")

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
    cur.execute("SELECT idUser FROM User WHERE username=%s", (email,))
    user_record = cur.fetchone()
    user_id = user_record[0] if user_record else None
    
    conn.commit()
    conn.close()

    # Registrar evento en archivo de log
    log_event('GUEST_ACCESS', email, client['ip'], client['mac'], client['dpid'], client['port'])

    # Cargar permisos proactivos (R2 - Autorización Proactiva)
    if HYBRID_MODE and user_id:
        logging.info(f"→ [MODO HÍBRIDO] Iniciando carga proactiva de permisos para invitado {email}")
        load_proactive_permissions(user_id, client['ip'], client['dpid'], client['port'])
    elif not HYBRID_MODE:
        logging.info(f"→ [MODO REACTIVO] Omitiendo carga proactiva para invitado {email}")

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
        # Eliminar TODOS los flows del usuario (Tabla 1, 2 y 3)
        delete_flow(row['flow_name'], dpid=row['current_dpid'])
        deleted_count = delete_user_flows(row['current_ip'], row['username'])
        
        # Registrar evento en log
        log_event('LOGOUT', row['username'], row['current_ip'], row['current_mac'], 
                  row['current_dpid'], row['current_in_port'], 
                  extra=f"Guest={row['is_guest']} Flows={deleted_count}")
        
        if row['is_guest']:
            # Usuario invitado: eliminar completamente
            cur.execute("SELECT idUser FROM User WHERE session_token=%s", (token,))
            user_result = cur.fetchone()
            user_id = user_result['idUser'] if user_result else None
            
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
    logging.info(f"Modo: {'HÍBRIDO (Proactivo+Reactivo)' if HYBRID_MODE else 'REACTIVO'}")
    logging.info("="*60)
    
    # Iniciar thread de limpieza automática
    cleanup_thread = Thread(target=cleanup_expired_sessions, daemon=True)
    cleanup_thread.start()
    logging.info("✓ Thread de limpieza automática iniciado (cada 5 min)")
    logging.info("="*60)

    app.run(host='0.0.0.0', port=5000, threaded=True)

