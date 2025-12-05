#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ddos_auto_mitigation.py
Sistema automático de detección y mitigación de ataques DDoS
"""

import requests
import time
import ipaddress
from datetime import datetime
import json

SFLOWRT_URL = "http://127.0.0.1:8008"
FLOODLIGHT_URL = "http://127.0.0.1:8080"

# Umbrales de detección
THRESHOLDS = {
    'frames_per_sec': 50000,      # Paquetes por segundo
    'mbps': 100,                  # Megabits por segundo
    'bytes_per_sec': 12_500_000,  # Bytes por segundo (100 Mbps)
}

# Configuración de mitigación
MITIGATION_CONFIG = {
    'priority': 600,              # Prioridad de flows de bloqueo
    'table_id': 0,                # Tabla OpenFlow
    'hard_timeout': 300,          # 5 minutos (300 segundos)
    'block_all_destinations': False,  # False = solo bloquear víctima específica
                                      # True = bloquear todo tráfico del atacante
}

# Redes
INTERNAL_NETWORK = ipaddress.ip_network('10.0.0.0/24')
CAMPUS_NETWORK = ipaddress. ip_network('10.0.0.0/16')

# Control de mitigaciones activas
active_mitigations = {}  # {switch_dpid: {src_ip: {dst_ip: timestamp}}}


def print_banner():
    """Banner inicial con configuración"""
    print("="*100)
    print("  🛡️  CAMPUS SENTINEL - Sistema de Mitigación Automática DDoS")
    print("="*100)
    print()
    print("📊 MÉTRICAS Y UMBRALES DE DETECCIÓN:")
    print("─"*100)
    print(f"  • Paquetes por segundo (PPS):     {THRESHOLDS['frames_per_sec']:>10,} pps")
    print(f"  • Ancho de banda (Bandwidth):     {THRESHOLDS['mbps']:>10} Mbps")
    print(f"  • Bytes por segundo:              {THRESHOLDS['bytes_per_sec']:>10,} bytes/s")
    print()
    print("⚙️  CONFIGURACIÓN DE MITIGACIÓN:")
    print("─"*100)
    print(f"  • Prioridad de flows:             {MITIGATION_CONFIG['priority']}")
    print(f"  • Tabla OpenFlow:                 {MITIGATION_CONFIG['table_id']}")
    print(f"  • Hard timeout:                   {MITIGATION_CONFIG['hard_timeout']} segundos ({MITIGATION_CONFIG['hard_timeout']//60} minutos)")
    
    if MITIGATION_CONFIG['block_all_destinations']:
        print(f"  • Alcance de bloqueo:             TOTAL (todos los destinos)")
        print(f"    └─ Bloquea TODO el tráfico del atacante")
    else:
        print(f"  • Alcance de bloqueo:             ESPECÍFICO (solo víctima detectada)")
        print(f"    └─ Bloquea solo tráfico atacante → víctima")
    
    print()
    print("🌐 REDES MONITOREADAS:")
    print("─"*100)
    print(f"  • Red interna (excluida):         {INTERNAL_NETWORK}")
    print(f"  • Red campus (monitoreada):       {CAMPUS_NETWORK}")
    print(f"  • Criterio: Detectar ataques desde {CAMPUS_NETWORK} fuera de {INTERNAL_NETWORK}")
    print()
    print("🚀 Iniciando monitoreo...")
    print("="*100)
    print()


def is_external_attack(src_ip):
    """Verifica si es ataque externo"""
    try:
        ip = ipaddress.ip_address(src_ip)
        in_campus = ip in CAMPUS_NETWORK
        in_internal = ip in INTERNAL_NETWORK
        return in_campus and not in_internal
    except:
        return False


def check_sflowrt():
    """Verifica sFlow-RT"""
    try:
        r = requests.get(f"{SFLOWRT_URL}/version", timeout=2)
        if r.status_code == 200:
            return True, r.text. strip()
        return False, None
    except Exception as e:
        return False, str(e)


def get_switches_from_floodlight():
    """Obtiene lista de switches desde Floodlight"""
    try:
        r = requests.get(f"{FLOODLIGHT_URL}/wm/core/controller/switches/json", timeout=3)
        if r.status_code == 200:
            switches = {}
            for switch in r.json():
                dpid = switch. get('switchDPID', switch.get('dpid', ''))
                inetAddress = switch.get('inetAddress', '')
                ip = ''
                if '/' in inetAddress:
                    ip = inetAddress.split('/')[1]. split(':')[0]
                switches[dpid] = {'dpid': dpid, 'ip': ip}
            return switches
        return {}
    except:
        return {}


def get_active_flows(flow_name, n=30):
    """Obtiene flows activos desde sFlow-RT"""
    try:
        r = requests.get(
            f"{SFLOWRT_URL}/activeflows/ALL/{flow_name}/json",
            params={"n": n},
            timeout=3
        )
        if r.status_code == 200:
            data = r.json()
            return data if isinstance(data, list) else []
        return []
    except:
        return []


def analyze_for_attacks():
    """Analiza flows buscando ataques DDoS"""
    attacks = []
    
    # Obtener flows de frames (paquetes por segundo)
    flows_frames = get_active_flows("ddos_frames", n=50)
    
    for flow in flows_frames:
        try:
            flow_key = flow.get('key', '')
            value = float(flow.get('value', 0))
            agent = flow.get('agent', '')
            
            parts = flow_key.split(',')
            if len(parts) < 2:
                continue
            
            src_ip = parts[0]
            dst_ip = parts[1]
            
            # Verificar que es ataque externo
            if not is_external_attack(src_ip):
                continue
            
            # Verificar umbral de PPS
            if value > THRESHOLDS['frames_per_sec']:
                attacks.append({
                    'type': 'PPS_HIGH',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'switch_ip': agent,
                    'metric': 'pps',
                    'value': value,
                    'threshold': THRESHOLDS['frames_per_sec']
                })
        except:
            continue
    
    # Obtener flows de bytes (ancho de banda)
    flows_bytes = get_active_flows("ddos_bytes", n=50)
    
    for flow in flows_bytes:
        try:
            flow_key = flow. get('key', '')
            value = float(flow.get('value', 0))
            agent = flow.get('agent', '')
            
            parts = flow_key.split(',')
            if len(parts) < 2:
                continue
            
            src_ip = parts[0]
            dst_ip = parts[1]
            
            if not is_external_attack(src_ip):
                continue
            
            # Convertir a Mbps
            mbps = (value * 8) / 1_000_000
            
            # Verificar umbral de bandwidth
            if mbps > THRESHOLDS['mbps']:
                # Verificar si ya existe ataque por PPS para evitar duplicados
                exists = any(
                    a['src_ip'] == src_ip and a['dst_ip'] == dst_ip 
                    for a in attacks
                )
                
                if not exists:
                    attacks.append({
                        'type': 'BANDWIDTH_HIGH',
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'switch_ip': agent,
                        'metric': 'mbps',
                        'value': mbps,
                        'threshold': THRESHOLDS['mbps']
                    })
        except:
            continue
    
    return attacks


def install_blocking_flow(switch_dpid, src_ip, dst_ip=None):
    """Instala flow de bloqueo en el switch"""
    
    # Generar nombre único del flow
    if dst_ip and not MITIGATION_CONFIG['block_all_destinations']:
        flow_name = f"ddos_block_{src_ip}_to_{dst_ip}". replace('. ', '_')
    else:
        flow_name = f"ddos_block_{src_ip}_all".replace('.', '_')
    
    # Construir match
    flow_data = {
        "switch": switch_dpid,
        "name": flow_name,
        "priority": str(MITIGATION_CONFIG['priority']),
        "eth_type": "0x0800",  # IPv4
        "ipv4_src": src_ip,
        "active": "true",
        "table": str(MITIGATION_CONFIG['table_id']),
        "hard_timeout": str(MITIGATION_CONFIG['hard_timeout'])
    }
    
    # Agregar destino si está configurado para bloqueo específico
    if dst_ip and not MITIGATION_CONFIG['block_all_destinations']:
        flow_data["ipv4_dst"] = dst_ip
    
    # Acción: DROP (sin actions = drop implícito en Floodlight)
    # O explícitamente: flow_data["actions"] = ""
    
    try:
        r = requests.post(
            f"{FLOODLIGHT_URL}/wm/staticflowpusher/json",
            headers={"Content-Type": "application/json"},
            data=json.dumps(flow_data),
            timeout=5
        )
        
        if r.status_code == 200:
            return True, flow_name
        else:
            return False, f"Error {r.status_code}: {r.text}"
    except Exception as e:
        return False, str(e)


def is_already_mitigated(switch_dpid, src_ip, dst_ip):
    """Verifica si ya existe mitigación activa"""
    if switch_dpid not in active_mitigations:
        return False
    
    if src_ip not in active_mitigations[switch_dpid]:
        return False
    
    if MITIGATION_CONFIG['block_all_destinations']:
        # Si bloqueamos todo, verificar solo src_ip
        return True
    else:
        # Si bloqueamos específico, verificar src_ip + dst_ip
        return dst_ip in active_mitigations[switch_dpid][src_ip]


def register_mitigation(switch_dpid, src_ip, dst_ip):
    """Registra mitigación activa"""
    if switch_dpid not in active_mitigations:
        active_mitigations[switch_dpid] = {}
    
    if src_ip not in active_mitigations[switch_dpid]:
        active_mitigations[switch_dpid][src_ip] = {}
    
    active_mitigations[switch_dpid][src_ip][dst_ip] = datetime.now()


def clean_expired_mitigations():
    """Limpia mitigaciones expiradas del registro"""
    current_time = datetime.now()
    timeout = MITIGATION_CONFIG['hard_timeout']
    
    for switch_dpid in list(active_mitigations.keys()):
        for src_ip in list(active_mitigations[switch_dpid].keys()):
            for dst_ip in list(active_mitigations[switch_dpid][src_ip].keys()):
                mitigation_time = active_mitigations[switch_dpid][src_ip][dst_ip]
                elapsed = (current_time - mitigation_time).total_seconds()
                
                if elapsed > timeout:
                    del active_mitigations[switch_dpid][src_ip][dst_ip]
            
            if not active_mitigations[switch_dpid][src_ip]:
                del active_mitigations[switch_dpid][src_ip]
        
        if not active_mitigations[switch_dpid]:
            del active_mitigations[switch_dpid]


def display_attack_and_mitigate(attack, switches):
    """Muestra información del ataque e instala mitigación"""
    
    print(f"\n{'🚨'*50}")
    print(f"  ATAQUE DDoS DETECTADO Y MITIGACIÓN AUTOMÁTICA ACTIVADA")
    print(f"{'🚨'*50}")
    
    print(f"\n{'═'*100}")
    print(f"  📊 DETALLES DEL ATAQUE")
    print(f"{'═'*100}")
    print(f"  Tipo:           {attack['type']}")
    print(f"  Atacante:       {attack['src_ip']} (RED EXTERNA)")
    print(f"  Víctima:        {attack['dst_ip']}")
    print(f"  Métrica:        {attack['metric']. upper()}")
    print(f"  Valor actual:   {attack['value']:,.2f} {attack['metric']}")
    print(f"  Umbral:         {attack['threshold']:,.2f} {attack['metric']}")
    print(f"  Exceso:         {((attack['value'] / attack['threshold']) - 1) * 100:.1f}% sobre umbral")
    
    # Obtener DPID del switch
    switch_ip = attack['switch_ip']
    switch_dpid = None
    
    for dpid, info in switches.items():
        if info['ip'] == switch_ip:
            switch_dpid = dpid
            break
    
    if not switch_dpid:
        print(f"\n  ✗ ERROR: No se pudo obtener DPID del switch {switch_ip}")
        print(f"{'─'*100}\n")
        return
    
    print(f"\n  Switch:         {switch_ip}")
    print(f"  Switch DPID:    {switch_dpid}")
    
    # Verificar si ya está mitigado
    if is_already_mitigated(switch_dpid, attack['src_ip'], attack['dst_ip']):
        print(f"\n{'═'*100}")
        print(f"  ⏭️  MITIGACIÓN YA ACTIVA")
        print(f"{'═'*100}")
        print(f"  Este ataque ya tiene un flow de bloqueo instalado.")
        print(f"  No se requiere acción adicional.")
        print(f"{'─'*100}\n")
        return
    
    # Instalar flow de bloqueo
    print(f"\n{'═'*100}")
    print(f"  🛡️  INSTALANDO FLOW DE BLOQUEO")
    print(f"{'═'*100}")
    
    if MITIGATION_CONFIG['block_all_destinations']:
        print(f"  Alcance:        BLOQUEO TOTAL del atacante")
        print(f"  Match:          eth_type=0x0800, ipv4_src={attack['src_ip']}")
    else:
        print(f"  Alcance:        BLOQUEO ESPECÍFICO (solo víctima detectada)")
        print(f"  Match:          eth_type=0x0800, ipv4_src={attack['src_ip']}, ipv4_dst={attack['dst_ip']}")
    
    print(f"  Action:         DROP")
    print(f"  Prioridad:      {MITIGATION_CONFIG['priority']}")
    print(f"  Tabla:          {MITIGATION_CONFIG['table_id']}")
    print(f"  Hard timeout:   {MITIGATION_CONFIG['hard_timeout']}s ({MITIGATION_CONFIG['hard_timeout']//60} min)")
    print()
    
    dst_ip_param = attack['dst_ip'] if not MITIGATION_CONFIG['block_all_destinations'] else None
    success, result = install_blocking_flow(switch_dpid, attack['src_ip'], dst_ip_param)
    
    if success:
        print(f"  ✅ Flow instalado exitosamente: {result}")
        register_mitigation(switch_dpid, attack['src_ip'], attack['dst_ip'])
        
        print(f"\n{'═'*100}")
        print(f"  ✅ MITIGACIÓN ACTIVA")
        print(f"{'═'*100}")
        print(f"  El tráfico del atacante está siendo bloqueado.")
        print(f"  El flow se eliminará automáticamente en {MITIGATION_CONFIG['hard_timeout']//60} minutos.")
    else:
        print(f"  ✗ ERROR al instalar flow: {result}")
    
    print(f"{'─'*100}\n")


def monitor_loop(interval=5):
    """Loop principal de monitoreo"""
    print_banner()
    
    # Verificar sFlow-RT
    running, version = check_sflowrt()
    if not running:
        print("✗ sFlow-RT no responde")
        return
    
    print(f"✓ sFlow-RT: {version}")
    
    # Obtener switches
    switches = get_switches_from_floodlight()
    if not switches:
        print("✗ No se pudieron obtener switches desde Floodlight")
        return
    
    print(f"✓ Switches conectados: {len(switches)}")
    for dpid, info in switches.items():
        print(f"  - {info['ip']} ({dpid})")
    
    print()
    print("🔄 Iniciando monitoreo continuo...")
    print("="*100)
    
    iteration = 0
    
    try:
        while True:
            iteration += 1
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"\n[{timestamp}] Iteración #{iteration}")
            
            # Limpiar mitigaciones expiradas
            clean_expired_mitigations()
            
            # Analizar ataques
            attacks = analyze_for_attacks()
            
            if attacks:
                print(f"🚨 {len(attacks)} ataque(s) detectado(s)")
                
                for attack in attacks:
                    display_attack_and_mitigate(attack, switches)
            else:
                print(f"✓ No se detectaron ataques")
            
            # Mostrar mitigaciones activas
            if active_mitigations:
                total_mitigations = sum(
                    len(dsts) 
                    for switch in active_mitigations.values() 
                    for dsts in switch.values()
                )
                print(f"🛡️  Mitigaciones activas: {total_mitigations}")
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n\n" + "="*100)
        print("  🛑 Monitor detenido por el usuario")
        
        if active_mitigations:
            print()
            print("  📋 Resumen de mitigaciones activas:")
            for switch_dpid, sources in active_mitigations.items():
                for src_ip, destinations in sources.items():
                    for dst_ip in destinations.keys():
                        print(f"    • {src_ip} → {dst_ip} en switch {switch_dpid}")
        
        print("="*100)
        print()


if __name__ == '__main__':
    monitor_loop(interval=5)
