#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ddos_auto_mitigation_v3.py
Sistema de Mitigación DDoS Optimizado - Reacción en 2-5 segundos
"""

import requests
import time
import ipaddress
from datetime import datetime
import json
import threading
from collections import defaultdict

SFLOWRT_URL = "http://127.0.0.1:8008"
FLOODLIGHT_URL = "http://127.0.0.1:8080"

# ⚡ Configuración optimizada para baja latencia
SAMPLING_RATE = 128
CHECK_INTERVAL = 1  # ⚡ Revisar cada 1 segundo (antes 5s)

# Umbrales de detección (valores REALES)
THRESHOLDS = {
    'frames_per_sec': 50000,       # 50K pps real
    'mbps': 50,                   # 50 Mbps
    'bytes_per_sec': 6_250_000,
}

# Configuración de mitigación
MITIGATION_CONFIG = {
    'priority': 600,
    'table_id': 0,
    'hard_timeout': 300,  # 5 minutos
    'block_all_destinations': False,
}

# Redes
INTERNAL_NETWORK = ipaddress.ip_network('10.0.0.0/24')
CAMPUS_NETWORK = ipaddress. ip_network('10.0.0.0/16')

# Control de mitigaciones activas
active_mitigations = {}
mitigation_lock = threading.Lock()

# Estadísticas de rendimiento
stats = {
    'total_attacks_detected': 0,
    'total_flows_installed': 0,
    'avg_detection_time': [],
    'last_detection_time': None,
}


def print_banner():
    """Banner con configuración optimizada"""
    print("="*100)
    print("  🛡️  CAMPUS SENTINEL - Sistema de Mitigación DDoS v3. 0 OPTIMIZADO")
    print("="*100)
    print()
    print("⚡ OPTIMIZACIONES ACTIVAS:")
    print("─"*100)
    print(f"  • Intervalo de monitoreo:         {CHECK_INTERVAL}s (⚡ 5x más rápido)")
    print(f"  • sFlow polling esperado:         1s (configurar en switches)")
    print(f"  • sFlow-RT flow timeout:          2s (configurar al iniciar)")
    print(f"  • Tiempo de reacción estimado:    2-5 segundos")
    print()
    print("📊 CONFIGURACIÓN DE sFlow:")
    print("─"*100)
    print(f"  • Sampling rate:                  1:{SAMPLING_RATE}")
    print(f"  • Factor de corrección:           ×{SAMPLING_RATE}")
    print()
    print("📊 UMBRALES DE DETECCIÓN:")
    print("─"*100)
    print(f"  • PPS real:                       {THRESHOLDS['frames_per_sec']:,} pps")
    print(f"  • PPS muestreado:                 ~{THRESHOLDS['frames_per_sec']//SAMPLING_RATE} pps")
    print(f"  • Bandwidth:                      {THRESHOLDS['mbps']} Mbps")
    print()
    print("⚙️  MITIGACIÓN:")
    print("─"*100)
    print(f"  • Prioridad:                      {MITIGATION_CONFIG['priority']}")
    print(f"  • Tabla:                          {MITIGATION_CONFIG['table_id']}")
    print(f"  • Timeout:                        {MITIGATION_CONFIG['hard_timeout']}s ({MITIGATION_CONFIG['hard_timeout']//60} min)")
    print(f"  • Alcance:                        {'TOTAL' if MITIGATION_CONFIG['block_all_destinations'] else 'ESPECÍFICO'}")
    print()
    print("🌐 REDES:")
    print("─"*100)
    print(f"  • Interna (excluida):             {INTERNAL_NETWORK}")
    print(f"  • Campus (monitoreada):           {CAMPUS_NETWORK}")
    print()
    print("🚀 Iniciando...")
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
    """Obtiene switches desde Floodlight"""
    try:
        r = requests.get(f"{FLOODLIGHT_URL}/wm/core/controller/switches/json", timeout=2)
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


def get_active_flows(flow_name, n=50):
    """Obtiene flows activos (aumentado a top 50)"""
    try:
        r = requests.get(
            f"{SFLOWRT_URL}/activeflows/ALL/{flow_name}/json",
            params={"n": n},
            timeout=2  # ⚡ Timeout reducido
        )
        if r.status_code == 200:
            data = r.json()
            return data if isinstance(data, list) else []
        return []
    except:
        return []


def analyze_for_attacks():
    """Analiza flows con corrección de sampling rate"""
    attacks = []
    detection_start = time.time()
    
    # Analizar PPS
    flows_frames = get_active_flows("ddos_frames_detailed", n=50)
    
    for flow in flows_frames:
        try:
            flow_key = flow. get('key', '')
            sampled_value = float(flow.get('value', 0))
            agent = flow.get('agent', '')
            
            # ⭐ Multiplicar por sampling rate
            real_value = sampled_value * SAMPLING_RATE
            
            parts = flow_key.split(',')
            if len(parts) < 2:
                continue
            
            src_ip = parts[0]
            dst_ip = parts[1]
            
            if not is_external_attack(src_ip):
                continue
            
            if real_value > THRESHOLDS['frames_per_sec']:
                attacks.append({
                    'type': 'PPS_HIGH',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'switch_ip': agent,
                    'metric': 'pps',
                    'sampled_value': sampled_value,
                    'real_value': real_value,
                    'threshold': THRESHOLDS['frames_per_sec'],
                    'detection_time': time.time() - detection_start
                })
        except:
            continue
    
    # Analizar Bandwidth
    flows_bytes = get_active_flows("ddos_bytes_detailed", n=50)
    
    for flow in flows_bytes:
        try:
            flow_key = flow.get('key', '')
            sampled_value = float(flow.get('value', 0))
            agent = flow.get('agent', '')
            
            real_value = sampled_value * SAMPLING_RATE
            real_mbps = (real_value * 8) / 1_000_000
            
            parts = flow_key.split(',')
            if len(parts) < 2:
                continue
            
            src_ip = parts[0]
            dst_ip = parts[1]
            
            if not is_external_attack(src_ip):
                continue
            
            if real_mbps > THRESHOLDS['mbps']:
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
                        'sampled_value': sampled_value,
                        'real_value': real_mbps,
                        'threshold': THRESHOLDS['mbps'],
                        'detection_time': time.time() - detection_start
                    })
        except:
            continue
    
    return attacks


def install_blocking_flow(switch_dpid, src_ip, dst_ip=None):
    """Instala flow de bloqueo"""
    install_start = time.time()
    
    if dst_ip and not MITIGATION_CONFIG['block_all_destinations']:
        flow_name = f"ddos_block_{src_ip}_to_{dst_ip}". replace('. ', '_')
    else:
        flow_name = f"ddos_block_{src_ip}_all".replace('.', '_')
    
    flow_data = {
        "switch": switch_dpid,
        "name": flow_name,
        "priority": str(MITIGATION_CONFIG['priority']),
        "eth_type": "0x0800",
        "ipv4_src": src_ip,
        "active": "true",
        "table": str(MITIGATION_CONFIG['table_id']),
        "hard_timeout": str(MITIGATION_CONFIG['hard_timeout'])
    }
    
    if dst_ip and not MITIGATION_CONFIG['block_all_destinations']:
        flow_data["ipv4_dst"] = dst_ip
    
    try:
        r = requests.post(
            f"{FLOODLIGHT_URL}/wm/staticflowpusher/json",
            headers={"Content-Type": "application/json"},
            data=json.dumps(flow_data),
            timeout=3  # ⚡ Timeout reducido
        )
        
        install_time = time.time() - install_start
        
        if r. status_code == 200:
            return True, flow_name, install_time
        else:
            return False, f"Error {r.status_code}", install_time
    except Exception as e:
        return False, str(e), time.time() - install_start


def is_already_mitigated(switch_dpid, src_ip, dst_ip):
    """Verifica mitigación existente (thread-safe)"""
    with mitigation_lock:
        if switch_dpid not in active_mitigations:
            return False
        
        if src_ip not in active_mitigations[switch_dpid]:
            return False
        
        if MITIGATION_CONFIG['block_all_destinations']:
            return True
        else:
            return dst_ip in active_mitigations[switch_dpid][src_ip]


def register_mitigation(switch_dpid, src_ip, dst_ip):
    """Registra mitigación (thread-safe)"""
    with mitigation_lock:
        if switch_dpid not in active_mitigations:
            active_mitigations[switch_dpid] = {}
        
        if src_ip not in active_mitigations[switch_dpid]:
            active_mitigations[switch_dpid][src_ip] = {}
        
        active_mitigations[switch_dpid][src_ip][dst_ip] = datetime.now()


def clean_expired_mitigations():
    """Limpia mitigaciones expiradas"""
    with mitigation_lock:
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
    """Muestra ataque e instala mitigación con tiempos"""
    mitigation_start = time.time()
    
    print(f"\n{'🚨'*50}")
    print(f"  ⚡ ATAQUE DETECTADO - MITIGACIÓN AUTOMÁTICA")
    print(f"{'🚨'*50}")
    
    print(f"\n{'═'*100}")
    print(f"  📊 ATAQUE")
    print(f"{'═'*100}")
    print(f"  Tipo:              {attack['type']}")
    print(f"  Atacante:          {attack['src_ip']} (RED EXTERNA)")
    print(f"  Víctima:           {attack['dst_ip']}")
    print()
    print(f"  📈 VALORES:")
    print(f"     Muestreado:      {attack['sampled_value']:,.2f} {attack['metric']}")
    print(f"     Real (×{SAMPLING_RATE}):      {attack['real_value']:,.2f} {attack['metric']} ⚠️")
    print(f"     Umbral:          {attack['threshold']:,.2f} {attack['metric']}")
    print(f"     Exceso:          {((attack['real_value'] / attack['threshold']) - 1) * 100:.1f}%")
    print()
    print(f"  ⏱️  TIMING:")
    print(f"     Detección:       {attack. get('detection_time', 0)*1000:.1f}ms")
    
    switch_ip = attack['switch_ip']
    switch_dpid = None
    
    for dpid, info in switches.items():
        if info['ip'] == switch_ip:
            switch_dpid = dpid
            break
    
    if not switch_dpid:
        print(f"\n  ✗ ERROR: No se pudo obtener DPID de {switch_ip}")
        print(f"{'─'*100}\n")
        return
    
    print(f"\n  Switch:            {switch_ip}")
    print(f"  Switch DPID:       {switch_dpid}")
    
    if is_already_mitigated(switch_dpid, attack['src_ip'], attack['dst_ip']):
        print(f"\n{'═'*100}")
        print(f"  ⏭️  MITIGACIÓN YA ACTIVA")
        print(f"{'═'*100}")
        print(f"{'─'*100}\n")
        return
    
    print(f"\n{'═'*100}")
    print(f"  🛡️  INSTALANDO FLOW")
    print(f"{'═'*100}")
    
    if MITIGATION_CONFIG['block_all_destinations']:
        print(f"  Match:             ipv4_src={attack['src_ip']}")
    else:
        print(f"  Match:             ipv4_src={attack['src_ip']}, ipv4_dst={attack['dst_ip']}")
    
    print(f"  Action:            DROP")
    print(f"  Priority:          {MITIGATION_CONFIG['priority']}")
    print(f"  Timeout:           {MITIGATION_CONFIG['hard_timeout']}s")
    
    dst_ip_param = attack['dst_ip'] if not MITIGATION_CONFIG['block_all_destinations'] else None
    success, result, install_time = install_blocking_flow(switch_dpid, attack['src_ip'], dst_ip_param)
    
    total_time = time.time() - mitigation_start
    
    if success:
        print(f"\n  ✅ Flow instalado: {result}")
        print(f"  ⏱️  Tiempo instalación: {install_time*1000:.1f}ms")
        print(f"  ⏱️  Tiempo total:       {total_time*1000:.1f}ms")
        
        register_mitigation(switch_dpid, attack['src_ip'], attack['dst_ip'])
        
        # Actualizar estadísticas
        stats['total_flows_installed'] += 1
        stats['avg_detection_time']. append(total_time)
        stats['last_detection_time'] = total_time
        
        print(f"\n{'═'*100}")
        print(f"  ✅ MITIGACIÓN ACTIVA")
        print(f"{'═'*100}")
    else:
        print(f"\n  ✗ ERROR: {result}")
    
    print(f"{'─'*100}\n")


def display_stats():
    """Muestra estadísticas de rendimiento"""
    if stats['avg_detection_time']:
        avg_time = sum(stats['avg_detection_time']) / len(stats['avg_detection_time'])
        min_time = min(stats['avg_detection_time'])
        max_time = max(stats['avg_detection_time'])
        
        print(f"\n📊 ESTADÍSTICAS DE RENDIMIENTO:")
        print(f"   Ataques detectados:    {stats['total_attacks_detected']}")
        print(f"   Flows instalados:      {stats['total_flows_installed']}")
        print(f"   Tiempo promedio:       {avg_time:.2f}s")
        print(f"   Tiempo mínimo:         {min_time:.2f}s")
        print(f"   Tiempo máximo:         {max_time:.2f}s")
        if stats['last_detection_time']:
            print(f"   Última detección:      {stats['last_detection_time']:.2f}s")


def monitor_loop(interval=CHECK_INTERVAL):
    """Loop principal optimizado"""
    print_banner()
    
    running, version = check_sflowrt()
    if not running:
        print("✗ sFlow-RT no responde")
        return
    
    print(f"✓ sFlow-RT: {version}")
    
    switches = get_switches_from_floodlight()
    if not switches:
        print("✗ No se pudieron obtener switches")
        return
    
    print(f"✓ Switches: {len(switches)}")
    for dpid, info in switches.items():
        print(f"  - {info['ip']} ({dpid})")
    
    print()
    print(f"⚡ Monitoreo activo (intervalo: {interval}s)")
    print("="*100)
    
    iteration = 0
    last_stats_display = time.time()
    
    try:
        while True:
            iteration += 1
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Mostrar iteración cada 10
            if iteration % 10 == 1:
                print(f"\n[{timestamp}] Iteración #{iteration}")
            
            clean_expired_mitigations()
            attacks = analyze_for_attacks()
            
            if attacks:
                stats['total_attacks_detected'] += len(attacks)
                print(f"\n🚨 [{timestamp}] {len(attacks)} ataque(s) detectado(s)")
                
                for attack in attacks:
                    display_attack_and_mitigate(attack, switches)
            
            # Mostrar estado cada 30 segundos
            if time.time() - last_stats_display > 30:
                with mitigation_lock:
                    if active_mitigations:
                        total = sum(len(d) for s in active_mitigations.values() for d in s.values())
                        print(f"\n🛡️  [{timestamp}] Mitigaciones activas: {total}")
                
                if stats['avg_detection_time']:
                    display_stats()
                
                last_stats_display = time.time()
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n\n" + "="*100)
        print("  🛑 Monitor detenido")
        
        display_stats()
        
        with mitigation_lock:
            if active_mitigations:
                print("\n  📋 Mitigaciones activas:")
                for dpid, sources in active_mitigations.items():
                    for src, dests in sources.items():
                        for dst in dests. keys():
                            print(f"    • {src} → {dst} en {dpid}")
        
        print("="*100)


if __name__ == '__main__':
    monitor_loop(interval=CHECK_INTERVAL)
