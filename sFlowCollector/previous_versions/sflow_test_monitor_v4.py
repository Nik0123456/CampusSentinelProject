#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sflow_test_monitor_enhanced.py
Monitor DDoS con información de switch y puerto
"""

import requests
import time
from datetime import datetime
from collections import defaultdict

SFLOWRT_URL = "http://127.0.0.1:8008"
FLOODLIGHT_URL = "http://127.0.0.1:8080"

# Umbrales
THRESHOLDS = {
    'bytes_per_sec': 12_500_000,
    'frames_per_sec': 5000,
    'mbps': 100,
}

# Mapeo de agentes (switches) a nombres amigables
SWITCH_NAMES = {
    '10.0.0.13': 'sw3 (Spine)',
    '10.0. 0.14': 'sw4 (Spine)',
    # Agregar más según tu topología
}

def print_header():
    """Banner del script"""
    print("="*80)
    print("  CAMPUS SENTINEL - sFlow Enhanced Monitor")
    print("="*80)
    print(f"sFlow-RT: {SFLOWRT_URL}")
    print(f"Floodlight: {FLOODLIGHT_URL}")
    print(f"Umbrales: {THRESHOLDS['mbps']} Mbps / {THRESHOLDS['frames_per_sec']:,} pps")
    print("="*80)
    print()

def get_switch_name(agent_ip):
    """Convierte IP de agente a nombre de switch"""
    return SWITCH_NAMES.get(agent_ip, agent_ip)

def get_port_name_from_dataSource(agent_ip, dataSource):
    """Obtiene nombre de puerto desde dataSource (ifIndex)
    
    Consulta a Floodlight para obtener el nombre del puerto
    """
    try:
        # Obtener información de switches desde Floodlight
        r = requests.get(f"{FLOODLIGHT_URL}/wm/core/controller/switches/json", timeout=2)
        
        if r.status_code != 200:
            return f"port-{dataSource}"
        
        switches = r.json()
        
        # Buscar el switch por IP
        for switch in switches:
            # El DPID del switch en Floodlight
            dpid = switch.get('switchDPID', '')
            
            # Obtener puertos del switch
            r2 = requests.get(
                f"{FLOODLIGHT_URL}/wm/core/switch/{dpid}/port/json",
                timeout=2
            )
            
            if r2.status_code == 200:
                ports = r2.json()
                
                # Buscar puerto por número
                for port_info in ports. get(dpid, []):
                    if str(port_info.get('portNumber')) == str(dataSource):
                        port_name = port_info.get('name', f"port-{dataSource}")
                        return port_name
        
        return f"port-{dataSource}"
    except:
        return f"port-{dataSource}"

def get_switch_topology():
    """Obtiene topología de switches desde Floodlight"""
    try:
        r = requests.get(f"{FLOODLIGHT_URL}/wm/topology/links/json", timeout=2)
        
        if r.status_code == 200:
            return r. json()
        return []
    except:
        return []

def check_sflowrt():
    """Verifica sFlow-RT"""
    try:
        r = requests.get(f"{SFLOWRT_URL}/version", timeout=2)
        if r.status_code == 200:
            return True, r.text. strip()
        return False, None
    except Exception as e:
        return False, str(e)

def check_agents():
    """Verifica agentes"""
    try:
        r = requests.get(f"{SFLOWRT_URL}/agents/json", timeout=3)
        agents = r.json()
        
        agent_list = []
        for agent in agents:
            if isinstance(agent, dict):
                addr = agent.get('address')
                if addr:
                    agent_list.append(addr)
            else:
                agent_list. append(str(agent))
        
        return agent_list
    except:
        return []

def check_flows():
    """Verifica flows"""
    try:
        r = requests.get(f"{SFLOWRT_URL}/flow/json", timeout=3)
        if r.status_code == 200:
            return r.json()
        return {}
    except:
        return {}

def get_active_flows(agent, flow_name, n=10):
    """Obtiene flows activos"""
    try:
        r = requests.get(
            f"{SFLOWRT_URL}/activeflows/{agent}/{flow_name}/json",
            params={"n": n},
            timeout=3
        )
        
        if r.status_code == 200:
            data = r.json()
            return data if isinstance(data, list) else []
        return []
    except:
        return []

def format_value(value, value_type):
    """Formatea valores"""
    try:
        value = float(value)
        
        if value_type == 'bytes':
            mbps = (value * 8) / 1_000_000
            if mbps >= 1000:
                return f"{mbps/1000:. 2f} Gbps"
            elif mbps >= 1:
                return f"{mbps:. 2f} Mbps"
            elif mbps >= 0.001:
                kbps = mbps * 1000
                return f"{kbps:. 2f} Kbps"
            else:
                return f"<1 Kbps"
        elif value_type == 'frames':
            if value >= 1000000:
                return f"{value/1000000:.2f} Mpps"
            elif value >= 1000:
                return f"{value/1000:.2f} Kpps"
            else:
                return f"{value:. 0f} pps"
        else:
            return f"{value:,.2f}"
    except:
        return "N/A"

def display_flows_table_enhanced(flows, title, value_type="bytes"):
    """Muestra tabla con información de switch/puerto"""
    print(f"\n{'─'*100}")
    print(f"  {title}")
    print(f"{'─'*100}")
    
    if not flows:
        print("  (Sin datos)")
        return
    
    print(f"{'Flow Key':<35} {'Switch':<20} {'Port':<10} {'Value':>15}")
    print(f"{'─'*35} {'─'*20} {'─'*10} {'─'*15}")
    
    for flow in flows[:10]:
        try:
            flow_key = flow.get('key', 'N/A')
            value = flow.get('value', 0)
            agent = flow.get('agent', 'N/A')
            dataSource = flow.get('dataSource', 'N/A')
            
            # Truncar flow_key
            if len(str(flow_key)) > 33:
                flow_key = str(flow_key)[:30] + "..."
            
            # Obtener nombre de switch
            switch_name = get_switch_name(agent)
            
            # Formatear puerto
            port_str = f"if{dataSource}"
            
            value_str = format_value(value, value_type)
            
            print(f"{flow_key:<35} {switch_name:<20} {port_str:<10} {value_str:>15}")
        except Exception as e:
            print(f"  Error: {e}")
    
    print()

def parse_flow_key(flow_key):
    """Parsea flow_key"""
    try:
        parts = str(flow_key).split(',')
        
        if len(parts) >= 2:
            return {
                'src': parts[0].strip(),
                'dst': parts[1].strip(),
                'proto': parts[2].strip() if len(parts) > 2 else None
            }
        elif len(parts) == 1:
            return {'src': parts[0].strip(), 'dst': None, 'proto': None}
        return {'src': str(flow_key), 'dst': None, 'proto': None}
    except:
        return {'src': str(flow_key), 'dst': None, 'proto': None}

def analyze_anomalies_enhanced(agent):
    """Analiza anomalías con detalles de switch/puerto"""
    anomalies = []
    
    # PPS alto
    try:
        flows_frames = get_active_flows(agent, "ddos_frames", n=20)
        
        for flow in flows_frames:
            flow_key = flow.get('key', '')
            value = float(flow.get('value', 0))
            agent_ip = flow.get('agent', 'N/A')
            dataSource = flow.get('dataSource', 'N/A')
            
            if value > THRESHOLDS['frames_per_sec']:
                parsed = parse_flow_key(flow_key)
                anomalies.append({
                    'type': 'PPS_HIGH',
                    'src_ip': parsed['src'],
                    'dst_ip': parsed['dst'],
                    'value': value,
                    'unit': 'pps',
                    'switch': get_switch_name(agent_ip),
                    'switch_ip': agent_ip,
                    'port': dataSource
                })
    except:
        pass
    
    # Bandwidth alto
    try:
        flows_bytes = get_active_flows(agent, "ddos_bytes", n=20)
        
        for flow in flows_bytes:
            flow_key = flow.get('key', '')
            value = float(flow.get('value', 0))
            agent_ip = flow.get('agent', 'N/A')
            dataSource = flow.get('dataSource', 'N/A')
            
            mbps = (value * 8) / 1_000_000
            
            if mbps > THRESHOLDS['mbps']:
                parsed = parse_flow_key(flow_key)
                anomalies.append({
                    'type': 'BANDWIDTH_HIGH',
                    'src_ip': parsed['src'],
                    'dst_ip': parsed['dst'],
                    'value': mbps,
                    'unit': 'Mbps',
                    'switch': get_switch_name(agent_ip),
                    'switch_ip': agent_ip,
                    'port': dataSource
                })
    except:
        pass
    
    return anomalies

def monitor_loop(interval=5):
    """Loop principal"""
    print_header()
    
    running, version = check_sflowrt()
    if not running:
        print("✗ sFlow-RT no responde")
        return
    
    print(f"✓ sFlow-RT: {version}")
    
    agents = check_agents()
    if agents:
        print(f"✓ Agentes:")
        for agent in agents:
            print(f"  - {get_switch_name(agent)} ({agent})")
    
    flows = check_flows()
    if not flows:
        print("✗ No hay flows")
        return
    
    print(f"✓ Flows: {len(flows)}")
    print()
    
    monitor_agent = 'ALL'
    
    flows_config = [
        ("ddos_frames", "Tráfico por Pares IP (Frames)", "frames"),
        ("ddos_bytes", "Tráfico por Pares IP (Bytes)", "bytes"),
        ("ddos_ports", "Puertos Más Atacados", "frames"),
    ]
    
    iteration = 0
    
    try:
        while True:
            iteration += 1
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"\n{'═'*100}")
            print(f"  Iteración #{iteration} - {timestamp}")
            print(f"{'═'*100}")
            
            for flow_name, title, value_type in flows_config:
                try:
                    flows_data = get_active_flows(monitor_agent, flow_name, n=10)
                    if flows_data:
                        display_flows_table_enhanced(flows_data, title, value_type)
                except Exception as e:
                    print(f"⚠ Error: {e}")
            
            print(f"\n{'─'*100}")
            print(f"  🚨 ANOMALÍAS DETECTADAS")
            print(f"{'─'*100}")
            
            anomalies = analyze_anomalies_enhanced(monitor_agent)
            
            if anomalies:
                for anom in anomalies:
                    print(f"\n{'▶'*50}")
                    print(f"🚨 {anom['type']. replace('_', ' ')}")
                    print(f"{'▶'*50}")
                    print(f"  IP Origen:     {anom. get('src_ip', 'N/A')}")
                    print(f"  IP Destino:    {anom.get('dst_ip', 'N/A')}")
                    print(f"  Switch:        {anom.get('switch', 'N/A')}")
                    print(f"  Puerto:        if{anom.get('port', 'N/A')}")
                    print(f"  Valor:         {anom['value']:,.2f} {anom['unit']}")
                    print(f"{'▶'*50}")
            else:
                print("✓ No se detectaron anomalías")
            
            print()
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n\n✓ Monitor detenido")

if __name__ == '__main__':
    monitor_loop(interval=5)
