#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sflow_test_monitor.py
Monitor DDoS con formato correcto de sFlow-RT
"""

import requests
import time
from datetime import datetime

SFLOWRT_URL = "http://127.0.0.1:8008"

# Umbrales de detección
THRESHOLDS = {
    'bytes_per_sec': 12_500_000,  # ~100 Mbps
    'frames_per_sec': 5000,        # 5000 paquetes/seg
    'mbps': 100,                   # 100 Mbps
}

def print_header():
    """Banner del script"""
    print("="*80)
    print("  CAMPUS SENTINEL - sFlow DDoS Monitor v4")
    print("="*80)
    print(f"Conectado a: {SFLOWRT_URL}")
    print(f"Umbrales:")
    print(f"  - Bandwidth: {THRESHOLDS['mbps']} Mbps")
    print(f"  - Packets: {THRESHOLDS['frames_per_sec']:,} pps")
    print("Presiona Ctrl+C para detener")
    print("="*80)
    print()

def check_sflowrt():
    """Verifica que sFlow-RT está corriendo"""
    try:
        r = requests.get(f"{SFLOWRT_URL}/version", timeout=2)
        if r.status_code == 200:
            version = r.text.strip()
            return True, version
        return False, None
    except Exception as e:
        return False, str(e)

def check_agents():
    """Verifica agentes conectados"""
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
    except Exception as e:
        return []

def check_flows():
    """Verifica que los flows están definidos"""
    try:
        r = requests.get(f"{SFLOWRT_URL}/flow/json", timeout=3)
        if r.status_code == 200:
            flows = r.json()
            return flows
        return {}
    except Exception as e:
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
    except Exception as e:
        return []

def format_value(value, value_type):
    """Formatea valores - CORREGIDO"""
    try:
        value = float(value)
        
        if value_type == 'bytes':
            # Convertir bytes/seg a Mbps
            mbps = (value * 8) / 1_000_000
            if mbps >= 1000:
                return f"{mbps/1000:.2f} Gbps"
            elif mbps >= 1:
                return f"{mbps:. 2f} Mbps"
            else:
                kbps = mbps * 1000
                return f"{kbps:. 2f} Kbps"
        elif value_type == 'frames':
            # Paquetes por segundo
            if value >= 1000000:
                return f"{value/1000000:.2f} Mpps"
            elif value >= 1000:
                return f"{value/1000:.2f} Kpps"
            else:
                return f"{value:.0f} pps"
        else:
            return f"{value:,.2f}"
    except:
        return "N/A"

def display_flows_table(flows, title, value_type="bytes"):
    """Muestra tabla formateada"""
    print(f"\n{'─'*80}")
    print(f"  {title}")
    print(f"{'─'*80}")
    
    if not flows:
        print("  (Sin datos)")
        return
    
    print(f"{'Flow Key':<50} {'Value':>20}")
    print(f"{'─'*50} {'─'*20}")
    
    for flow in flows[:10]:
        try:
            # Formato sFlow-RT: {"key": "10.0.0. 5,10.0.0.21", "value": 123.45}
            flow_key = flow.get('key', 'N/A')
            value = flow.get('value', 0)
            
            # Truncar si es muy largo
            if len(str(flow_key)) > 48:
                flow_key = str(flow_key)[:45] + "..."
            
            value_str = format_value(value, value_type)
            
            print(f"{flow_key:<50} {value_str:>20}")
        except Exception as e:
            print(f"  Error: {e}")
    
    print()

def parse_flow_key(flow_key):
    """Parsea flow_key para extraer IPs"""
    try:
        parts = str(flow_key).split(',')
        
        if len(parts) >= 2:
            return {
                'src': parts[0].strip(),
                'dst': parts[1].strip(),
                'proto': parts[2].strip() if len(parts) > 2 else None
            }
        elif len(parts) == 1:
            return {
                'src': parts[0].strip(),
                'dst': None,
                'proto': None
            }
        return {'src': str(flow_key), 'dst': None, 'proto': None}
    except:
        return {'src': str(flow_key), 'dst': None, 'proto': None}

def analyze_anomalies(agent):
    """Analiza anomalías"""
    anomalies = []
    
    # 1.  Bandwidth alto (ddos_bytes)
    try:
        flows_bytes = get_active_flows(agent, "ddos_bytes", n=20)
        
        for flow in flows_bytes:
            flow_key = flow.get('key', '')
            value = float(flow.get('value', 0))
            
            # Calcular Mbps
            mbps = (value * 8) / 1_000_000
            
            if mbps > THRESHOLDS['mbps']:
                parsed = parse_flow_key(flow_key)
                anomalies.append({
                    'type': 'BANDWIDTH_HIGH',
                    'src_ip': parsed['src'],
                    'dst_ip': parsed['dst'],
                    'value': mbps,
                    'unit': 'Mbps'
                })
    except:
        pass
    
    # 2. PPS alto (ddos_frames)
    try:
        flows_frames = get_active_flows(agent, "ddos_frames", n=20)
        
        for flow in flows_frames:
            flow_key = flow.get('key', '')
            value = float(flow.get('value', 0))
            
            if value > THRESHOLDS['frames_per_sec']:
                parsed = parse_flow_key(flow_key)
                anomalies.append({
                    'type': 'PPS_HIGH',
                    'src_ip': parsed['src'],
                    'dst_ip': parsed['dst'],
                    'value': value,
                    'unit': 'pps'
                })
    except:
        pass
    
    # 3. Top talkers
    try:
        talkers = get_active_flows(agent, "ddos_talkers", n=10)
        
        for talker in talkers:
            flow_key = talker.get('key', '')
            value = float(talker.get('value', 0))
            mbps = (value * 8) / 1_000_000
            
            if mbps > THRESHOLDS['mbps']:
                parsed = parse_flow_key(flow_key)
                anomalies.append({
                    'type': 'TALKER_HIGH',
                    'src_ip': parsed['src'],
                    'dst_ip': parsed. get('dst'),
                    'value': mbps,
                    'unit': 'Mbps'
                })
    except:
        pass
    
    return anomalies

def monitor_loop(interval=5):
    """Loop principal"""
    print_header()
    
    # Verificaciones iniciales
    running, version = check_sflowrt()
    if not running:
        print(f"✗ sFlow-RT no responde")
        return
    
    print(f"✓ sFlow-RT corriendo: {version}")
    
    agents = check_agents()
    if agents:
        print(f"✓ Agentes: {agents}")
    else:
        print("⚠ No hay agentes")
    
    flows = check_flows()
    if not flows:
        print("✗ No hay flows.  Ejecuta: ./load_flows.sh")
        return
    
    print(f"✓ Flows: {list(flows.keys())}")
    
    monitor_agent = 'ALL'
    print(f"\nMonitoreando: {monitor_agent} | Intervalo: {interval}s\n")
    
    flows_config = [
        ("ddos_bytes", "Tráfico por Pares IP (Bytes)", "bytes"),
        ("ddos_frames", "Tráfico por Pares IP (Frames)", "frames"),
        ("ddos_talkers", "Top Talkers (Origen)", "bytes"),
        ("ddos_destinations", "Top Destinations", "bytes"),
        ("ddos_protocols", "Tráfico por Protocolo", "frames"),
        ("ddos_ports", "Puertos Más Atacados", "frames"),
    ]
    
    iteration = 0
    
    try:
        while True:
            iteration += 1
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"\n{'═'*80}")
            print(f"  Iteración #{iteration} - {timestamp}")
            print(f"{'═'*80}")
            
            # Mostrar flows
            for flow_name, title, value_type in flows_config:
                try:
                    flows_data = get_active_flows(monitor_agent, flow_name, n=10)
                    if flows_data:
                        display_flows_table(flows_data, title, value_type)
                except Exception as e:
                    print(f"⚠ Error en {flow_name}: {e}")
            
            # Anomalías
            print(f"\n{'─'*80}")
            print(f"  🔍 Análisis de Anomalías")
            print(f"{'─'*80}")
            
            anomalies = analyze_anomalies(monitor_agent)
            
            if anomalies:
                for anom in anomalies:
                    atype = anom['type']
                    src = anom.get('src_ip', 'N/A')
                    dst = anom.get('dst_ip', 'N/A')
                    val = anom['value']
                    unit = anom['unit']
                    
                    if atype == 'BANDWIDTH_HIGH':
                        print(f"🚨 BANDWIDTH ALTO:")
                        print(f"   Origen:  {src}")
                        print(f"   Destino: {dst}")
                        print(f"   Valor:   {val:. 2f} {unit}")
                        print()
                    elif atype == 'PPS_HIGH':
                        print(f"🚨 PPS ALTO (Posible Flood):")
                        print(f"   Origen:  {src}")
                        print(f"   Destino: {dst}")
                        print(f"   Rate:    {val:,.0f} {unit}")
                        print()
                    elif atype == 'TALKER_HIGH':
                        print(f"⚠️  TALKER SOSPECHOSO:")
                        print(f"   IP:      {src}")
                        print(f"   Valor:   {val:.2f} {unit}")
                        print()
            else:
                print("✓ No se detectaron anomalías")
            
            print()
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n\n✓ Monitor detenido")

if __name__ == '__main__':
    monitor_loop(interval=5)
