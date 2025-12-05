#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sflow_test_monitor_v3_fixed.py
Monitor DDoS con detección mejorada y corrección de errores de formato
"""

import requests
import time
from datetime import datetime

SFLOWRT_URL = "http://127.0.0.1:8008"

# Umbrales de detección (ajustar según tu red)
THRESHOLDS = {
    'bytes_per_sec': 12_500_000,  # ~100 Mbps
    'frames_per_sec': 5000,        # 5000 paquetes/seg
    'mbps': 100,                   # 100 Mbps
}

def print_header():
    """Banner del script"""
    print("="*80)
    print("  CAMPUS SENTINEL - sFlow DDoS Monitor v3 (FIXED)")
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
        print(f"✗ Error obteniendo agentes: {e}")
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
        print(f"✗ Error obteniendo flows: {e}")
        return {}

def get_active_flows(agent, flow_name, n=10):
    """Obtiene flows activos usando /activeflows"""
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
    """Formatea valores según tipo - CORREGIDO"""
    try:
        # Asegurar que value es numérico
        value = float(value) if value is not None else 0.0
        
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
            return f"{value:,. 2f}"
    except Exception as e:
        return f"Error: {e}"

def display_flows_table(flows, title, value_type="bytes"):
    """Muestra tabla formateada de flows - CORREGIDO"""
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
            flow_key = flow.get('flowKey', flow.get('key', 'N/A'))
            value = flow.get('value', flow.get('metricValue', 0))
            
            # Asegurar que flowKey es string
            flow_key = str(flow_key) if flow_key else 'N/A'
            
            # Truncar flow_key si es muy largo
            if len(flow_key) > 48:
                flow_key = flow_key[:45] + "..."
            
            value_str = format_value(value, value_type)
            
            print(f"{flow_key:<50} {value_str:>20}")
        except Exception as e:
            print(f"  Error procesando flow: {e} | Data: {flow}")
    
    print()

def parse_flow_key(flow_key):
    """Parsea flow_key para extraer IPs origen/destino
    
    Formatos esperados:
    - "10. 0.0.5,10.0.0.21" → (src: 10.0.0.5, dst: 10.0. 0.21)
    - "10.0.0.5" → (src: 10.0.0.5, dst: None)
    - "10.0.0.5,10.0.0.21,6" → (src: 10. 0.0.5, dst: 10.0.0.21, proto: 6)
    """
    try:
        parts = str(flow_key).split(',')
        
        if len(parts) >= 2:
            return {
                'src': parts[0],
                'dst': parts[1],
                'proto': parts[2] if len(parts) > 2 else None
            }
        elif len(parts) == 1:
            return {
                'src': parts[0],
                'dst': None,
                'proto': None
            }
        else:
            return {'src': str(flow_key), 'dst': None, 'proto': None}
    except Exception as e:
        return {'src': str(flow_key), 'dst': None, 'proto': None}

def analyze_anomalies(agent):
    """Analiza anomalías en el tráfico - MEJORADO con detalles"""
    anomalies = []
    
    # 1. Verificar bandwidth alto (ddos_bytes)
    try:
        flows_bytes = get_active_flows(agent, "ddos_bytes", n=20)
        
        for flow in flows_bytes:
            flow_key = flow.get('flowKey', '')
            value = float(flow.get('value', 0))
            
            # Calcular Mbps
            mbps = (value * 8) / 1_000_000
            
            if mbps > THRESHOLDS['mbps']:
                parsed = parse_flow_key(flow_key)
                anomalies.append({
                    'type': 'BANDWIDTH_HIGH',
                    'flow_key': flow_key,
                    'src_ip': parsed['src'],
                    'dst_ip': parsed['dst'],
                    'value': mbps,
                    'unit': 'Mbps'
                })
    except Exception as e:
        pass
    
    # 2.  Verificar PPS alto (ddos_frames)
    try:
        flows_frames = get_active_flows(agent, "ddos_frames", n=20)
        
        for flow in flows_frames:
            flow_key = flow.get('flowKey', '')
            value = float(flow.get('value', 0))
            
            if value > THRESHOLDS['frames_per_sec']:
                parsed = parse_flow_key(flow_key)
                anomalies.append({
                    'type': 'PPS_HIGH',
                    'flow_key': flow_key,
                    'src_ip': parsed['src'],
                    'dst_ip': parsed['dst'],
                    'value': value,
                    'unit': 'pps'
                })
    except Exception as e:
        pass
    
    # 3. Verificar top talkers sospechosos
    try:
        talkers = get_active_flows(agent, "ddos_talkers", n=10)
        
        for talker in talkers:
            flow_key = talker.get('flowKey', '')
            value = float(talker. get('value', 0))
            mbps = (value * 8) / 1_000_000
            
            if mbps > THRESHOLDS['mbps']:
                parsed = parse_flow_key(flow_key)
                anomalies.append({
                    'type': 'TALKER_HIGH',
                    'flow_key': flow_key,
                    'src_ip': parsed['src'],
                    'dst_ip': parsed. get('dst'),
                    'value': mbps,
                    'unit': 'Mbps'
                })
    except Exception as e:
        pass
    
    return anomalies

def monitor_loop(interval=5):
    """Loop principal de monitoreo"""
    print_header()
    
    # Verificar sFlow-RT
    running, version = check_sflowrt()
    if not running:
        print(f"✗ sFlow-RT no responde: {version}")
        return
    
    print(f"✓ sFlow-RT corriendo: {version}")
    
    # Verificar agentes
    agents = check_agents()
    if not agents:
        print("⚠ No hay agentes conectados")
        print("  Verifica configuración sFlow en switches")
    else:
        print(f"✓ Agentes detectados: {agents}")
    
    # Verificar flows
    flows = check_flows()
    if not flows:
        print("✗ No hay flows definidos")
        print("  Ejecuta: ./load_flows.sh")
        return
    
    print(f"✓ Flows definidos ({len(flows)}): {list(flows.keys())}")
    
    # Usar 'ALL' para monitorear todos los agentes
    monitor_agent = 'ALL'
    
    print(f"\nMonitoreando agente: {monitor_agent}")
    print(f"Intervalo de actualización: {interval} segundos")
    print()
    
    # Configuración de flows a monitorear
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
            
            # Monitorear cada flow
            for flow_name, title, value_type in flows_config:
                try:
                    flows_data = get_active_flows(monitor_agent, flow_name, n=10)
                    
                    if flows_data:
                        display_flows_table(flows_data, title, value_type)
                except Exception as e:
                    print(f"⚠ Error obteniendo {flow_name}: {e}")
            
            # Análisis de anomalías
            print(f"\n{'─'*80}")
            print(f"  🔍 Análisis de Anomalías")
            print(f"{'─'*80}")
            
            anomalies = analyze_anomalies(monitor_agent)
            
            if anomalies:
                for anomaly in anomalies:
                    anom_type = anomaly['type']
                    src_ip = anomaly. get('src_ip', 'N/A')
                    dst_ip = anomaly.get('dst_ip', 'N/A')
                    value = anomaly['value']
                    unit = anomaly['unit']
                    
                    if anom_type == 'BANDWIDTH_HIGH':
                        print(f"🚨 BANDWIDTH ALTO:")
                        print(f"   Origen: {src_ip}")
                        print(f"   Destino: {dst_ip}")
                        print(f"   Bandwidth: {value:. 2f} {unit}")
                        print()
                    elif anom_type == 'PPS_HIGH':
                        print(f"🚨 PPS ALTO (Posible Flood):")
                        print(f"   Origen: {src_ip}")
                        print(f"   Destino: {dst_ip}")
                        print(f"   Rate: {value:,.0f} {unit}")
                        print()
                    elif anom_type == 'TALKER_HIGH':
                        print(f"⚠️  TALKER SOSPECHOSO:")
                        print(f"   IP Origen: {src_ip}")
                        print(f"   Bandwidth: {value:.2f} {unit}")
                        print()
            else:
                print("✓ No se detectaron anomalías")
            
            print()
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n\n✓ Monitoreo detenido por el usuario")

if __name__ == '__main__':
    monitor_loop(interval=5)
