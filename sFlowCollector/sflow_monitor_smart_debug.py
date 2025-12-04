#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sflow_monitor_smart_debug.py
Monitor DDoS con descubrimiento automático y debug completo del proceso de decisión
"""

import requests
import time
import ipaddress
from datetime import datetime
import json

SFLOWRT_URL = "http://127.0.0.1:8008"
FLOODLIGHT_URL = "http://127.0.0.1:8080"

# Umbrales
THRESHOLDS = {
    'frames_per_sec': 5000,
    'mbps': 100,
}

# Redes
INTERNAL_NETWORK = ipaddress.ip_network('10.0.0.0/24')
CAMPUS_NETWORK = ipaddress. ip_network('10.0.0.0/16')

class TopologyManager:
    """Gestiona topología desde Floodlight"""
    
    def __init__(self, floodlight_url):
        self.floodlight_url = floodlight_url
        self. switches = {}
        self.inter_switch_ports = set()
        self.host_ports = {}
        
    def discover_topology(self):
        """Descubre topología completa"""
        print("🔍 Descubriendo topología de red...")
        
        self._get_switches()
        self._get_inter_switch_links()
        self._identify_host_ports()
        
        print(f"✓ Topología descubierta:")
        print(f"  - Switches: {len(self.switches)}")
        print(f"  - Puertos totales: {sum(len(sw['ports']) for sw in self.switches.values())}")
        print(f"  - Enlaces inter-switch: {len(self.inter_switch_ports)}")
        print(f"  - Puertos de hosts: {len(self.host_ports)}")
        
        for dpid, sw_info in self.switches.items():
            print(f"\n  [{sw_info['ip']}] {dpid}")
            print(f"    Puertos totales: {sorted(sw_info['ports']. keys())}")
            
            isw_ports = sorted([p. split(':')[-1] for p in self.inter_switch_ports if p.startswith(dpid)])
            print(f"    Puertos inter-switch: {isw_ports}")
            
            host_ports_list = sorted([p.split(':')[-1] for p in self.host_ports.keys() if p.startswith(dpid)])
            print(f"    Puertos de hosts: {host_ports_list}")
            
            uplinks = self. count_uplinks(sw_info['ip'])
            print(f"    Uplinks count: {uplinks}")
        
        print()
        
    def _get_switches(self):
        """Obtiene switches y sus puertos"""
        try:
            r = requests.get(
                f"{self.floodlight_url}/wm/core/controller/switches/json",
                timeout=3
            )
            
            if r.status_code == 200:
                switches_data = r.json()
                
                for switch in switches_data:
                    dpid = switch. get('switchDPID', switch.get('dpid', ''))
                    inetAddress = switch.get('inetAddress', '')
                    
                    ip = ''
                    if '/' in inetAddress:
                        ip = inetAddress.split('/')[1]. split(':')[0]
                    
                    ports = self._get_switch_ports(dpid)
                    
                    self.switches[dpid] = {
                        'dpid': dpid,
                        'ip': ip,
                        'ports': ports
                    }
                    
                print(f"  ✓ Switches descubiertos: {len(self. switches)}")
        except Exception as e:
            print(f"  ✗ Error obteniendo switches: {e}")
    
    def _get_switch_ports(self, dpid):
        """Obtiene puertos de un switch"""
        try:
            r = requests.get(
                f"{self.floodlight_url}/wm/core/switch/{dpid}/port/json",
                timeout=3
            )
            
            if r.status_code == 200:
                data = r.json()
                ports = {}
                
                port_reply = data.get('port_reply', [])
                
                if port_reply and len(port_reply) > 0:
                    port_list = port_reply[0].get('port', [])
                    
                    for port_info in port_list:
                        port_num = str(port_info.get('portNumber', ''))
                        
                        if port_num.upper() == 'LOCAL':
                            continue
                        if port_num == '65534':
                            continue
                        
                        port_name = f"eth{port_num}"
                        
                        ports[port_num] = {
                            'number': port_num,
                            'name': port_name,
                            'stats': port_info
                        }
                
                return ports
        except Exception as e:
            print(f"    ✗ Error obteniendo puertos de {dpid}: {e}")
            return {}
    
    def _get_inter_switch_links(self):
        """Identifica enlaces inter-switch"""
        try:
            r = requests. get(
                f"{self. floodlight_url}/wm/topology/links/json",
                timeout=3
            )
            
            if r.status_code == 200:
                links = r.json()
                
                for link in links:
                    src_switch = link.get('src-switch')
                    src_port = str(link.get('src-port'))
                    dst_switch = link.get('dst-switch')
                    dst_port = str(link.get('dst-port'))
                    
                    self.inter_switch_ports.add(f"{src_switch}:{src_port}")
                    self.inter_switch_ports.add(f"{dst_switch}:{dst_port}")
                
                print(f"  ✓ Enlaces inter-switch: {len(self.inter_switch_ports)//2} enlaces ({len(self.inter_switch_ports)} puertos)")
        except Exception as e:
            print(f"  ✗ Error obteniendo enlaces: {e}")
    
    def _identify_host_ports(self):
        """Identifica puertos de hosts"""
        for dpid, switch_info in self.switches.items():
            for port_num, port_info in switch_info['ports'].items():
                port_key = f"{dpid}:{port_num}"
                
                if port_key not in self.inter_switch_ports:
                    self.host_ports[port_key] = {
                        'switch_dpid': dpid,
                        'switch_ip': switch_info['ip'],
                        'port_num': port_num,
                        'port_name': port_info['name']
                    }
    
    def is_host_port(self, switch_ip, port_num):
        """Verifica si es puerto de host"""
        dpid = None
        for sw_dpid, sw_info in self. switches.items():
            if sw_info['ip'] == switch_ip:
                dpid = sw_dpid
                break
        
        if not dpid:
            return False
        
        port_key = f"{dpid}:{str(port_num)}"
        return port_key in self.host_ports
    
    def get_port_info(self, switch_ip, port_num):
        """Obtiene info de puerto"""
        dpid = None
        for sw_dpid, sw_info in self.switches.items():
            if sw_info['ip'] == switch_ip:
                dpid = sw_dpid
                break
        
        if not dpid:
            return None
        
        port_key = f"{dpid}:{str(port_num)}"
        return self.host_ports.get(port_key)
    
    def get_switch_name(self, switch_ip):
        """Nombre amigable del switch"""
        for dpid, sw_info in self.switches.items():
            if sw_info['ip'] == switch_ip:
                return f"SW-{switch_ip. split('.')[-1]}"
        return switch_ip
    
    def count_uplinks(self, switch_ip):
        """Cuenta enlaces inter-switch de un switch"""
        dpid = None
        for sw_dpid, sw_info in self.switches.items():
            if sw_info['ip'] == switch_ip:
                dpid = sw_dpid
                break
        
        if not dpid:
            return 999
        
        uplink_count = len([p for p in self.inter_switch_ports if p.startswith(dpid)])
        return uplink_count


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


def check_flows():
    """Verifica flows"""
    try:
        r = requests.get(f"{SFLOWRT_URL}/flow/json", timeout=3)
        if r.status_code == 200:
            return r.json()
        return {}
    except:
        return {}


def get_active_flows(flow_name, n=30):
    """Obtiene flows activos"""
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


def _calculate_ip_distance(ip1, ip2):
    """Calcula distancia entre dos IPs"""
    try:
        parts1 = [int(x) for x in ip1.split('.')]
        parts2 = [int(x) for x in ip2.split('. ')]
        
        distance = abs(parts1[2] - parts2[2]) * 256 + abs(parts1[3] - parts2[3])
        
        return distance
    except:
        return 9999


def filter_ingress_flows(flows, topology, debug=False):
    """Filtra flows con debug detallado del proceso"""
    ingress_flows = []
    flows_by_pair = {}
    debug_info = {}
    
    for flow in flows:
        try:
            flow_key = flow.get('key', '')
            agent = flow.get('agent', '')
            dataSource = str(flow. get('dataSource', ''))
            
            parts = flow_key.split(',')
            if len(parts) < 2:
                continue
            
            src_ip = parts[0]
            dst_ip = parts[1]
            
            if not topology. is_host_port(agent, dataSource):
                continue
            
            if not is_external_attack(src_ip):
                continue
            
            pair_key = f"{src_ip},{dst_ip}"
            
            if pair_key not in flows_by_pair:
                flows_by_pair[pair_key] = []
                debug_info[pair_key] = []
            
            flows_by_pair[pair_key]. append(flow)
        except:
            continue
    
    for pair_key, pair_flows in flows_by_pair. items():
        if not pair_flows:
            continue
        
        src_ip = pair_key.split(',')[0]
        
        # Evaluar cada candidato
        candidates = []
        for flow in pair_flows:
            agent = flow.get('agent', '')
            dataSource = str(flow.get('dataSource', ''))
            value = float(flow.get('value', 0))
            
            uplinks = topology.count_uplinks(agent)
            distance = _calculate_ip_distance(agent, src_ip)
            
            candidates.append({
                'flow': flow,
                'switch_ip': agent,
                'switch_name': topology.get_switch_name(agent),
                'port': dataSource,
                'port_name': f"eth{dataSource}",
                'uplinks': uplinks,
                'distance': distance,
                'value': value
            })
        
        # Guardar info de debug
        debug_info[pair_key] = candidates
        
        # Seleccionar el mejor
        best_flow = min(
            pair_flows,
            key=lambda f: (
                topology.count_uplinks(f. get('agent', '')),
                _calculate_ip_distance(f. get('agent', ''), src_ip),
                -float(f.get('value', 0))
            )
        )
        ingress_flows.append(best_flow)
    
    if debug:
        return ingress_flows, debug_info
    
    return ingress_flows


def format_value(value, value_type):
    """Formatea valores"""
    try:
        value = float(value)
        
        if value_type == 'bytes':
            mbps = (value * 8) / 1_000_000
            if mbps >= 1:
                return f"{mbps:.2f} Mbps"
            else:
                return f"{mbps*1000:.2f} Kbps"
        elif value_type == 'frames':
            if value >= 1000:
                return f"{value/1000:.2f} Kpps"
            else:
                return f"{value:.0f} pps"
        return f"{value:.2f}"
    except:
        return "N/A"


def display_flows(flows, topology, title, value_type):
    """Muestra tabla"""
    print(f"\n{'─'*100}")
    print(f"  {title}")
    print(f"{'─'*100}")
    
    if not flows:
        print("  ✓ No se detectaron ataques externos")
        return
    
    print(f"{'Origen (Atacante)':<20} {'Destino (Víctima)':<20} {'Switch':<15} {'Puerto':<15} {'Value':>15}")
    print(f"{'─'*20} {'─'*20} {'─'*15} {'─'*15} {'─'*15}")
    
    for flow in flows[:10]:
        try:
            flow_key = flow.get('key', '')
            agent = flow. get('agent', '')
            dataSource = str(flow.get('dataSource', ''))
            value = flow.get('value', 0)
            
            parts = flow_key.split(',')
            src_ip = parts[0] if len(parts) > 0 else 'N/A'
            dst_ip = parts[1] if len(parts) > 1 else 'N/A'
            
            port_info = topology.get_port_info(agent, dataSource)
            port_name = port_info['port_name'] if port_info else f"if{dataSource}"
            
            switch_name = topology.get_switch_name(agent)
            value_str = format_value(value, value_type)
            
            print(f"{src_ip:<20} {dst_ip:<20} {switch_name:<15} {port_name:<15} {value_str:>15}")
        except Exception as e:
            print(f"  Error: {e}")
    
    print()


def analyze_anomalies(topology):
    """Detecta anomalías con debug completo"""
    anomalies = []
    
    flows = get_active_flows("ddos_frames", n=30)
    ingress_flows, debug_info = filter_ingress_flows(flows, topology, debug=True)
    
    for flow in ingress_flows:
        try:
            flow_key = flow.get('key', '')
            value = float(flow.get('value', 0))
            agent = flow.get('agent', '')
            dataSource = str(flow.get('dataSource', ''))
            
            if value > THRESHOLDS['frames_per_sec']:
                parts = flow_key.split(',')
                src_ip = parts[0] if len(parts) > 0 else 'N/A'
                dst_ip = parts[1] if len(parts) > 1 else 'N/A'
                
                port_info = topology.get_port_info(agent, dataSource)
                
                # Obtener debug info
                pair_key = f"{src_ip},{dst_ip}"
                candidates_info = debug_info.get(pair_key, [])
                
                anomalies.append({
                    'type': 'EXTERNAL_ATTACK',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'value': value,
                    'switch_ip': agent,
                    'switch_name': topology.get_switch_name(agent),
                    'port_num': dataSource,
                    'port_name': port_info['port_name'] if port_info else f"if{dataSource}",
                    'switch_dpid': port_info['switch_dpid'] if port_info else 'N/A',
                    'candidates': candidates_info,
                    'flow_key': flow_key
                })
        except:
            continue
    
    return anomalies


def display_attack_debug(anom, topology):
    """Muestra información detallada del ataque con proceso de decisión"""
    
    print(f"\n{'🚨'*40}")
    print(f"  ATAQUE DDoS DETECTADO")
    print(f"{'🚨'*40}")
    
    # Información básica del ataque
    print(f"\n{'═'*80}")
    print(f"  📊 INFORMACIÓN DEL ATAQUE")
    print(f"{'═'*80}")
    print(f"  Atacante:       {anom['src_ip']} (RED EXTERNA)")
    print(f"  Víctima:        {anom['dst_ip']}")
    print(f"  Rate:           {anom['value']:,.0f} pps")
    print(f"  Flow Key:       {anom['flow_key']}")
    
    # Decisión final
    print(f"\n{'═'*80}")
    print(f"  ✅ INGRESS REAL SELECCIONADO")
    print(f"{'═'*80}")
    print(f"  Switch:         {anom['switch_name']} ({anom['switch_ip']})")
    print(f"  Switch DPID:    {anom['switch_dpid']}")
    print(f"  Puerto:         {anom['port_name']} (#{anom['port_num']})")
    print(f"  Uplinks:        {topology.count_uplinks(anom['switch_ip'])}")
    
    # Proceso de decisión
    if anom. get('candidates'):
        print(f"\n{'═'*80}")
        print(f"  🔍 PROCESO DE DECISIÓN (Candidatos Evaluados)")
        print(f"{'═'*80}")
        
        print(f"\n  {'Switch':<15} {'Puerto':<10} {'Uplinks':<10} {'Distancia IP':<15} {'Tráfico (pps)':<15} {'Seleccionado':<12}")
        print(f"  {'-'*15} {'-'*10} {'-'*10} {'-'*15} {'-'*15} {'-'*12}")
        
        # Ordenar candidatos por el mismo criterio de selección
        sorted_candidates = sorted(
            anom['candidates'],
            key=lambda c: (c['uplinks'], c['distance'], -c['value'])
        )
        
        for idx, candidate in enumerate(sorted_candidates):
            is_selected = (candidate['switch_ip'] == anom['switch_ip'] and 
                          candidate['port'] == anom['port_num'])
            
            selected_mark = "✓ SÍ" if is_selected else "✗ No"
            
            print(f"  {candidate['switch_name']:<15} "
                  f"{candidate['port_name']:<10} "
                  f"{candidate['uplinks']:<10} "
                  f"{candidate['distance']:<15} "
                  f"{candidate['value']:>13,.0f}  "
                  f"{selected_mark:<12}")
        
        # Explicación de la decisión
        print(f"\n{'─'*80}")
        print(f"  📋 CRITERIOS DE SELECCIÓN (en orden de prioridad):")
        print(f"{'─'*80}")
        print(f"  1.  UPLINKS:       Menor número = Switch leaf (más cercano al host)")
        print(f"  2. DISTANCIA IP:  Menor distancia = Más cercano al atacante")
        print(f"  3. TRÁFICO:       Mayor valor = Tiebreaker final")
        
        # Razón de la selección
        winner = sorted_candidates[0]
        print(f"\n  💡 RAZÓN DE SELECCIÓN:")
        print(f"     {winner['switch_name']} tiene {winner['uplinks']} uplink(s),")
        
        if len(sorted_candidates) > 1:
            runner_up = sorted_candidates[1]
            if winner['uplinks'] < runner_up['uplinks']:
                print(f"     mientras que {runner_up['switch_name']} tiene {runner_up['uplinks']} uplink(s).")
                print(f"     → {winner['switch_name']} es un switch LEAF (más cercano a hosts)")
            elif winner['uplinks'] == runner_up['uplinks']:
                print(f"     igual que {runner_up['switch_name']}.")
                print(f"     Usando distancia IP como tiebreaker:")
                print(f"     - {winner['switch_name']}: distancia {winner['distance']}")
                print(f"     - {runner_up['switch_name']}: distancia {runner_up['distance']}")
                print(f"     → {winner['switch_name']} está MÁS CERCA del atacante")
    
    # APIs consultadas
    print(f"\n{'═'*80}")
    print(f"  🔌 DATOS DE APIS CONSULTADAS")
    print(f"{'═'*80}")
    
    # 1. sFlow-RT Active Flows
    print(f"\n  [1] sFlow-RT Active Flows API")
    print(f"      GET {SFLOWRT_URL}/activeflows/ALL/ddos_frames/json? n=30")
    print(f"      Response: Flow detectado para {anom['flow_key']}")
    print(f"      {'-'*76}")
    
    # Simular respuesta (mostrar el flow específico)
    if anom. get('candidates'):
        for candidate in anom['candidates']:
            print(f"      {{")
            print(f"        \"key\": \"{anom['flow_key']}\",")
            print(f"        \"agent\": \"{candidate['switch_ip']}\",")
            print(f"        \"dataSource\": \"{candidate['port']}\",")
            print(f"        \"value\": {candidate['value']:.2f}")
            print(f"      }}")
    
    # 2. Floodlight Topology Links
    print(f"\n  [2] Floodlight Topology Links API")
    print(f"      GET {FLOODLIGHT_URL}/wm/topology/links/json")
    print(f"      Response: Enlaces usados para identificar uplinks")
    print(f"      {'-'*76}")
    
    # Mostrar uplinks relevantes
    for candidate in anom. get('candidates', []):
        uplink_count = candidate['uplinks']
        print(f"      {candidate['switch_name']} ({candidate['switch_ip']}): {uplink_count} uplink(s)")
    
    # 3. Floodlight Switch Ports
    print(f"\n  [3] Floodlight Switch Ports API")
    print(f"      GET {FLOODLIGHT_URL}/wm/core/switch/{{dpid}}/port/json")
    print(f"      Response: Puertos del switch seleccionado")
    print(f"      {'-'*76}")
    print(f"      Switch DPID: {anom['switch_dpid']}")
    print(f"      Puerto #{anom['port_num']} ({anom['port_name']}) es puerto de HOST")
    print(f"      (No está en enlaces inter-switch)")
    
    # Acción recomendada
    print(f"\n{'═'*80}")
    print(f"  ⚠️  ACCIÓN RECOMENDADA")
    print(f"{'═'*80}")
    print(f"  Instalar flow de bloqueo en:")
    print(f"  - Switch DPID: {anom['switch_dpid']}")
    print(f"  - Puerto:      {anom['port_num']}")
    print(f"  - Match:       src_ip={anom['src_ip']}, dst_ip={anom['dst_ip']}")
    print(f"  - Action:      DROP")
    
    print(f"\n{'─'*80}\n")


def monitor_loop(interval=5):
    """Loop principal"""
    print("="*100)
    print("  CAMPUS SENTINEL - Smart DDoS Monitor (Debug Mode)")
    print("  - Auto-discovery desde Floodlight")
    print("  - Filtrado automático de uplinks")
    print("  - Detección con debug completo del proceso")
    print("="*100)
    print()
    
    running, version = check_sflowrt()
    if not running:
        print("✗ sFlow-RT no responde")
        return
    
    print(f"✓ sFlow-RT: {version}")
    
    flows = check_flows()
    if not flows:
        print("✗ No hay flows")
        return
    
    print(f"✓ Flows: {len(flows)}")
    print()
    
    topology = TopologyManager(FLOODLIGHT_URL)
    topology.discover_topology()
    
    print(f"Filtros activos:")
    print(f"  - Red interna: {INTERNAL_NETWORK}")
    print(f"  - Red campus: {CAMPUS_NETWORK}")
    print(f"  - Estrategia: Uplinks → Distancia IP → Tráfico")
    print()
    
    iteration = 0
    
    try:
        while True:
            iteration += 1
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"\n{'═'*100}")
            print(f"  Iteración #{iteration} - {timestamp}")
            print(f"{'═'*100}")
            
            anomalies = analyze_anomalies(topology)
            
            if anomalies:
                for anom in anomalies:
                    display_attack_debug(anom, topology)
            else:
                print("\n✓ No se detectaron ataques externos\n")
            
            if iteration % 10 == 0:
                print("🔄 Actualizando topología...")
                topology.discover_topology()
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n\n✓ Monitor detenido por el usuario")


if __name__ == '__main__':
    monitor_loop(interval=5)
