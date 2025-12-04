#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sflow_monitor_smart_final.py
Monitor DDoS con mapeo correcto de ifIndex a Puerto OpenFlow
"""

import requests
import time
import ipaddress
from datetime import datetime

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

# Mapeo ifIndex (dataSource de sFlow) → Puerto OpenFlow
IFINDEX_TO_OFPORT = {
    '10.0.0.13': {  # SW3
        '3': '1',  # ens4
        '4': '2',  # ens5
        '5': '3',  # ens6 ← ATACANTE CONECTADO AQUÍ
        '6': '4',  # ens7
        '7': '5',  # ens8
        '8': '6',  # ens9
    },
    '10.0.0.14': {  # SW4
        '3': '1',  # ens4
        '4': '2',  # ens5
        '5': '3',  # ens6
        '6': '4',  # ens7
        '7': '5',  # ens8
    },
    # Agregar SW11 y SW12 cuando tengas sus datos
}

# Mapeo de interfaces
IFINDEX_TO_INTERFACE = {
    '10.0.0.13': {
        '3': 'ens4',
        '4': 'ens5',
        '5': 'ens6',
        '6': 'ens7',
        '7': 'ens8',
        '8': 'ens9',
    },
    '10.0.0.14': {
        '3': 'ens4',
        '4': 'ens5',
        '5': 'ens6',
        '6': 'ens7',
        '7': 'ens8',
    },
}


class TopologyManager:
    """Gestiona topología desde Floodlight"""
    
    def __init__(self, floodlight_url):
        self.floodlight_url = floodlight_url
        self.switches = {}
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
        print(f"  - Enlaces inter-switch: {len(self. inter_switch_ports)}")
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
                    
                    self. switches[dpid] = {
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
            r = requests.get(
                f"{self.floodlight_url}/wm/topology/links/json",
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
                    self. inter_switch_ports.add(f"{dst_switch}:{dst_port}")
                
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
    
    def get_ofport_from_ifindex(self, switch_ip, ifindex):
        """Convierte ifIndex (dataSource) a puerto OpenFlow"""
        return IFINDEX_TO_OFPORT.get(switch_ip, {}).get(str(ifindex), str(ifindex))
    
    def get_interface_name(self, switch_ip, ifindex):
        """Obtiene nombre de interfaz desde ifIndex"""
        return IFINDEX_TO_INTERFACE.get(switch_ip, {}).get(str(ifindex), f"if{ifindex}")


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
    """Filtra flows con debug detallado"""
    ingress_flows = []
    flows_by_pair = {}
    debug_info = {}
    
    for flow in flows:
        try:
            flow_key = flow. get('key', '')
            agent = flow.get('agent', '')
            dataSource = str(flow.get('dataSource', ''))
            
            parts = flow_key.split(',')
            if len(parts) < 2:
                continue
            
            src_ip = parts[0]
            dst_ip = parts[1]
            
            if not topology.is_host_port(agent, dataSource):
                continue
            
            if not is_external_attack(src_ip):
                continue
            
            pair_key = f"{src_ip},{dst_ip}"
            
            if pair_key not in flows_by_pair:
                flows_by_pair[pair_key] = []
                debug_info[pair_key] = []
            
            flows_by_pair[pair_key].append(flow)
        except:
            continue
    
    for pair_key, pair_flows in flows_by_pair.items():
        if not pair_flows:
            continue
        
        src_ip = pair_key.split(',')[0]
        
        candidates = []
        for flow in pair_flows:
            agent = flow.get('agent', '')
            dataSource = str(flow.get('dataSource', ''))
            value = float(flow.get('value', 0))
            
            uplinks = topology.count_uplinks(agent)
            distance = _calculate_ip_distance(agent, src_ip)
            ofport = topology.get_ofport_from_ifindex(agent, dataSource)
            iface = topology.get_interface_name(agent, dataSource)
            
            candidates.append({
                'flow': flow,
                'switch_ip': agent,
                'switch_name': topology.get_switch_name(agent),
                'ifindex': dataSource,
                'ofport': ofport,
                'interface': iface,
                'uplinks': uplinks,
                'distance': distance,
                'value': value
            })
        
        debug_info[pair_key] = candidates
        
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
                ofport = topology.get_ofport_from_ifindex(agent, dataSource)
                iface = topology.get_interface_name(agent, dataSource)
                
                pair_key = f"{src_ip},{dst_ip}"
                candidates_info = debug_info.get(pair_key, [])
                
                anomalies.append({
                    'type': 'EXTERNAL_ATTACK',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'value': value,
                    'switch_ip': agent,
                    'switch_name': topology.get_switch_name(agent),
                    'ifindex': dataSource,
                    'ofport': ofport,
                    'interface': iface,
                    'port_name': port_info['port_name'] if port_info else f"if{dataSource}",
                    'switch_dpid': port_info['switch_dpid'] if port_info else 'N/A',
                    'candidates': candidates_info,
                    'flow_key': flow_key
                })
        except:
            continue
    
    return anomalies


def display_attack_debug(anom, topology):
    """Muestra información detallada del ataque"""
    
    print(f"\n{'🚨'*40}")
    print(f"  ATAQUE DDoS DETECTADO")
    print(f"{'🚨'*40}")
    
    print(f"\n{'═'*80}")
    print(f"  📊 INFORMACIÓN DEL ATAQUE")
    print(f"{'═'*80}")
    print(f"  Atacante:       {anom['src_ip']} (RED EXTERNA)")
    print(f"  Víctima:        {anom['dst_ip']}")
    print(f"  Rate:           {anom['value']:,.0f} pps")
    print(f"  Flow Key:       {anom['flow_key']}")
    
    print(f"\n{'═'*80}")
    print(f"  ✅ INGRESS REAL IDENTIFICADO")
    print(f"{'═'*80}")
    print(f"  Switch:         {anom['switch_name']} ({anom['switch_ip']})")
    print(f"  Switch DPID:    {anom['switch_dpid']}")
    print(f"  ──────────────────────────────────────────")
    print(f"  ifIndex (sFlow):     {anom['ifindex']}")
    print(f"  Interfaz (Linux):    {anom['interface']}")
    print(f"  Puerto OpenFlow:     {anom['ofport']}")
    print(f"  ──────────────────────────────────────────")
    print(f"  Uplinks:        {topology.count_uplinks(anom['switch_ip'])}")
    
    if anom. get('candidates'):
        print(f"\n{'═'*80}")
        print(f"  🔍 PROCESO DE DECISIÓN")
        print(f"{'═'*80}")
        
        print(f"\n  {'Switch':<12} {'ifIndex':<9} {'Interfaz':<9} {'OF Port':<9} {'Uplinks':<9} {'Dist IP':<9} {'Tráfico':<12} {'Sel':<5}")
        print(f"  {'-'*12} {'-'*9} {'-'*9} {'-'*9} {'-'*9} {'-'*9} {'-'*12} {'-'*5}")
        
        sorted_candidates = sorted(
            anom['candidates'],
            key=lambda c: (c['uplinks'], c['distance'], -c['value'])
        )
        
        for candidate in sorted_candidates:
            is_selected = (candidate['switch_ip'] == anom['switch_ip'] and 
                          candidate['ifindex'] == anom['ifindex'])
            
            selected_mark = "✓" if is_selected else "✗"
            
            print(f"  {candidate['switch_name']:<12} "
                  f"{candidate['ifindex']:<9} "
                  f"{candidate['interface']:<9} "
                  f"{candidate['ofport']:<9} "
                  f"{candidate['uplinks']:<9} "
                  f"{candidate['distance']:<9} "
                  f"{candidate['value']:>10,.0f}  "
                  f"{selected_mark:<5}")
        
        print(f"\n{'─'*80}")
        print(f"  📋 CRITERIOS DE SELECCIÓN:")
        print(f"{'─'*80}")
        print(f"  1.  UPLINKS:      Menor número = Switch leaf")
        print(f"  2. DISTANCIA IP: Más cercano al atacante")
        print(f"  3. TRÁFICO:      Mayor valor (tiebreaker)")
        
        winner = sorted_candidates[0]
        print(f"\n  💡 SELECCIONADO: {winner['switch_name']}")
        print(f"     - Tiene {winner['uplinks']} uplink(s) (switch leaf)")
        print(f"     - Puerto OpenFlow {winner['ofport']} ({winner['interface']})")
    
    print(f"\n{'═'*80}")
    print(f"  🔌 DATOS DE APIs CONSULTADAS")
    print(f"{'═'*80}")
    
    print(f"\n  [1] sFlow-RT Active Flows")
    print(f"      GET {SFLOWRT_URL}/activeflows/ALL/ddos_frames/json? n=30")
    print(f"      ──────────────────────────────────────────")
    if anom.get('candidates'):
        for candidate in anom['candidates']:
            print(f"      Switch: {candidate['switch_ip']}")
            print(f"      dataSource (ifIndex): {candidate['ifindex']}")
            print(f"      value: {candidate['value']:.2f} pps")
            print()
    
    print(f"  [2] Floodlight Topology Links")
    print(f"      GET {FLOODLIGHT_URL}/wm/topology/links/json")
    print(f"      ──────────────────────────────────────────")
    for candidate in anom. get('candidates', []):
        print(f"      {candidate['switch_name']}: {candidate['uplinks']} uplink(s)")
    
    print(f"\n  [3] Mapeo Local ifIndex → Puerto OpenFlow")
    print(f"      IFINDEX_TO_OFPORT['{anom['switch_ip']}']['{anom['ifindex']}']")
    print(f"      ──────────────────────────────────────────")
    print(f"      ifIndex {anom['ifindex']} → Interfaz {anom['interface']}")
    print(f"      ifIndex {anom['ifindex']} → Puerto OpenFlow {anom['ofport']}")
    
    print(f"\n{'═'*80}")
    print(f"  ⚠️ ACCIÓN RECOMENDADA: INSTALAR FLOW DE BLOQUEO")
    print(f"{'═'*80}")
    print(f"  Switch DPID:    {anom['switch_dpid']}")
    print(f"  Puerto OpenFlow: {anom['ofport']}")
    print(f"  Match:          in_port={anom['ofport']}, nw_src={anom['src_ip']}, nw_dst={anom['dst_ip']}")
    print(f"  Action:         DROP")
    print(f"\n  Comando de ejemplo:")
    print(f"  curl -X POST {FLOODLIGHT_URL}/wm/staticflowpusher/json \\")
    print(f"    -d '{{")
    print(f"      \"switch\":\"{anom['switch_dpid']}\",")
    print(f"      \"name\":\"block_{anom['src_ip']}\",")
    print(f"      \"in_port\":\"{anom['ofport']}\",")
    print(f"      \"nw_src\":\"{anom['src_ip']}\",")
    print(f"      \"nw_dst\":\"{anom['dst_ip']}\",")
    print(f"      \"priority\":\"32768\",")
    print(f"      \"active\":\"true\"")
    print(f"    }}'")
    
    print(f"\n{'─'*80}\n")


def monitor_loop(interval=5):
    """Loop principal"""
    print("="*100)
    print("  CAMPUS SENTINEL - Smart DDoS Monitor (v4 - Con Mapeo OpenFlow)")
    print("  - Auto-discovery desde Floodlight")
    print("  - Mapeo ifIndex → Puerto OpenFlow")
    print("  - Debug completo del proceso de decisión")
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
    
    print(f"Configuración:")
    print(f"  - Red interna: {INTERNAL_NETWORK}")
    print(f"  - Red campus: {CAMPUS_NETWORK}")
    print(f"  - Mapeo ifIndex→OF disponible para:")
    for switch_ip in IFINDEX_TO_OFPORT. keys():
        print(f"    • {switch_ip}")
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
        print("\n\n✓ Monitor detenido")


if __name__ == '__main__':
    monitor_loop(interval=5)
