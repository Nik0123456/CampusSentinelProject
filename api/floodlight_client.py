#!/usr/bin/python3

import requests

class FloodlightClient:
    def __init__(self, base_url="http://10.20.12.225:8080"):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Content-type": "application/json", "Accept": "application/json"}

    def _get(self, path, params=None):
        try:
            r = requests.get(f"{self.base_url}{path}", headers=self.headers, params=params, timeout=5)
            r.raise_for_status()
            t = r.text.strip()
            return None if not t else r.json()
        except requests.RequestException as e:
            print(f"GET {path} fallo: {e}")
        except ValueError:
            print(f"JSON inválido en {path}")
        return None

    def _post(self, path, json_data):
        try:
            r = requests.post(f"{self.base_url}{path}", headers=self.headers, json=json_data, timeout=5)
            r.raise_for_status()
            return True
        except requests.RequestException as e:
            print(f"POST {path} fallo: {e}")
            return False

    def _delete(self, path, json_data=None):
        try:
            r = requests.delete(f"{self.base_url}{path}", headers=self.headers, json=json_data, timeout=5)
            r.raise_for_status()
            return True
        except requests.RequestException as e:
            print(f"DELETE {path} fallo: {e}")
            return False

    def get_switches(self):
        return self._get("/wm/core/controller/switches/json") or []

    def get_attachment_points(self, mac, first_only=True):
        if not mac:
            return None
        data = self._get("/wm/device/", params={"mac": mac.lower()})
        if not isinstance(data, list):
            return None
        aps = []
        for device in data:
            for ap in device.get("attachmentPoint", []) if isinstance(device, dict) else []:
                if not isinstance(ap, dict):
                    continue
                sw = ap.get('switchDPID')
                port = ap.get('port')
                aps.append({'DPID' : sw, 'port' : port})

        if not aps:
            return None
        if first_only:
            return aps[0]
        
        results, seen = [], set()
        for a in aps:
            key = (a.get('DPID'), a.get('port'))
            if key not in seen:
                seen.add(key)
                results.append(a)
        return results

    def get_route(self, src_dpid, src_port, dst_dpid, dst_port):
        if not (src_dpid and dst_dpid):
            return []
        raw = self._get(f"/wm/topology/route/{src_dpid}/{src_port}/{dst_dpid}/{dst_port}/json")
    
        if not isinstance(raw, list):
            return []
        route = []
        for hop in raw:
            if isinstance(hop, dict):
                sw = hop.get('switch') #DPID del switch del salto
                port = hop.get('port', {}).get('portNumber') #Puerto del switch del salto
                if sw and isinstance(port, int):
                    if not route or route[-1] != (sw, port): #Evita redundancia de un mismo switch:port
                        route.append({"switch": sw, "port": port})
        return route
    
    def build_route(self, route):
        # Convierte secuencia [{switch, port}, ...] a saltos por switch con in_port/out_port
        if not isinstance(route, list) or len(route) < 2:
            return []
        hops = []
        for i in range(len(route) - 1):
            a, b = route[i], route[i+1]
            if a.get('switch') == b.get('switch'): #Mismo switch DPID, diferente puerto de entrada y salida
                hops.append({
                    'switch': a['switch'],
                    'in_port': a['port'],
                    'out_port': b['port'],
                })
        return hops

    # Consultas adicionales de dispositivos
    def get_attachment_points_by_ip(self, ip, first_only=True):
        if not ip:
            return None
        data = self._get("/wm/device/", params={"ipv4": ip})
        if not isinstance(data, list):
            return None
        aps = []
        for device in data:
            for ap in device.get("attachmentPoint", []) if isinstance(device, dict) else []:
                if not isinstance(ap, dict):
                    continue
                sw = ap.get('switchDPID')
                port = ap.get('port')
                aps.append({'DPID': sw, 'port': port})
        if not aps:
            return None
        if first_only:
            return aps[0]
        results, seen = [], set()
        for a in aps:
            key = (a.get('DPID'), a.get('port'))
            if key not in seen:
                seen.add(key)
                results.append(a)
        return results

    def get_device_ipv4s(self, mac=None, ip=None):
        params = {}
        if mac:
            params['mac'] = mac.lower()
        if ip:
            params['ipv4'] = ip
        if not params:
            return []
        data = self._get("/wm/device/", params=params)
        if not isinstance(data, list):
            return []
        ips = []
        for device in data:
            if isinstance(device, dict):
                for a in device.get('ipv4', []) or []:
                    if a and a not in ips:
                        ips.append(a)
        return ips

    # Static Flow Entry Pusher helpers
    def push_flow(self, flow_def: dict):
        return self._post("/wm/staticflowpusher/json", flow_def)

    def delete_flow(self, name: str):
        return self._delete("/wm/staticflowpusher/json", {"name": name})

    def format_service_flow(self, name, switch, in_port, out_port, eth_type="0x0800", ipv4_src=None, ipv4_dst=None, ip_proto=None, l4_field=None, l4_value=None, priority=32768):
        flow = {
            "switch": str(switch),
            "name": str(name),
            "cookie": "0",
            "priority": str(priority),
            "in_port": str(in_port),
            "eth_type": eth_type,
            "active": "true",
            "actions": f"output={out_port}",
        }
        if ipv4_src:
            flow["ipv4_src"] = str(ipv4_src)
        if ipv4_dst:
            flow["ipv4_dst"] = str(ipv4_dst)
        if ip_proto is not None:
            flow["ip_proto"] = str(ip_proto)
        if l4_field and l4_value is not None:
            flow[str(l4_field)] = str(l4_value)
        return flow

    def format_arp_flow(self, name, switch, in_port, out_port, priority=10000):
        return {
            "switch": str(switch),
            "name": str(name),
            "cookie": "0",
            "priority": str(priority),
            "in_port": str(in_port),
            "eth_type": "0x0806",  # ARP
            "active": "true",
            "actions": f"output={out_port}",
        }
        

