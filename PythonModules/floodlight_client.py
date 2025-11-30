#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cliente de Floodlight adaptado de TEL354_LAB4_20223209
Proporciona métodos para interactuar con la API REST de Floodlight
"""
import requests
import logging

class FloodlightClient:
    def __init__(self, base_url="http://127.0.0.1:8080"):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Content-type": "application/json", "Accept": "application/json"}
        logging.info(f"FloodlightClient inicializado: {self.base_url}")

    def _get(self, path, params=None):
        """Realiza petición GET a Floodlight"""
        try:
            r = requests.get(f"{self.base_url}{path}", headers=self.headers, params=params, timeout=5)
            r.raise_for_status()
            text = r.text.strip()
            return None if not text else r.json()
        except requests.RequestException as e:
            logging.error(f"GET {path} falló: {e}")
        except ValueError:
            logging.error(f"JSON inválido en {path}")
        return None

    def _post(self, path, json_data):
        """Realiza petición POST a Floodlight"""
        try:
            r = requests.post(f"{self.base_url}{path}", headers=self.headers, json=json_data, timeout=5)
            r.raise_for_status()
            return True
        except requests.RequestException as e:
            logging.error(f"POST {path} falló: {e}")
            return False

    def _delete(self, path, json_data=None):
        """Realiza petición DELETE a Floodlight"""
        try:
            r = requests.delete(f"{self.base_url}{path}", headers=self.headers, json=json_data, timeout=5)
            r.raise_for_status()
            return True
        except requests.RequestException as e:
            logging.error(f"DELETE {path} falló: {e}")
            return False

    # ========================================
    # TOPOLOGÍA Y DISPOSITIVOS
    # ========================================
    
    def get_switches(self):
        """Obtiene lista de switches conectados"""
        return self._get("/wm/core/controller/switches/json") or []

    def get_attachment_points(self, mac, first_only=True):
        """Obtiene puntos de conexión (DPID + puerto) de un dispositivo por MAC
        
        Args:
            mac: Dirección MAC del dispositivo
            first_only: Si True, retorna solo el primer AP encontrado
            
        Returns:
            dict con 'DPID' y 'port', o lista de dicts si first_only=False
        """
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
                if sw and port:
                    aps.append({'DPID': sw, 'port': port})

        if not aps:
            return None
        
        if first_only:
            return aps[0]
        
        # Eliminar duplicados
        results, seen = [], set()
        for a in aps:
            key = (a.get('DPID'), a.get('port'))
            if key not in seen:
                seen.add(key)
                results.append(a)
        return results

    def get_attachment_points_by_ip(self, ip, first_only=True):
        """Obtiene puntos de conexión de un dispositivo por IP"""
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
                if sw and port:
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
        """Obtiene direcciones IPv4 de un dispositivo
        
        Args:
            mac: Dirección MAC para buscar
            ip: Dirección IP para buscar
            
        Returns:
            Lista de IPs asociadas al dispositivo
        """
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
                for addr in device.get('ipv4', []) or []:
                    if addr and addr not in ips:
                        ips.append(addr)
        return ips

    # ========================================
    # RUTEO
    # ========================================
    
    def get_route_direct(self, src_dpid, src_port, dst_dpid, dst_port):
        """Obtiene ruta entre dos puntos usando directamente la API de topología de Floodlight
        
        NO usa get_attachment_points, asume que los DPIDs y puertos vienen de la BD.
        API: /wm/topology/route/<src-dpid>/<src-port>/<dst-dpid>/<dst-port>/json
        
        Args:
            src_dpid: DPID del switch origen (formato: 00:00:xx:xx:xx:xx:xx:xx)
            src_port: Puerto origen (int)
            dst_dpid: DPID del switch destino (formato: 00:00:xx:xx:xx:xx:xx:xx)
            dst_port: Puerto destino (int)
            
        Returns:
            Lista de dicts con 'switch' y 'port' representando la ruta
        """
        if not (src_dpid and dst_dpid):
            logging.error("get_route_direct: DPID origen o destino faltante")
            return []
        
        # Llamar API 
        api_url = f"/wm/topology/route/{src_dpid}/{src_port}/{dst_dpid}/{dst_port}/json"
        logging.debug(f"get_route_direct: Consultando API: {api_url}")
        raw = self._get(api_url)
        
        if not isinstance(raw, list):
            logging.warning(f"get_route_direct: Respuesta inválida de Floodlight. Tipo: {type(raw)}, Contenido: {raw}")
            return []
        
        route = []
        for hop in raw:
            if isinstance(hop, dict):
                sw = hop.get('switch') #DPID del switch del salto
                port = hop.get('port', {}).get('portNumber') #Puerto del switch del salto
                
                if sw and isinstance(port, int):
                    # Evitar duplicados consecutivos
                    if not route or route[-1] != (sw, port): #Evita redundancia de un mismo switch:port
                        route.append({"switch": sw, "port": port})

        logging.debug(f"get_route_direct: Ruta obtenida con {len(route)} hops")
        return route
    
    def get_route(self, src_dpid, src_port, dst_dpid, dst_port):
        """DEPRECATED: Usar get_route_direct() en su lugar
        
        Obtiene ruta entre dos puntos usando la API de Floodlight
        Mantener por compatibilidad con código antiguo
        """
        return self.get_route_direct(src_dpid, src_port, dst_dpid, dst_port)

    def build_route(self, route):
        """Convierte secuencia [{switch, port}, ...] a saltos por switch con in_port/out_port
        
        Args:
            route: Lista de dicts con 'switch' y 'port'
            
        Returns:
            Lista de hops con 'switch', 'in_port', 'out_port'
        """
        if not isinstance(route, list) or len(route) < 2:
            return []
        
        hops = []
        for i in range(len(route) - 1):
            a, b = route[i], route[i+1]
            # Mismo switch, diferente puerto = hop interno
            if a.get('switch') == b.get('switch'):
                hops.append({
                    'switch': a['switch'],
                    'in_port': a['port'],
                    'out_port': b['port'],
                })
        
        return hops

    # ========================================
    # FLOWS (Static Flow Pusher)
    # ========================================
    
    def push_flow(self, flow_def):
        """Instala un flow entry en un switch
        
        Args:
            flow_def: Diccionario con definición del flow
            
        Returns:
            True si exitoso, False en caso contrario
        """
        return self._post("/wm/staticflowpusher/json", flow_def)

    def delete_flow(self, name, switch=None):
        """Elimina un flow entry por nombre
        
        Args:
            name: Nombre del flow
            switch: DPID del switch (opcional)
            
        Returns:
            True si exitoso, False en caso contrario
        """
        data = {"name": name}
        if switch:
            data["switch"] = switch
        return self._delete("/wm/staticflowpusher/json", data)

    def format_permission_flow(self, name, switch, in_port, out_port, 
                              ipv4_src=None, ipv4_dst=None, 
                              ip_proto=None, tp_dst=None,
                              priority=100, idle_timeout=14400):
        """Formatea un flow para Table 2 (Permisos)
        
        Args:
            name: Nombre único del flow
            switch: DPID del switch
            in_port: Puerto de entrada
            out_port: Puerto de salida
            ipv4_src: IP origen (opcional)
            ipv4_dst: IP destino (opcional)
            ip_proto: Protocolo IP (6=TCP, 17=UDP)
            tp_dst: Puerto de transporte destino
            priority: Prioridad del flow (default 100)
            idle_timeout: Timeout de inactividad en segundos
            
        Returns:
            dict con definición del flow
        """
        flow = {
            "switch": str(switch),
            "name": str(name),
            "table": "2",  # Table 2: Permisos
            "cookie": "0",
            "priority": str(priority),
            "in_port": str(in_port),
            "eth_type": "0x0800",  # IPv4
            "active": "true",
            "idle_timeout": str(idle_timeout),
            "actions": f"output={out_port}",
        }
        
        if ipv4_src:
            flow["ipv4_src"] = str(ipv4_src)
        if ipv4_dst:
            flow["ipv4_dst"] = str(ipv4_dst)
        if ip_proto is not None:
            flow["ip_proto"] = str(ip_proto)
        if tp_dst is not None:
            flow["tcp_dst" if ip_proto == 6 else "udp_dst"] = str(tp_dst)
        
        return flow

    def format_return_flow(self, name, switch, in_port, out_port,
                          ipv4_src=None, ipv4_dst=None,
                          ip_proto=None, tp_src=None,
                          priority=100, idle_timeout=14400):
        """Formatea un flow de retorno (servidor → usuario)
        
        Similar a format_permission_flow pero match en puerto origen
        """
        flow = {
            "switch": str(switch),
            "name": str(name),
            "table": "2",
            "cookie": "0",
            "priority": str(priority),
            "in_port": str(in_port),
            "eth_type": "0x0800",
            "active": "true",
            "idle_timeout": str(idle_timeout),
            "actions": f"output={out_port}",
        }
        
        if ipv4_src:
            flow["ipv4_src"] = str(ipv4_src)
        if ipv4_dst:
            flow["ipv4_dst"] = str(ipv4_dst)
        if ip_proto is not None:
            flow["ip_proto"] = str(ip_proto)
        if tp_src is not None:
            flow["tcp_src" if ip_proto == 6 else "udp_src"] = str(tp_src)
        
        return flow
