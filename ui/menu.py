from data.data_manager import DataManager
from api.floodlight_client import FloodlightClient
from core.models import Alumno, Curso, Servidor

class Menu:

    def __init__(self):
        self.floodlight_client = FloodlightClient("http://10.20.12.225:8080")
        self.alumnos = []
        self.cursos = []
        self.servidores = []
        self.data_manager = DataManager()

    def mostrar_menu(self):
        print("###############################################")
        print(" Network Policy manager de la PUCP")
        print("###############################################\n")
        print("Seleccione una opción:\n")
        print("1) Importar")
        print("2) Exportar")
        print("3) Cursos")
        print("4) Alumnos")
        print("5) Servidores")
        print("6) Políticas")
        print("7) Conexiones")
        print("8) Salir")
        return input(">>> ")

    def opcion_importar(self):
        ruta = input("Ingrese la ruta del archivo YAML a importar: ")
        
        try:
            data = self.data_manager.load_yaml(ruta)
            self.alumnos = [Alumno.from_dict(alumno) for alumno in data.get("alumnos", [])]
            self.cursos = [Curso.from_dict(curso) for curso in data.get("cursos", [])]
            self.servidores = [Servidor.from_dict(servidor) for servidor in data.get("servidores", [])]
            
            if self.cursos and self.servidores:
                nombres_inexistentes = set()
                for curso in self.cursos:
                    perdidos = curso.resolver_referencias_servidores(self.servidores)
                    for n in perdidos:
                        nombres_inexistentes.add(n)
                if nombres_inexistentes:
                    print("Advertencia: políticas con servidores no encontrados:")
                    for n in nombres_inexistentes:
                        print(f" - {n}")
            
            print("\nDatos importados correctamente")
        except Exception as e:
            print(f"No se pudo cargar el archivo: {e}\n")
            return
        

    def opcion_exportar(self):
        ruta = input("Ingrese la ruta donde desea exportar el archivo YAML: ")
        data = {
            "alumnos": [a.to_dict() for a in self.alumnos],
            "cursos": [c.to_dict() for c in self.cursos],
            "servidores": [s.to_dict() for s in self.servidores],
        }

        try:
            self.data_manager.export_yaml(ruta, data)
            print("\nDatos exportados correctamente")
        except Exception as e:
            print(f"No se pudieron exportar los datos: {e}\n")

    def ejecutar(self):
        while True:
            opcion = self.mostrar_menu()
            if opcion == "1":
                self.opcion_importar()
            elif opcion == "2":
                self.opcion_exportar()
            elif opcion == "3":
                self.menu_cursos()
            elif opcion == "4":
                self.menu_alumnos()
            elif opcion == "5":
                self.menu_servidores()
            elif opcion == "6":
                print("Gestión de Políticas - Funcionalidad en desarrollo.\n")
            elif opcion == "7":
                self.menu_conexiones()
            elif opcion == "8":
                print("Saliendo del programa.")
                break
            else:
                print("Opción no válida, por favor intente de nuevo.\n")

    # =======================
    # Cursos - Submenú (opción 3)
    # =======================
    def menu_cursos(self):
        while True:
            print("\n--- Gestión de Cursos ---")
            print("1) Listar")
            print("2) Mostrar detalle")
            print("3) Actualizar (agregar/eliminar alumno)")
            print("4) Volver")
            opcion = input(">>> ")

            if opcion == "1":
                self.cursos_listar()
            elif opcion == "2":
                self.cursos_mostrar_detalle()
            elif opcion == "3":
                self.cursos_actualizar()
            elif opcion == "4":
                break
            else:
                print("Opción no válida.\n")

    # Helpers
    def _buscar_curso_por_codigo(self, codigo_curso: str):
        for c in self.cursos:
            # c.codigo suele ser str (p.ej. "TEL354")
            if str(getattr(c, 'codigo', '')).strip().lower() == str(codigo_curso).strip().lower():
                return c
        return None

    def _buscar_alumno_por_codigo(self, codigo_alumno):
        # códigos de alumno suelen ser int; aceptamos str también
        for a in self.alumnos:
            if str(getattr(a, 'codigo', '')).strip() == str(codigo_alumno).strip():
                return a
        return None

    def _extraer_codigos_alumnos_de_curso(self, curso: Curso):
        codigos = []
        for item in getattr(curso, 'alumnos', []) or []:
            if isinstance(item, Alumno):
                codigos.append(item.codigo)
            else:
                codigos.append(item)
        return codigos

    def _buscar_servidor_por_nombre(self, nombre_servidor: str):
        for s in self.servidores:
            if str(getattr(s, 'nombre', '')).strip().lower() == str(nombre_servidor).strip().lower():
                return s
        return None

    def _alumno_autorizado(self, codigo_alumno, nombre_servidor, nombre_servicio):
        # Regla: curso con estado DICTANDO y que tenga servidor y servicio en su política
        for c in self.cursos:
            if str(getattr(c, 'estado', '')).strip().upper() != 'DICTANDO':
                continue
            # alumnos puede contener códigos o instancias
            cods = self._extraer_codigos_alumnos_de_curso(c)
            if str(codigo_alumno) not in {str(x) for x in cods}:
                continue
            for p in getattr(c, 'servidores', []) or []:
                nombre = p.get('nombre') if isinstance(p, dict) else getattr(p, 'nombre', None)
                servs = p.get('servicios_permitidos', []) if isinstance(p, dict) else getattr(p, 'servicios_permitidos', [])
                if nombre and servs and str(nombre).lower() == str(nombre_servidor).lower() and any(str(s).lower()==str(nombre_servicio).lower() for s in servs):
                    return True
        return False

    # Subopción: Listar cursos
    def cursos_listar(self):
        if not self.cursos:
            print("No hay cursos cargados. Importe datos primero.")
            return
        print("\nCursos disponibles:")
        for idx, c in enumerate(self.cursos, start=1):
            print(f"{idx}) {getattr(c, 'codigo', '')} - {getattr(c, 'nombre', '')} (Estado: {getattr(c, 'estado', '')})")

    # Subopción: Mostrar detalle de un curso
    def cursos_mostrar_detalle(self):
        if not self.cursos:
            print("No hay cursos cargados. Importe datos primero.")
            return
        codigo_curso = input("Ingrese código del curso: ").strip()
        curso = self._buscar_curso_por_codigo(codigo_curso)
        if not curso:
            print("Curso no encontrado.")
            return

        print("\nDetalle del curso:")
        print(f"Nombre: {getattr(curso, 'nombre', '')}")
        print(f"Código: {getattr(curso, 'codigo', '')}")
        print(f"Estado: {getattr(curso, 'estado', '')}")

        # Alumnos
        codigos = self._extraer_codigos_alumnos_de_curso(curso)
        print("\nAlumnos:")
        if not codigos:
            print("  (sin alumnos)")
        else:
            for cod in codigos:
                al = self._buscar_alumno_por_codigo(cod)
                if al:
                    print(f"  - {al.codigo} | {al.nombre} | {al.mac}")
                else:
                    print(f"  - {cod} (no encontrado en catálogo de alumnos)")

        # Políticas de servidores (si existen)
        politicas = getattr(curso, 'servidores', []) or []
        if politicas:
            print("\nPolíticas de servidores:")
            for p in politicas:
                if isinstance(p, dict):
                    nombre = p.get('nombre')
                    servs = p.get('servicios_permitidos', [])
                    print(f"  - {nombre}: {', '.join(servs) if servs else '(sin servicios)'}")
                else:
                    # Si fuese una instancia con to_dict
                    nombre = getattr(p, 'nombre', None)
                    servs = getattr(p, 'servicios_permitidos', [])
                    if nombre is not None:
                        print(f"  - {nombre}: {', '.join(servs) if servs else '(sin servicios)'}")

    # Subopción: Actualizar (agregar/eliminar alumno)
    def cursos_actualizar(self):
        if not self.cursos:
            print("No hay cursos cargados. Importe datos primero.")
            return
        print("\nActualizar curso:")
        print("1) Agregar alumno a curso")
        print("2) Eliminar alumno de curso")
        print("3) Volver")
        opcion = input(">>> ").strip()

        if opcion == "1":
            codigo_curso = input("Código del curso: ").strip()
            curso = self._buscar_curso_por_codigo(codigo_curso)
            if not curso:
                print("Curso no encontrado.")
                return
            codigo_alumno = input("Código del alumno a agregar: ").strip()
            alumno = self._buscar_alumno_por_codigo(codigo_alumno)
            if not alumno:
                print("Alumno no encontrado en el catálogo. Primero créelo en 'Alumnos > Crear'.")
                return
            # Normaliza a códigos dentro del curso
            codigos = self._extraer_codigos_alumnos_de_curso(curso)
            if str(alumno.codigo) in {str(c) for c in codigos}:
                print("El alumno ya está en el curso.")
                return
            # Agrega el código para mantener compatibilidad con exportación
            curso.alumnos.append(alumno.codigo)
            print("Alumno agregado al curso.")

        elif opcion == "2":
            codigo_curso = input("Código del curso: ").strip()
            curso = self._buscar_curso_por_codigo(codigo_curso)
            if not curso:
                print("Curso no encontrado.")
                return
            codigo_alumno = input("Código del alumno a eliminar: ").strip()
            # Elimina por coincidencia de código, tolerando ints/strs y objetos
            antes = len(curso.alumnos)
            nuevos = []
            for item in curso.alumnos:
                cod_item = item.codigo if isinstance(item, Alumno) else item
                if str(cod_item).strip() != str(codigo_alumno).strip():
                    nuevos.append(item)
            curso.alumnos = nuevos
            if len(curso.alumnos) < antes:
                print("Alumno eliminado del curso.")
            else:
                print("El alumno no estaba inscrito en el curso.")

        elif opcion == "3":
            return
        else:
            print("Opción no válida.")

    # =======================
    # Alumnos - Submenú (opción 4)
    # =======================
    def menu_alumnos(self):
        while True:
            print("\n--- Gestión de Alumnos ---")
            print("1) Listar")
            print("2) Mostrar detalle")
            print("3) Crear")
            print("4) Volver")
            opcion = input(">>> ").strip()

            if opcion == "1":
                self.alumnos_listar()
            elif opcion == "2":
                self.alumnos_mostrar_detalle()
            elif opcion == "3":
                self.alumnos_crear()
            elif opcion == "4":
                break
            else:
                print("Opción no válida.\n")

    def alumnos_listar(self):
        if not self.alumnos:
            print("No hay alumnos cargados. Importe datos primero.")
            return
        print("\nFiltros (deje vacío para omitir):")
        f_codigo = input("- Código (coincidencia exacta): ").strip()
        f_nombre = input("- Nombre contiene: ").strip().lower()
        f_mac = input("- MAC contiene: ").strip().lower()

        def _match(a: Alumno):
            ok = True
            if f_codigo:
                ok = ok and str(a.codigo).strip() == f_codigo
            if f_nombre:
                ok = ok and f_nombre in str(a.nombre).lower()
            if f_mac:
                ok = ok and f_mac in str(a.mac).lower()
            return ok

        filtrados = [a for a in self.alumnos if _match(a)]
        if not filtrados:
            print("No se encontraron alumnos con esos filtros.")
            return
        print("\nAlumnos:")
        for idx, a in enumerate(filtrados, start=1):
            print(f"{idx}) {a.codigo} | {a.nombre} | {a.mac}")

    def alumnos_mostrar_detalle(self):
        if not self.alumnos:
            print("No hay alumnos cargados. Importe datos primero.")
            return
        codigo = input("Ingrese el código del alumno: ").strip()
        alumno = self._buscar_alumno_por_codigo(codigo)
        if not alumno:
            print("Alumno no encontrado.")
            return
        print("\nDetalle del Alumno:")
        print(f"Código: {alumno.codigo}")
        print(f"Nombre: {alumno.nombre}")
        print(f"MAC: {alumno.mac}")

    def alumnos_crear(self):
        print("\nCrear alumno:")
        codigo_in = input("Código: ").strip()
        # Validar duplicado
        if self._buscar_alumno_por_codigo(codigo_in):
            print("Ya existe un alumno con ese código.")
            return
        nombre = input("Nombre: ").strip()
        mac = input("MAC address (formato XX:XX:XX:XX:XX:XX): ").strip()
        # intenta castear el código a int si corresponde
        try:
            codigo_cast = int(codigo_in)
        except ValueError:
            codigo_cast = codigo_in
        nuevo = Alumno(nombre=nombre, codigo=codigo_cast, mac=mac)
        self.alumnos.append(nuevo)
        print("Alumno creado y agregado al catálogo.")

    # =======================
    # Servidores - Submenú (opción 5)
    # =======================
    def menu_servidores(self):
        while True:
            print("\n--- Gestión de Servidores ---")
            print("1) Listar")
            print("2) Mostrar detalle")
            print("3) Volver")
            opcion = input(">>> ").strip()

            if opcion == "1":
                self.servidores_listar()
            elif opcion == "2":
                self.servidores_mostrar_detalle()
            elif opcion == "3":
                break
            else:
                print("Opción no válida.\n")

    def servidores_listar(self):
        if not self.servidores:
            print("No hay servidores cargados. Importe datos primero.")
            return
        print("\nServidores:")
        for idx, s in enumerate(self.servidores, start=1):
            print(f"{idx}) {s.nombre} | {s.ip}")

    def servidores_mostrar_detalle(self):
        if not self.servidores:
            print("No hay servidores cargados. Importe datos primero.")
            return
        nombre = input("Ingrese el nombre del servidor: ").strip()
        servidor = self._buscar_servidor_por_nombre(nombre)
        if not servidor:
            print("Servidor no encontrado.")
            return
        print("\nDetalle del Servidor:")
        print(f"Nombre: {servidor.nombre}")
        print(f"IP: {servidor.ip}")
        print("Servicios:")
        servicios = getattr(servidor, 'servicios', []) or []
        if not servicios:
            print("  (sin servicios)")
        else:
            for sv in servicios:
                # sv es instancia de Servicio por normalización
                nombre_sv = getattr(sv, 'nombre', None)
                proto_sv = getattr(sv, 'protocolo', None)
                puerto_sv = getattr(sv, 'puerto', None)
                print(f"  - {nombre_sv} | {proto_sv} | {puerto_sv}")

    # =======================
    # Conexiones - Submenú (opción 7)
    # =======================
    def menu_conexiones(self):
        # almacenamiento en memoria de conexiones creadas: handler -> list of flow names
        if not hasattr(self, 'conexiones'):
            self.conexiones = {}
        while True:
            print("\n--- Gestión de Conexiones ---")
            print("1) Crear")
            print("2) Listar")
            print("3) Borrar")
            print("4) Volver")
            op = input(">>> ").strip()

            if op == '1':
                self.conn_crear()
            elif op == '2':
                self.conn_listar()
            elif op == '3':
                self.conn_borrar()
            elif op == '4':
                break
            else:
                print("Opción no válida.")

    def conn_listar(self):
        if not getattr(self, 'conexiones', {}):
            print("No hay conexiones registradas.")
            return
        print("\nConexiones:")
        for handler, flows in self.conexiones.items():
            print(f"- Handler: {handler} ({len(flows)} flows)")

    def conn_borrar(self):
        handler = input("Ingrese handler de la conexión a borrar: ").strip()
        flows = getattr(self, 'conexiones', {}).get(handler)
        if not flows:
            print("Handler no encontrado.")
            return
        ok_all = True
        for name in flows:
            if not self.floodlight_client.delete_flow(name):
                ok_all = False
        if ok_all:
            print("Conexión eliminada.")
            self.conexiones.pop(handler, None)
        else:
            print("Algunos flows no pudieron eliminarse. Revise el controlador.")

    def conn_crear(self):
        # Entrada de datos
        codigo_alumno = input("Código de alumno: ").strip()
        nombre_servidor = input("Nombre del servidor: ").strip()
        nombre_servicio = input("Nombre del servicio: ").strip()

        # Validar autorización
        if not self._alumno_autorizado(codigo_alumno, nombre_servidor, nombre_servicio):
            print("Alumno no autorizado para este servicio/servidor.")
            return

        alumno = self._buscar_alumno_por_codigo(codigo_alumno)
        servidor = self._buscar_servidor_por_nombre(nombre_servidor)
        if not alumno or not servidor:
            print("Alumno o servidor no encontrado.")
            return

        # ------------- Datos para Binding L3 -------------

        # Para el alumno tomamos la primera IP conocida por Floodlight de acuerdo a la MAC 
        ips_alumno = self.floodlight_client.get_device_ipv4s(mac=alumno.mac)
        if not ips_alumno:
            print("No se encontró IP del alumno en el controlador.")
            return
        ip_alumno = ips_alumno[0]

        # Para el servidor, tomamos la IP desde su atributo ip
        ip_servidor = getattr(servidor, 'ip', None)
        if not ip_servidor:
            print("El servidor no tiene IP configurada.")
            return
        
        # ------------- Datos para Binding L1 -------------

        # Obtener attachment points (DPID/puerto) alumno y servidor
        ap_alumno = self.floodlight_client.get_attachment_points(mac=alumno.mac, first_only=True)
        ap_srv = self.floodlight_client.get_attachment_points_by_ip(ip_servidor, first_only=True)

        if not ap_alumno or not ap_srv:
            print("No se pudo determinar los puntos de conexión en la red.")
            return

        # Ruta entre host y servidor
        route = self.floodlight_client.get_route(ap_alumno['DPID'], ap_alumno['port'], ap_srv['DPID'], ap_srv['port'])
        hops = self.floodlight_client.build_route(route)

        if not hops:
            print("No se pudo construir ruta entre el alumno y el servidor.")
            return

        # ------------- Datos para Binding L4 -------------

        # Buscar el puerto/protocolo por nombre del servicio en el servidor (Binding L4)
        svc = None
        for s in getattr(servidor, 'servicios', []) or []:
            if str(getattr(s, 'nombre', '')).lower() == nombre_servicio.lower():
                svc = s
                break
        if not svc:
            print("Servicio no encontrado en el servidor.")
            return
        proto = str(getattr(svc, 'protocolo', 'TCP')).upper()
        puerto = getattr(svc, 'puerto', None)
        if not puerto:
            print("El servicio no define un puerto L4.")
            return
        ip_proto = 6 if proto == 'TCP' else (17 if proto == 'UDP' else None)

        # ------------- Crear flows para cada hop en ambos sentidos + ARP -------------
        # Handler generado
        handler = f"conn-{codigo_alumno}-{nombre_servidor}-{nombre_servicio}"
        flow_names = []

        def push(flow):
            name = flow.get('name')
            if not name:
                return False
            ok = self.floodlight_client.push_flow(flow)
            if ok:
                flow_names.append(name)
            return ok

        # Flujos IP/puerto alumno->servidor y servidor->alumno
        for idx, h in enumerate(hops):
            sw, in_p, out_p = h['switch'], h['in_port'], h['out_port']
            # sentido alumno -> servidor
            l4_field_cliente = 'tcp_dst' if proto == 'TCP' else ('udp_dst' if proto == 'UDP' else None)
            f1 = self.floodlight_client.format_service_flow(
                name=f"{handler}-a2s-{idx}",
                switch=sw,
                in_port=in_p,
                out_port=out_p,
                ipv4_src=f"{ip_alumno}/32",
                ipv4_dst=f"{ip_servidor}/32",
                ip_proto=ip_proto,
                l4_field=l4_field_cliente, #Puerto destino
                l4_value=puerto,
                priority=40000,
            )
            # sentido servidor -> alumno
            l4_field_servidor = 'tcp_src' if proto == 'TCP' else ('udp_src' if proto == 'UDP' else None)
            f2 = self.floodlight_client.format_service_flow(
                name=f"{handler}-s2a-{idx}",
                switch=sw,
                in_port=out_p,
                out_port=in_p,
                ipv4_src=f"{ip_servidor}/32",
                ipv4_dst=f"{ip_alumno}/32",
                ip_proto=ip_proto,
                l4_field=l4_field_servidor, #Puerto origen
                l4_value=puerto,
                priority=40000,
            )
            if not (push(f1) and push(f2)):
                print("Error creando flows L3/L4 en la ruta.")
                return

            # Flujos ARP (bidireccional) sin match de L4
            fa1 = self.floodlight_client.format_arp_flow(
                name=f"{handler}-arp-a2s-{idx}", switch=sw, in_port=in_p, out_port=out_p, priority=20000)
            fa2 = self.floodlight_client.format_arp_flow(
                name=f"{handler}-arp-s2a-{idx}", switch=sw, in_port=out_p, out_port=in_p, priority=20000)
            if not (push(fa1) and push(fa2)):
                print("Error creando flows ARP en la ruta.")
                return

        # Registro en memoria
        if not hasattr(self, 'conexiones'):
            self.conexiones = {}
        self.conexiones[handler] = flow_names
        print(f"Conexión creada con handler: {handler} ({len(flow_names)} flows)")