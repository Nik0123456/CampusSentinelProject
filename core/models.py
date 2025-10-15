#!/usr/bin/python

class Alumno:
    def __init__(self, nombre, codigo, mac):
        self.nombre = nombre
        self.codigo = codigo
        self.mac = mac
    
    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise ValueError("Alumno.from_dict esperaba un dict")
        return cls(
            nombre=data.get("nombre"),
            codigo=data.get("codigo"),
            mac=data.get("mac"),
        )

    def to_dict(self):
        return {
            "nombre": self.nombre,
            "codigo": self.codigo,
            "mac": self.mac
        }

class Servidor:
    def __init__(self, nombre, ip, servicios=None):
        self.nombre = nombre
        self.ip = ip
        servicios = servicios or []  # En caso no se pase una lista de servicios, se inicializa como lista vacía
        normalizados = []
        for s in servicios:
            if isinstance(s, Servicio):
                normalizados.append(s)
            elif isinstance(s, dict):
                normalizados.append(Servicio.from_dict(s))
            else:
                # Ignora tipos inesperados para robustez
                continue
        self.servicios = normalizados #Se asegura que todos los servicios sean instancias de Servicio

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise ValueError("Servidor.from_dict esperaba un dict")
        return cls(
            nombre=data.get("nombre"),
            ip=data.get("ip"),
            servicios=data.get("servicios") or [],
        )

    def to_dict(self):
        return {
            "nombre": self.nombre,
            "ip": self.ip,
            "servicios": [s.to_dict() if hasattr(s, "to_dict") else s for s in self.servicios],
        }

class Servicio:
    def __init__(self, nombre, protocolo, puerto):
        self.nombre = nombre
        self.protocolo = protocolo
        self.puerto = puerto
    
    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise ValueError("Servicio.from_dict esperaba un dict")
        puerto = data.get("puerto")
        try:
            if puerto is not None:
                puerto = int(puerto)
        except (TypeError, ValueError):
            pass
        return cls(
            nombre=data.get("nombre"),
            protocolo=data.get("protocolo"),
            puerto=puerto,
        )

    def to_dict(self):
        return {
            "nombre": self.nombre,
            "protocolo": self.protocolo,
            "puerto": self.puerto
        }

class PoliticaServidorCurso:
    
    def __init__(self, nombre, servicios_permitidos=None):
        self.nombre = nombre
        self.servicios_permitidos = list(servicios_permitidos or [])

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise ValueError("PoliticaServidorCurso.from_dict esperaba un dict")
        return cls(
            nombre=data.get("nombre"),
            servicios_permitidos=data.get("servicios_permitidos") or []
        )

    def to_dict(self):
        return {
            "nombre": self.nombre,
            "servicios_permitidos": list(self.servicios_permitidos)
        }

class Curso:
    def __init__(self, nombre, codigo, estado, alumnos=None, servidores=None):
        self.nombre = nombre
        self.codigo = codigo
        self.estado = estado

        alumnos = alumnos or []
        norm_alumnos = []
        for a in alumnos:
            if isinstance(a, Alumno):
                norm_alumnos.append(a)
            elif isinstance(a, dict):
                try:
                    norm_alumnos.append(Alumno.from_dict(a))
                except Exception:
                    norm_alumnos.append(a)
            else:  # códigos (int/str) u otros primitivos
                norm_alumnos.append(a)
        self.alumnos = norm_alumnos

        servidores = servidores or []
        politicas = []
        for s in servidores:
            if isinstance(s, PoliticaServidorCurso):
                politicas.append(s)
            elif isinstance(s, Servidor):
                politicas.append(PoliticaServidorCurso(
                    nombre=s.nombre,
                    servicios_permitidos=[svc.nombre for svc in getattr(s, 'servicios', [])]
                ))
            elif isinstance(s, dict):
                if 'servicios_permitidos' in s: #Es un diccionario en formato de politica
                    try:
                        politicas.append(PoliticaServidorCurso.from_dict(s))
                    except Exception:
                        politicas.append(s)
                elif 'ip' in s and 'servicios' in s: #Es un diccionario en formato de servidor
                    servicios_list = s.get('servicios') or []
                    nombres_servicios = []
                    for sv in servicios_list:
                        if isinstance(sv, dict):
                            nombre_sv = sv.get('nombre')
                            if nombre_sv:
                                nombres_servicios.append(nombre_sv)
                    politicas.append(PoliticaServidorCurso(
                        nombre=s.get('nombre'),
                        servicios_permitidos=nombres_servicios
                    ))
                else:
                    politicas.append(s)
            else:
                politicas.append(s)
        self.servidores = politicas

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise ValueError("Curso.from_dict esperaba un dict")
        return cls(
            nombre=data.get("nombre"),
            codigo=data.get("codigo"),
            estado=data.get("estado"),
            alumnos=data.get("alumnos") or [],
            servidores=data.get("servidores") or [],
        )

    def agregar_alumno(self, alumno):
        self.alumnos.append(alumno)

    def eliminar_alumno(self, alumno):
        if alumno in self.alumnos:
            self.alumnos.remove(alumno)

    def agregar_servidor(self, servidor):
        self.servidores.append(servidor)

    def to_dict(self):
        return {
            "nombre": self.nombre,
            "codigo": self.codigo,
            "estado": self.estado,
            # Al exportar: si es instancia Alumno -> código, si dict/primitivo -> tal cual
            "alumnos": [a.codigo if hasattr(a, "codigo") else a for a in self.alumnos],
            # Políticas exportadas uniformemente como dicts
            "servidores": [p.to_dict() if hasattr(p, 'to_dict') else p for p in self.servidores]
        }

    def resolver_referencias_servidores(self, servidores_disponibles):
        
        index = {s.nombre: s for s in servidores_disponibles if isinstance(s, Servidor)}
        no_resueltos = []
        for p in self.servidores:
            if isinstance(p, PoliticaServidorCurso):
                if p.nombre not in index:
                    no_resueltos.append(p.nombre)
        return no_resueltos