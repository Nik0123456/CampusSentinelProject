#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Inicialización de atributos, cursos y permisos para Campus Sentinel
Nuevo modelo:
- Attributes: Rol + Facultades específicas (Ing. Telecomunicaciones, etc.)
- AttributeValues: Cursos dentro de cada facultad
- Permissions: Servicios de red asociados a cursos
"""
import mysql.connector

config = {
    'user': 'campus',
    'password': 'SQLgrupo3?',
    'host': 'localhost',
    'database': 'DB_Permissions'
}

conn = mysql.connector.connect(**config)
cur = conn.cursor()

print("=" * 70)
print(" INICIALIZACIÓN DE ATRIBUTOS Y PERMISOS - Campus Sentinel")
print("=" * 70)

# Limpiar todo para poder volver a ejecutar sin errores
print("\n[1/4] Limpiando tablas existentes...")
cur.execute("SET FOREIGN_KEY_CHECKS = 0")
cur.execute("TRUNCATE TABLE User_has_AttributeValue")
cur.execute("TRUNCATE TABLE User_Permission_Usage")
cur.execute("TRUNCATE TABLE Permission")
cur.execute("TRUNCATE TABLE AttributeValue")
cur.execute("TRUNCATE TABLE Attribute")
cur.execute("SET FOREIGN_KEY_CHECKS = 1")
print("  ✓ Tablas limpiadas")

# ========================================
# PASO 1: Crear Attributes (Rol + Facultades)
# ========================================
print("\n[2/4] Creando Attributes (Rol y Facultades)...")
cur.execute("""
    INSERT INTO Attribute (name) VALUES 
    ('Rol'),
    ('Ingeniería de las Telecomunicaciones'),
    ('Ingeniería Civil'),
    ('Ingeniería Industrial')
""")
conn.commit()

# Obtener IDs de attributes
cur.execute("SELECT idAttribute, name FROM Attribute")
attrs = {row[1]: row[0] for row in cur.fetchall()}
print(f"  ✓ Attributes creados: {list(attrs.keys())}")

# ========================================
# PASO 2: Crear AttributeValues
# ========================================
print("\n[3/4] Creando AttributeValues (Roles y Cursos)...")

# --- ROLES ---
id_rol = attrs['Rol']
roles = ['Estudiante', 'Profesor', 'Administrativo', 'Administrador TI', 'Invitado']
for rol in roles:
    cur.execute("INSERT INTO AttributeValue (value, attribute_id) VALUES (%s, %s)", (rol, id_rol))
print(f"  ✓ Roles: {', '.join(roles)}")

# --- CURSOS DE ING. TELECOMUNICACIONES ---
id_tel = attrs['Ingeniería de las Telecomunicaciones']
cursos_tel = [
    'Redes Definidas por Software',
    'Ingeniería Inalámbrica',
    'Circuitos y Sistemas de Alta Frecuencia',
    'Procesamiento Digital de Señales'
]
for curso in cursos_tel:
    cur.execute("INSERT INTO AttributeValue (value, attribute_id) VALUES (%s, %s)", (curso, id_tel))
print(f"  ✓ Cursos Ing. Telecomunicaciones: {', '.join(cursos_tel)}")

# Nota: Ing. Civil e Industrial se llenarán después según necesidad del proyecto
conn.commit()

# Obtener IDs de AttributeValues para crear permisos
cur.execute("SELECT id, value, attribute_id FROM AttributeValue")
attr_values = {row[1]: {'id': row[0], 'attr_id': row[2]} for row in cur.fetchall()}

# ========================================
# PASO 3: Crear Permissions (Servicios de red)
# ========================================
print("\n[4/4] Creando Permissions (Servicios de red)...")

# ========================================
# SERVICIOS DE RED (Solo IPs: 10.0.0.21, 10.0.0.22, 10.0.0.23)
# ========================================
# Nota: Las MACs se obtendrán dinámicamente de Floodlight, estos valores son placeholders

# Servicios generales (para todos los estudiantes) - SERVER2
servicios_generales = [
    {
        'name': 'Biblioteca General PUCP',
        'ip': '10.0.0.22',
        'mac': 'fa:16:3e:60:4c:fa',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 4,
        'protocol': 'TCP',
        'port': '80',  # HTTP
        'attr_value': 'Estudiante'
    },
    {
        'name': 'Servidor DNS PUCP',
        'ip': '10.0.0.22',
        'mac': 'fa:16:3e:60:4c:fa',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 4,
        'protocol': 'UDP',
        'port': '53',
        'attr_value': 'Estudiante'
    },
    {
        'name': 'Portal Web Estudiantes',
        'ip': '10.0.0.22',
        'mac': 'fa:16:3e:60:4c:fa',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 4,
        'protocol': 'TCP',
        'port': '8080',
        'attr_value': 'Estudiante'
    }
]

# Servicios específicos de Redes SDN - SERVER1
servicios_sdn = [
    {
        'name': 'Servidor FTP SDN',
        'ip': '10.0.0.21',
        'mac': 'fa:16:3e:01:d2:e7',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 3,
        'protocol': 'TCP',
        'port': '21',
        'attr_value': 'Redes Definidas por Software'
    },
    {
        'name': 'Laboratorio SDN Web',
        'ip': '10.0.0.21',
        'mac': 'fa:16:3e:01:d2:e7',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 3,
        'protocol': 'TCP',
        'port': '8081',
        'attr_value': 'Redes Definidas por Software'
    },
    {
        'name': 'Network File System SDN',
        'ip': '10.0.0.21',
        'mac': 'fa:16:3e:01:d2:e7',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 3,
        'protocol': 'TCP',
        'port': '2049',
        'attr_value': 'Redes Definidas por Software'
    },
    {
        'name': 'API REST Floodlight SDN',
        'ip': '10.0.0.21',
        'mac': 'fa:16:3e:01:d2:e7',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 3,
        'protocol': 'TCP',
        'port': '8080',
        'attr_value': 'Redes Definidas por Software'
    }
]

# Servicios específicos de Ingeniería Inalámbrica - SERVER3
servicios_wireless = [
    {
        'name': 'Servidor de Simulación Wireless',
        'ip': '10.0.0.23',
        'mac': 'fa:16:3e:f0:2f:9a',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 5,
        'protocol': 'TCP',
        'port': '8082',
        'attr_value': 'Ingeniería Inalámbrica'
    },
    {
        'name': 'Base de Datos Espectro',
        'ip': '10.0.0.23',
        'mac': 'fa:16:3e:f0:2f:9a',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 5,
        'protocol': 'TCP',
        'port': '3306',
        'attr_value': 'Ingeniería Inalámbrica'
    },
    {
        'name': 'Servidor SSH Wireless Lab',
        'ip': '10.0.0.23',
        'mac': 'fa:16:3e:f0:2f:9a',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 5,
        'protocol': 'TCP',
        'port': '22',
        'attr_value': 'Ingeniería Inalámbrica'
    }
]

# Servicios específicos de Circuitos RF - SERVER1 (diferente puerto)
servicios_rf = [
    {
        'name': 'Servidor de Simulación RF',
        'ip': '10.0.0.21',
        'mac': 'fa:16:3e:01:d2:e7',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 3,
        'protocol': 'TCP',
        'port': '8083',
        'attr_value': 'Circuitos y Sistemas de Alta Frecuencia'
    },
    {
        'name': 'Laboratorio Virtual RF',
        'ip': '10.0.0.21',
        'mac': 'fa:16:3e:01:d2:e7',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 3,
        'protocol': 'TCP',
        'port': '8084',
        'attr_value': 'Circuitos y Sistemas de Alta Frecuencia'
    }
]

# Servicios específicos de Procesamiento de Señales - SERVER3 (diferentes puertos)
servicios_dsp = [
    {
        'name': 'Servidor MATLAB Online',
        'ip': '10.0.0.23',
        'mac': 'fa:16:3e:f0:2f:9a',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 5,
        'protocol': 'TCP',
        'port': '8085',
        'attr_value': 'Procesamiento Digital de Señales'
    },
    {
        'name': 'Repositorio de Datasets DSP',
        'ip': '10.0.0.23',
        'mac': 'fa:16:3e:f0:2f:9a',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 5,
        'protocol': 'TCP',
        'port': '9000',
        'attr_value': 'Procesamiento Digital de Señales'
    }
]

# Servicios para profesores y administrativos - SERVER2 (diferentes puertos)
servicios_admin = [
    {
        'name': 'Portal Docente',
        'ip': '10.0.0.22',
        'mac': 'fa:16:3e:60:4c:fa',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 4,
        'protocol': 'TCP',
        'port': '8443',
        'attr_value': 'Profesor'
    },
    {
        'name': 'Sistema de Gestión Académica',
        'ip': '10.0.0.22',
        'mac': 'fa:16:3e:60:4c:fa',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 4,
        'protocol': 'TCP',
        'port': '8090',
        'attr_value': 'Administrativo'
    },
    {
        'name': 'SSH Admin Server',
        'ip': '10.0.0.22',
        'mac': 'fa:16:3e:60:4c:fa',
        'dpid': '00:00:62:bb:7c:2d:37:4f',
        'in_port': 4,
        'protocol': 'TCP',
        'port': '22',
        'attr_value': 'Administrativo'
    }
]

# Insertar todos los servicios
todos_servicios = (servicios_generales + servicios_sdn + servicios_wireless + 
                   servicios_rf + servicios_dsp + servicios_admin)

for svc in todos_servicios:
    attr_val_id = attr_values[svc['attr_value']]['id']
    cur.execute("""
        INSERT INTO Permission (serviceName, serviceIP, serviceMAC, serviceDPID, serviceInPort, serviceProtocol, servicePort, attributevalue_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (svc['name'], svc['ip'], svc['mac'], svc['dpid'], svc['in_port'], svc['protocol'], svc['port'], attr_val_id))

conn.commit()
print(f"  ✓ {len(todos_servicios)} permisos (servicios) creados")

cur.close()
conn.close()

print("\n" + "=" * 70)
print(" ✓ INICIALIZACIÓN COMPLETADA EXITOSAMENTE")
print("=" * 70)
print("\nResumen:")
print(f"  • Roles: {len(roles)}")
print(f"  • Cursos (Ing. Telecomunicaciones): {len(cursos_tel)}")
print(f"  • Servicios de red: {len(todos_servicios)}")
print("\nAhora puede crear usuarios con: python3 create_user.py")
print("=" * 70)
