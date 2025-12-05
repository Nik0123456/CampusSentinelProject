# 🛡️ Campus Sentinel

**Sistema de Seguridad SDN para Redes de Campus Universitario**

---

## 📋 Descripción

Campus Sentinel es una solución de seguridad basada en Redes Definidas por Software (SDN) diseñada para redes de campus universitario. Implementa un framework AAA (Autenticación, Autorización y Accounting) con control granular de acceso a recursos y detección de ataques DDoS.

**Desarrollado para:** Curso de Redes Definidas por Software - PUCP 2025-2

### Características Principales

| Requisito | Descripción |
|-----------|-------------|
| **R1** | Control de acceso a la red (Autenticación RADIUS) | 
| **R2** | Restricción de acceso a recursos (Autorización ABAC) |
| **R4** | Detección y mitigación de ataques DDoS | 

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│  PLANO DE APLICACIÓN                                        │
│  ├── campus_sentinel.py      (API REST - Autenticación)    │
│  ├── PacketInCapture.java    (Interceptor PACKET_IN)       │
│  └── ddos_auto_mitigation.py (Detector DDoS)               │
├─────────────────────────────────────────────────────────────┤
│  PLANO DE CONTROL                                           │
│  ├── Floodlight 1.2          (Controlador SDN)             │
│  ├── FreeRADIUS + MySQL      (Servidor AAA)                │
│  └── sFlow-RT                (Colector de métricas)        │
├─────────────────────────────────────────────────────────────┤
│  PLANO DE DATOS                                             │
│  └── Open vSwitch            (OpenFlow 1.3)                │
└─────────────────────────────────────────────────────────────┘
```

### Pipeline OpenFlow Multi-Tabla

| Tabla | Función | Responsabilidad |
|-------|---------|-----------------|
| 0 | Seguridad | Clasificación, anti-spoofing VLAN, mitigación DDoS |
| 1 | Autenticación | Validación anti-spoofing (IP+MAC+Puerto) |
| 2 | Autorización | Permisos granulares L3/L4 |
| 3 | Forwarding | Enrutamiento hop-by-hop |

---

## 📁 Estructura del Proyecto

```
CampusSentinelProject/
├── PythonModules/
│   ├── campus_sentinel. py      # Módulo principal AAA
│   ├── floodlight_client.py    # Cliente API Floodlight
│   ├── campus_client.py        # Cliente de autenticación (hosts)
│   └── Additional_Scripts/
│       ├── register_user.py    # Registro de usuarios
│       └── delete_user.py      # Eliminación de usuarios
├── JavaModules/
│   └── PacketInCapture. java    # Módulo Floodlight
├── Databases/
│   ├── DB_Permissions.sql      # Schema de permisos
│   └── init_attributes.py      # Inicialización de atributos
├── sFlowCollector/
│   └── ddos_auto_mitigation.py # Detector DDoS
├── ConfigFiles/
│   ├── SwitchesSetup.txt       # Flow entries base
│   ├── DatabasesSetup.txt      # Configuración MySQL + RADIUS
│   └── DhcpServer.txt          # Configuración DHCP
└── logs/                        # Logs diarios de eventos
```

---

## 🚀 Instalación Rápida

### Prerrequisitos

- Ubuntu 20.04 LTS
- Python 3.8+
- Java OpenJDK 1.8
- MySQL Server
- FreeRADIUS
- Open vSwitch
- Floodlight 1.2

### 1. Clonar repositorio

```bash
git clone https://github.com/Nik0123456/CampusSentinelProject.git
cd CampusSentinelProject
```

### 2. Configurar entorno virtual Python

```bash
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements. txt
```

### 3. Configurar bases de datos

```bash
# Crear bases de datos
mysql -u root -p < Databases/DB_Permissions.sql

# Inicializar atributos y permisos
python3 Databases/init_attributes.py
```

### 4.  Configurar FreeRADIUS

Seguir instrucciones en `ConfigFiles/DatabasesSetup.txt`

### 5. Desplegar servicios

```bash
# Terminal 1: Floodlight
cd ~/floodlight-1.2 && java -jar target/floodlight. jar

# Terminal 2: Campus Sentinel
source myenv/bin/activate
gunicorn -w 8 -b 0.0.0. 0:5000 campus_sentinel:app

# Terminal 3: Configurar switches
bash ConfigFiles/SwitchesSetup. txt
```

---

## 📖 Uso

### Registro de usuarios

```bash
python3 PythonModules/Additional_Scripts/register_user.py
```

### Autenticación desde host

```bash
# En el host del usuario
python3 PythonModules/campus_client.py
```

### Monitoreo DDoS (opcional)

```bash
python3 sFlowCollector/ddos_auto_mitigation.py
```

---

## 🔧 Configuración

### Variables principales (`campus_sentinel.py`)

```python
SESSION_HOURS = 4          # Duración de sesión
HYBRID_MODE = False        # True = Proactivo + Reactivo
VLAN_AUTH = 100            # VLAN de marcado interno
FLOW_PRIORITY = 200        # Prioridad base de flows
```

### Umbrales DDoS (`ddos_auto_mitigation.py`)

```python
THRESHOLDS = {
    'frames_per_sec': 50000,  # PPS
    'mbps': 50,               # Bandwidth
}
MITIGATION_CONFIG = {
    'priority': 600,
    'hard_timeout': 300,      # 5 minutos
}
```

---

## 📊 APIs

### Flask REST API (:5000)

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/packetin` | POST | Recibe PACKET_IN de Floodlight |
| `/api/login` | POST | Autenticación RADIUS |
| `/api/guest` | POST | Acceso invitado |
| `/api/logout` | POST | Cierre de sesión |
| `/api/status` | GET | Estado del sistema |

### Floodlight API (:8080)

| Endpoint | Descripción |
|----------|-------------|
| `/wm/staticflowpusher/json` | Gestión de flows |
| `/wm/topology/route/... ` | Cálculo de rutas |
| `/wm/core/controller/switches/json` | Lista de switches |

---

## 🧪 Entorno de Pruebas

El sistema fue desarrollado y probado en el VNRT (Virtual Network Research Testbed) de la PUCP con la siguiente topología:

- **4 switches OVS** (SW1-SW4)
- **4 hosts de usuario** (h1-h4)
- **3 servidores** (Server1-3)
- **1 Core** (Controlador + AAA)
- **1 Gateway**

---

## 📈 Escalabilidad

| Métrica | Valor (4 switches) |
|---------|-------------------|
| Usuarios concurrentes máximos | ~600 |
| Logins/segundo | ~120-180 |
| Latencia autenticación | 30-60 ms |
| Tiempo detección DDoS | 2-5 s |

Para escalar a 20,000-30,000 usuarios, se propone una arquitectura federada con múltiples controladores por zona.

---

## 👥 Autores

| Nombre | GitHub | Rol | Aportes |
|--------|--------|-----|---- |
| Tony Flores | https://github.com/Nik0123456 | Desarrollador y Arquitecto de Soluciones | Arquitectura del Sistema, Módulos de autorización, Escalabilidad |
| Christian Flores | https://github.com/Cjfs2005 | Desarrollador e Ingeniero de Seguridad | Pipeline OpenFlow, Módulos de autenticación, Detección y Mitigación DDoS |

---

---

## 🙏 Agradecimientos

### Jhon Branko Zambrano Linares
*Asesor de Laboratorio*

Por su acompañamiento constante durante todo el desarrollo del proyecto, orientándonos en la selección de tecnologías, arquitectura del sistema y decisiones de diseño. Su experiencia práctica fue fundamental para materializar las ideas en una implementación funcional.

### Dr. César Augusto Santivañez Guarniz
*Profesor del Curso*

Por su retroalimentación exhaustiva y crítica rigurosa que nos impulsó a refinar y optimizar cada aspecto de la propuesta. Su exigencia nos enseñó que la excelencia técnica requiere cuestionar constantemente nuestras propias decisiones.

### Mg. Christian Isaac Quispe Ordoñez
*Profesor del Curso*

Por sus explicaciones claras de los fundamentos de SDN y su visión amplia del campo, que nos permitió entender las redes definidas por software no solo como tecnología, sino como paradigma que converge con redes neutras, análisis económico y escalabilidad empresarial.

---

## 📚 Referencias

- [Floodlight Controller](https://github.com/floodlight/floodlight)
- [Open vSwitch](https://www.openvswitch.org/)
- [OpenFlow 1.3 Specification](https://opennetworking.org/software-defined-standards/specifications/)
- [FreeRADIUS](https://freeradius.org/)
- [sFlow-RT](https://sflow-rt.com/)

---

## 📄 Licencia

Este proyecto fue desarrollado con fines académicos para el curso de Redes Definidas por Software de la Pontificia Universidad Católica del Perú (PUCP). 

---
