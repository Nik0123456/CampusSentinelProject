#!/usr/bin/env python3
import requests
import json
import os
from datetime import datetime

SERVER = "http://10.0.0.2:5000"
SESSION_FILE = os.path.expanduser("~/.campus_session")

def load_session():
    """Carga la sesión guardada localmente"""
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE) as f:
            return json.load(f)
    return None

def save_session(data):
    """Guarda la sesión localmente"""
    with open(SESSION_FILE, "w") as f:
        json.dump(data, f)

def delete_session():
    """Elimina la sesión local"""
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)

def get_client_info():
    """Obtiene la información de red del cliente desde el servidor"""
    try:
        print("Obteniendo información de red...")
        r = requests.get(f"{SERVER}/api/client_info", timeout=5)
        
        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                return data["client"]
            else:
                print(f"Error: {data.get('error', 'No se pudo obtener info del cliente')}")
        else:
            print(f"Error del servidor: código {r.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("No se pudo conectar al servidor de autenticación.")
        print("Asegúrate de que el servidor esté ejecutándose en http://10.0.0.2:5000")
    except requests.exceptions.Timeout:
        print("Timeout al conectar con el servidor.")
    except Exception as e:
        print(f"Error inesperado: {e}")
    
    return None

def login_user(client_info):
    """Autenticación de usuario registrado"""
    print("\n=== LOGIN DE USUARIO REGISTRADO ===")
    email = input("Email: ").strip().lower()
    
    import getpass
    password = getpass.getpass("Contraseña: ")
    
    payload = {
        "email": email,
        "password": password,
        "client": client_info
    }
    
    try:
        resp = requests.post(f"{SERVER}/api/login", json=payload, timeout=10)
        result = resp.json()
        
        if resp.status_code == 200 and result.get("success"):
            save_session({
                "email": email,
                "token": result["token"],
                "expires_at": (datetime.utcnow().timestamp() + result["expires_in"])
            })
            print(f"\n✓ Autenticación exitosa!")
            print(f"  Usuario: {result.get('user', email)}")
            print(f"  Acceso válido por {result['expires_in'] // 3600} horas")
            print(f"  VLAN 100 asignada automáticamente")
            return True
        else:
            print(f"\n✗ Error: {result.get('error', 'Credenciales inválidas')}")
            
    except Exception as e:
        print(f"Error durante el login: {e}")
    
    return False

def guest_access(client_info):
    """Acceso de invitado"""
    print("\n=== ACCESO DE INVITADO ===")
    email = input("Email: ").strip().lower()
    
    if not email or '@' not in email:
        print("Email inválido")
        return False
    
    payload = {
        "email": email,
        "client": client_info
    }
    
    try:
        resp = requests.post(f"{SERVER}/api/guest", json=payload, timeout=10)
        result = resp.json()
        
        if resp.status_code == 200 and result.get("success"):
            save_session({
                "email": email,
                "token": result["token"],
                "expires_at": (datetime.utcnow().timestamp() + result["expires_in"])
            })
            print(f"\n✓ Acceso de invitado concedido!")
            print(f"  Email: {email}")
            print(f"  Acceso válido por {result['expires_in'] // 3600} horas")
            print(f"  VLAN 100 asignada automáticamente")
            return True
        else:
            print(f"\n✗ Error: {result.get('error', 'No se pudo registrar')}")
            
    except Exception as e:
        print(f"Error durante el registro: {e}")
    
    return False

def logout_user(session):
    """Cierra la sesión del usuario"""
    try:
        resp = requests.post(f"{SERVER}/api/logout", 
                           json={"token": session["token"]}, 
                           timeout=5)
        
        if resp.status_code == 200:
            delete_session()
            print("\n✓ Sesión cerrada correctamente")
            print("  El flow de autenticación ha sido eliminado del switch")
            return True
        else:
            print("Error al cerrar sesión en el servidor")
            
    except Exception as e:
        print(f"Error al cerrar sesión: {e}")
    
    # Eliminar sesión local aunque falle el servidor
    delete_session()
    return False

def check_session_validity(session):
    """Verifica si la sesión aún es válida"""
    if 'expires_at' in session:
        now = datetime.utcnow().timestamp()
        if now < session['expires_at']:
            remaining = int(session['expires_at'] - now)
            hours = remaining // 3600
            minutes = (remaining % 3600) // 60
            return True, hours, minutes
    return False, 0, 0

def main():
    print("\n" + "="*60)
    print("     CAMPUS SENTINEL - Sistema de Autenticación SDN")
    print("="*60)
    
    # Verificar sesión existente
    session = load_session()
    if session:
        is_valid, hours, minutes = check_session_validity(session)
        
        if is_valid:
            print(f"\n✓ Sesión activa encontrada")
            print(f"  Usuario: {session['email']}")
            print(f"  Tiempo restante: {hours}h {minutes}m")
            
            opcion = input("\n¿Qué deseas hacer?\n1. Mantener sesión\n2. Cerrar sesión\nElige (1/2): ").strip()
            
            if opcion == "2":
                logout_user(session)
            else:
                print("\nSesión mantenida. Ya tienes acceso a la red.")
            return
        else:
            print("\n⚠ Sesión expirada")
            delete_session()
    
    # Obtener información del cliente
    print("\nPara autenticarte, primero necesitamos tu información de red.")
    print("Esto ocurre automáticamente cuando intentas navegar.")
    
    client_info = get_client_info()
    
    if not client_info:
        print("\n⚠ No se pudo obtener tu información de red.")
        print("\nPasos para solucionar:")
        print("  1. Intenta navegar a cualquier sitio web (ej: google.com)")
        print("  2. Espera unos segundos")
        print("  3. Ejecuta este programa nuevamente")
        return
    
    # Mostrar información del cliente
    print(f"\n✓ Cliente detectado:")
    print(f"  IP: {client_info['ip']}")
    print(f"  MAC: {client_info['mac']}")
    print(f"  Switch: {client_info['dpid']}")
    print(f"  Puerto: {client_info['port']}")
    
    # Menú de autenticación
    print("\n" + "-"*60)
    print("Opciones de autenticación:")
    print("-"*60)
    tipo = input("\n1. Usuario registrado (autenticación RADIUS)\n2. Acceso invitado\n\nElige (1/2): ").strip()
    
    if tipo == "1":
        login_user(client_info)
    elif tipo == "2":
        guest_access(client_info)
    else:
        print("Opción inválida")

if __name__ == '__main__':
    try:
        while True:
            main()
            
            continuar = input("\n¿Ejecutar nuevamente? (s/N): ").strip().lower()
            if continuar != 's':
                break
            
    except KeyboardInterrupt:
        print("\n\nPrograma interrumpido por el usuario")
    except Exception as e:
        print(f"\nError fatal: {e}")
    finally:
        print("\nGracias por usar Campus Sentinel")
