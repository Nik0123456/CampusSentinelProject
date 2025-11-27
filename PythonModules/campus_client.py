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

def login_user():
    """Autenticación de usuario registrado
    NOTA: La información de red (IP, MAC, DPID, Puerto) es obtenida automáticamente
    por el servidor desde Floodlight cuando el usuario navega.
    """
    print("\n=== LOGIN DE USUARIO REGISTRADO ===")
    email = input("Email: ").strip().lower()
    
    import getpass
    password = getpass.getpass("Contraseña: ")
    
    payload = {
        "email": email,
        "password": password
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
            print(f"  Flow de autenticación instalado en el switch")
            return True
        else:
            print(f"\n✗ Error: {result.get('error', 'Credenciales inválidas')}")
            if 'No se encontró información de red' in result.get('error', ''):
                print("\n  Asegúrate de haber navegado a http://10.0.0.2:5000 primero")
            
    except Exception as e:
        print(f"Error durante el login: {e}")
    
    return False

def guest_access():
    """Acceso de invitado
    NOTA: La información de red es obtenida automáticamente por el servidor
    """
    print("\n=== ACCESO DE INVITADO ===")
    email = input("Email: ").strip().lower()
    
    if not email or '@' not in email:
        print("Email inválido")
        return False
    
    payload = {
        "email": email
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
            print(f"  Flow de autenticación instalado en el switch")
            return True
        else:
            print(f"\n✗ Error: {result.get('error', 'No se pudo registrar')}")
            if 'No se encontró información de red' in result.get('error', ''):
                print("\n  Asegúrate de haber navegado a http://10.0.0.2:5000 primero")
            
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
    
    # Información importante para el usuario
    print("\n" + "-"*60)
    print("IMPORTANTE: Asegúrate de haber navegado a http://10.0.0.2:5000")
    print("antes de autenticarte. Esto permite que el sistema detecte tu red.")
    print("-"*60)
    
    # Menú de autenticación
    print("\nOpciones de autenticación:")
    tipo = input("\n1. Usuario registrado (autenticación RADIUS)\n2. Acceso invitado\n\nElige (1/2): ").strip()
    
    if tipo == "1":
        login_user()
    elif tipo == "2":
        guest_access()
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
