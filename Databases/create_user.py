#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para crear usuarios en FreeRADIUS y DB_Permissions
Uso: python3 create_user.py
"""
import mysql.connector
import sys

def get_db_radius():
    return mysql.connector.connect(
        host="localhost",
        user="radius",
        password="RadiusPass2025!",
        database="radius"
    )

def get_db_permissions():
    return mysql.connector.connect(
        host="localhost",
        user="campus",
        password="SQLgrupo3?",
        database="DB_Permissions"
    )

def create_user_radius(username, password):
    """Crea usuario en FreeRADIUS (tabla radcheck)"""
    try:
        conn = get_db_radius()
        cur = conn.cursor()
        
        # Verificar si ya existe
        cur.execute("SELECT COUNT(*) FROM radcheck WHERE username=%s", (username,))
        if cur.fetchone()[0] > 0:
            print(f"⚠ Usuario '{username}' ya existe en RADIUS")
            cur.close()
            conn.close()
            return False
        
        # Insertar en rad Check
        cur.execute(
            "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
            (username, 'Cleartext-Password', ':=', password)
        )
        conn.commit()
        cur.close()
        conn.close()
        print(f"✓ Usuario '{username}' creado en RADIUS")
        return True
    except mysql.connector.Error as e:
        print(f"✗ Error creando usuario en RADIUS: {e}")
        return False

def create_user_db(username, rol_id, curso_ids):
    """Crea usuario en DB_Permissions y asigna atributos"""
    try:
        conn = get_db_permissions()
        cur = conn.cursor(dictionary=True)
        
        # Verificar si ya existe
        cur.execute("SELECT COUNT(*) FROM User WHERE username=%s", (username,))
        if cur.fetchone()['COUNT(*)'] > 0:
            print(f"⚠ Usuario '{username}' ya existe en DB_Permissions")
            
            # Obtener ID del usuario
            cur.execute("SELECT idUser FROM User WHERE username=%s", (username,))
            user_id = cur.fetchone()['idUser']
        else:
            # Insertar usuario
            cur.execute(
                "INSERT INTO User (username, is_guest) VALUES (%s, %s)",
                (username, False)
            )
            conn.commit()
            user_id = cur.lastrowid
            print(f"✓ Usuario '{username}' creado en DB_Permissions (ID: {user_id})")
        
        # Asignar rol
        if rol_id:
            cur.execute(
                "INSERT IGNORE INTO User_has_AttributeValue (user_id, attributevalue_id) VALUES (%s, %s)",
                (user_id, rol_id)
            )
            print(f"  → Rol asignado (AttributeValue ID: {rol_id})")
        
        # Asignar cursos
        for curso_id in curso_ids:
            cur.execute(
                "INSERT IGNORE INTO User_has_AttributeValue (user_id, attributevalue_id) VALUES (%s, %s)",
                (user_id, curso_id)
            )
            print(f"  → Curso asignado (AttributeValue ID: {curso_id})")
        
        conn.commit()
        cur.close()
        conn.close()
        return True
    except mysql.connector.Error as e:
        print(f"✗ Error creando usuario en DB: {e}")
        return False

def listar_roles():
    """Lista roles disponibles"""
    try:
        conn = get_db_permissions()
        cur = conn.cursor(dictionary=True)
        
        # Buscar attribute "Rol"
        cur.execute("SELECT idAttribute FROM Attribute WHERE name='Rol'")
        result = cur.fetchone()
        if not result:
            print("No se encontró el atributo 'Rol'")
            return []
        
        attr_id = result['idAttribute']
        
        # Obtener valores
        cur.execute(
            "SELECT id, value FROM AttributeValue WHERE attribute_id=%s",
            (attr_id,)
        )
        roles = cur.fetchall()
        cur.close()
        conn.close()
        return roles
    except mysql.connector.Error as e:
        print(f"Error consultando roles: {e}")
        return []

def listar_cursos():
    """Lista cursos disponibles (AttributeValues de facultades)"""
    try:
        conn = get_db_permissions()
        cur = conn.cursor(dictionary=True)
        
        # Obtener todos los attributes que NO sean "Rol"
        cur.execute("SELECT idAttribute, name FROM Attribute WHERE name != 'Rol'")
        facultades = cur.fetchall()
        
        cursos = []
        for fac in facultades:
            cur.execute(
                "SELECT id, value FROM AttributeValue WHERE attribute_id=%s",
                (fac['idAttribute'],)
            )
            for curso in cur.fetchall():
                cursos.append({
                    'id': curso['id'],
                    'value': curso['value'],
                    'facultad': fac['name']
                })
        
        cur.close()
        conn.close()
        return cursos
    except mysql.connector.Error as e:
        print(f"Error consultando cursos: {e}")
        return []

def main():
    print("=" * 60)
    print(" CREACIÓN DE USUARIO - Campus Sentinel Project")
    print("=" * 60)
    
    # Input de datos
    username = input("\nEmail del usuario: ").strip().lower()
    if not username:
        print("✗ Email no puede estar vacío")
        sys.exit(1)
    
    password = input("Contraseña: ").strip()
    if not password:
        print("✗ Contraseña no puede estar vacía")
        sys.exit(1)
    
    # Listar y seleccionar rol
    print("\n--- Roles Disponibles ---")
    roles = listar_roles()
    if not roles:
        print("✗ No hay roles disponibles. Ejecute init_attributes.py primero")
        sys.exit(1)
    
    for idx, rol in enumerate(roles, start=1):
        print(f"{idx}) {rol['value']}")
    
    rol_idx = input("\nSeleccione número de rol: ").strip()
    try:
        rol_id = roles[int(rol_idx) - 1]['id']
    except (ValueError, IndexError):
        print("✗ Selección inválida")
        sys.exit(1)
    
    # Listar y seleccionar cursos (opcional para estudiantes)
    cursos_ids = []
    print("\n--- Cursos Disponibles ---")
    cursos = listar_cursos()
    if cursos:
        for idx, curso in enumerate(cursos, start=1):
            print(f"{idx}) {curso['value']} ({curso['facultad']})")
        
        print("\nSeleccione números de cursos (separados por coma, Enter para omitir):")
        cursos_input = input("> ").strip()
        if cursos_input:
            try:
                for num in cursos_input.split(','):
                    curso_idx = int(num.strip()) - 1
                    cursos_ids.append(cursos[curso_idx]['id'])
            except (ValueError, IndexError):
                print("⚠ Algunos cursos no pudieron ser asignados")
    
    # Crear usuario
    print("\n" + "=" * 60)
    print("Creando usuario...")
    print("=" * 60)
    
    radius_ok = create_user_radius(username, password)
    db_ok = create_user_db(username, rol_id, cursos_ids)
    
    if radius_ok and db_ok:
        print("\n✓ Usuario creado exitosamente en ambas bases de datos")
        print(f"  Email: {username}")
        print(f"  Rol ID: {rol_id}")
        print(f"  Cursos: {len(cursos_ids)} asignados")
    else:
        print("\n⚠ Usuario creado parcialmente. Revise los errores arriba")
    
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✗ Operación cancelada por el usuario")
        sys.exit(0)
