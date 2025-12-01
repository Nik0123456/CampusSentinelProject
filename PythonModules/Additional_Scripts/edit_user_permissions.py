#!/usr/bin/env python3
"""
Script para editar permisos de usuarios existentes
Permite agregar o revocar servicios de cualquier usuario
"""
import mysql.connector

DB_CONFIG = {
    'user': 'campus',
    'password': 'SQLgrupo3?',
    'host': 'localhost',
    'database': 'DB_Permissions'
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

def list_users():
    """Lista todos los usuarios registrados"""
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    
    cur.execute("""
        SELECT idUser, username, is_guest, session_active
        FROM User
        ORDER BY idUser DESC
    """)
    
    users = cur.fetchall()
    cur.close()
    conn.close()
    
    return users

def get_user_permissions(user_id):
    """Obtiene los permisos actuales del usuario"""
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    
    cur.execute("""
        SELECT DISTINCT p.id, p.serviceName, p.serviceIP, 
               p.servicePort, p.serviceProtocol, av.value as attribute_value
        FROM User_has_AttributeValue uhav
        JOIN AttributeValue av ON uhav.attributevalue_id = av.id
        JOIN Permission p ON p.attributevalue_id = av.id
        WHERE uhav.user_id = %s
        ORDER BY p.serviceIP, p.servicePort
    """, (user_id,))
    
    permissions = cur.fetchall()
    cur.close()
    conn.close()
    
    return permissions

def get_available_services():
    """Lista todos los servicios disponibles"""
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    
    cur.execute("""
        SELECT p.id, p.serviceName, p.serviceIP, p.servicePort,
               p.serviceProtocol, av.value as required_attribute
        FROM Permission p
        JOIN AttributeValue av ON p.attributevalue_id = av.id
        ORDER BY p.serviceIP, p.servicePort
    """)
    
    services = cur.fetchall()
    cur.close()
    conn.close()
    
    return services

def add_permissions(user_id, service_ids):
    """Agrega permisos (servicios) al usuario"""
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        
        if not service_ids:
            print("\n⚠️  No se proporcionaron servicios")
            return 0
        
        # Obtener los attributevalue_id de los servicios
        placeholders = ','.join(['%s'] * len(service_ids))
        cur.execute(f"""
            SELECT DISTINCT attributevalue_id 
            FROM Permission 
            WHERE id IN ({placeholders})
        """, service_ids)
        
        attribute_values = [row['attributevalue_id'] for row in cur.fetchall()]
        
        if not attribute_values:
            print("\n⚠️  No se encontraron atributos válidos")
            return 0
        
        # Insertar relaciones
        added = 0
        for av_id in attribute_values:
            try:
                cur.execute("""
                    INSERT IGNORE INTO User_has_AttributeValue (user_id, attributevalue_id)
                    VALUES (%s, %s)
                """, (user_id, av_id))
                if cur.rowcount > 0:
                    added += 1
            except mysql.connector.Error:
                pass
        
        # Inicializar User_Permission_Usage para los nuevos servicios
        if service_ids:
            usage_initialized = 0
            for perm_id in service_ids:
                try:
                    cur.execute("""
                        INSERT IGNORE INTO User_Permission_Usage (user_id, permission_id, usage_count, first_used, last_used)
                        VALUES (%s, %s, 0, NOW(), NOW())
                    """, (user_id, perm_id))
                    if cur.rowcount > 0:
                        usage_initialized += 1
                except mysql.connector.Error:
                    pass
            
            if usage_initialized > 0:
                print(f"✅ Inicializadas {usage_initialized} estadísticas de uso")
        
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"\n✅ Agregados {added} nuevos atributos al usuario")
        return added
        
    except mysql.connector.Error as e:
        print(f"\n❌ Error al agregar permisos: {e}")
        return 0

def revoke_permissions(user_id, service_ids):
    """Revoca permisos (servicios) del usuario"""
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        
        if not service_ids:
            print("\n⚠️  No se proporcionaron servicios")
            return 0
        
        # Obtener los attributevalue_id de los servicios
        placeholders = ','.join(['%s'] * len(service_ids))
        cur.execute(f"""
            SELECT DISTINCT attributevalue_id 
            FROM Permission 
            WHERE id IN ({placeholders})
        """, service_ids)
        
        attribute_values = [row['attributevalue_id'] for row in cur.fetchall()]
        
        if not attribute_values:
            print("\n⚠️  No se encontraron atributos válidos")
            return 0
        
        # Eliminar relaciones
        revoked = 0
        for av_id in attribute_values:
            cur.execute("""
                DELETE FROM User_has_AttributeValue
                WHERE user_id = %s AND attributevalue_id = %s
            """, (user_id, av_id))
            if cur.rowcount > 0:
                revoked += 1
        
        # Limpiar registros de uso de los servicios revocados
        # Obtener todos los permission_id que corresponden a los atributos revocados
        if service_ids:
            placeholders_perms = ','.join(['%s'] * len(service_ids))
            cur.execute(f"""
                DELETE FROM User_Permission_Usage
                WHERE user_id = %s AND permission_id IN ({placeholders_perms})
            """, [user_id] + service_ids)
            
            usage_deleted = cur.rowcount
            if usage_deleted > 0:
                print(f"✅ Eliminadas {usage_deleted} estadísticas de uso asociadas")
        
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"\n✅ Revocados {revoked} atributos del usuario")
        return revoked
        
    except mysql.connector.Error as e:
        print(f"\n❌ Error al revocar permisos: {e}")
        return 0

def parse_selection(selection, valid_ids):
    """Parsea la selección del usuario (IDs, rangos, 'all')"""
    selection = selection.strip()
    
    if not selection:
        return []
    
    if selection.lower() == 'all':
        return valid_ids
    
    selected_ids = []
    for part in selection.split(','):
        part = part.strip()
        if '-' in part:
            # Rango
            try:
                start, end = map(int, part.split('-'))
                selected_ids.extend(range(start, end + 1))
            except ValueError:
                print(f"⚠️  Rango inválido: {part}")
        else:
            # Número individual
            try:
                selected_ids.append(int(part))
            except ValueError:
                print(f"⚠️  ID inválido: {part}")
    
    # Filtrar solo IDs válidos
    return [sid for sid in selected_ids if sid in valid_ids]

def main():
    print("=" * 80)
    print(" EDITOR DE PERMISOS - Campus Sentinel SDN")
    print("=" * 80)
    
    # 1. Listar usuarios
    print("\n📋 USUARIOS REGISTRADOS")
    print("-" * 80)
    
    users = list_users()
    
    if not users:
        print("❌ No hay usuarios registrados")
        exit(1)
    
    print("\n{:<6} {:<40} {:<12} {:<10}".format(
        "ID", "Email", "Tipo", "Sesión"))
    print("-" * 80)
    
    for user in users:
        tipo = "Invitado" if user['is_guest'] else "Regular"
        sesion = "Activa" if user['session_active'] else "Inactiva"
        print("{:<6} {:<40} {:<12} {:<10}".format(
            user['idUser'],
            user['username'][:39],
            tipo,
            sesion
        ))
    
    # 2. Seleccionar usuario
    print("\n" + "=" * 80)
    user_id = input("ID del usuario a editar (o 'q' para salir): ").strip()
    
    if user_id.lower() == 'q':
        print("👋 Saliendo...")
        exit(0)
    
    try:
        user_id = int(user_id)
    except ValueError:
        print("❌ ID inválido")
        exit(1)
    
    # Verificar que el usuario existe
    selected_user = next((u for u in users if u['idUser'] == user_id), None)
    if not selected_user:
        print(f"❌ Usuario con ID {user_id} no encontrado")
        exit(1)
    
    print(f"\n✅ Usuario seleccionado: {selected_user['username']}")
    
    # 3. Mostrar permisos actuales
    print("\n" + "=" * 80)
    print(" PERMISOS ACTUALES")
    print("=" * 80)
    
    current_perms = get_user_permissions(user_id)
    
    if not current_perms:
        print("\n⚠️  Este usuario no tiene permisos asignados")
    else:
        print("\n{:<4} {:<35} {:<15} {:<8} {:<10}".format(
            "ID", "Servicio", "IP", "Puerto", "Protocolo"))
        print("-" * 80)
        
        for perm in current_perms:
            print("{:<4} {:<35} {:<15} {:<8} {:<10}".format(
                perm['id'],
                perm['serviceName'][:34],
                perm['serviceIP'],
                perm['servicePort'],
                perm['serviceProtocol']
            ))
    
    # 4. Mostrar todos los servicios disponibles
    print("\n" + "=" * 80)
    print(" TODOS LOS SERVICIOS DISPONIBLES")
    print("=" * 80)
    
    all_services = get_available_services()
    
    print("\n{:<4} {:<35} {:<15} {:<8} {:<10} {:<20}".format(
        "ID", "Servicio", "IP", "Puerto", "Protocolo", "Atributo Requerido"))
    print("-" * 80)
    
    for svc in all_services:
        # Marcar si el usuario ya tiene este permiso
        has_perm = any(p['id'] == svc['id'] for p in current_perms)
        marker = "✓ " if has_perm else "  "
        
        print("{}{:<2} {:<35} {:<15} {:<8} {:<10} {:<20}".format(
            marker,
            svc['id'],
            svc['serviceName'][:34],
            svc['serviceIP'],
            svc['servicePort'],
            svc['serviceProtocol'],
            svc['required_attribute'][:19]
        ))
    
    print("\n(Los servicios marcados con ✓ ya están asignados)")
    
    # 5. Operación a realizar
    print("\n" + "=" * 80)
    print("¿Qué deseas hacer?")
    print("  1) Agregar permisos")
    print("  2) Revocar permisos")
    print("  3) Salir sin cambios")
    print("=" * 80)
    
    operation = input("\nOpción (1/2/3): ").strip()
    
    if operation == '3':
        print("👋 Saliendo sin cambios...")
        exit(0)
    
    if operation not in ['1', '2']:
        print("❌ Opción inválida")
        exit(1)
    
    # 6. Seleccionar servicios
    print("\n" + "=" * 80)
    
    if operation == '1':
        print("AGREGAR PERMISOS")
        print("Ingresa los IDs de los servicios a AGREGAR")
        # Mostrar solo los que NO tiene
        available = [s['id'] for s in all_services if not any(p['id'] == s['id'] for p in current_perms)]
        if not available:
            print("\n⚠️  El usuario ya tiene TODOS los permisos disponibles")
            exit(0)
        print(f"Servicios disponibles para agregar: {', '.join(map(str, available))}")
    else:
        print("REVOCAR PERMISOS")
        print("Ingresa los IDs de los servicios a REVOCAR")
        # Mostrar solo los que SÍ tiene
        available = [p['id'] for p in current_perms]
        if not available:
            print("\n⚠️  El usuario no tiene permisos para revocar")
            exit(0)
        print(f"Servicios que tiene actualmente: {', '.join(map(str, available))}")
    
    print("\nPuedes ingresar:")
    print("  - IDs separados por comas: 1,3,5")
    print("  - Rangos: 1-5")
    print("  - 'all' para todos los disponibles")
    print("=" * 80)
    
    selection = input("\nServicios: ").strip()
    
    if operation == '1':
        valid_ids = [s['id'] for s in all_services]
    else:
        valid_ids = [p['id'] for p in current_perms]
    
    selected_ids = parse_selection(selection, valid_ids)
    
    if not selected_ids:
        print("\n⚠️  No se seleccionaron servicios válidos")
        exit(0)
    
    # 7. Confirmar
    print("\n" + "=" * 80)
    print(" RESUMEN DE CAMBIOS")
    print("=" * 80)
    print(f"Usuario: {selected_user['username']} (ID: {user_id})")
    print(f"Operación: {'AGREGAR' if operation == '1' else 'REVOCAR'} permisos")
    print(f"Cantidad: {len(selected_ids)} servicios")
    
    print("\nServicios seleccionados:")
    for sid in selected_ids:
        svc = next((s for s in all_services if s['id'] == sid), None)
        if svc:
            print(f"  • {svc['serviceName']} ({svc['serviceIP']}:{svc['servicePort']})")
    
    confirm = input("\n¿Confirmar cambios? (s/N): ").strip().lower()
    
    if confirm != 's':
        print("❌ Operación cancelada")
        exit(0)
    
    # 8. Aplicar cambios
    print("\n" + "=" * 80)
    print(" APLICANDO CAMBIOS...")
    print("=" * 80)
    
    if operation == '1':
        result = add_permissions(user_id, selected_ids)
    else:
        result = revoke_permissions(user_id, selected_ids)
    
    if result > 0:
        print("\n" + "=" * 80)
        print(" ✅ PERMISOS ACTUALIZADOS EXITOSAMENTE")
        print("=" * 80)
        
        # Mostrar permisos actualizados
        updated_perms = get_user_permissions(user_id)
        print(f"\nPermisos actuales del usuario: {len(updated_perms)}")
        
        if updated_perms:
            print("\nServicios activos:")
            for perm in updated_perms:
                print(f"  • {perm['serviceName']} ({perm['serviceIP']}:{perm['servicePort']})")
        else:
            print("\n⚠️  El usuario no tiene permisos asignados")
        
        print("=" * 80)
    else:
        print("\n⚠️  No se realizaron cambios")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Operación cancelada por el usuario")
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        import traceback
        traceback.print_exc()
