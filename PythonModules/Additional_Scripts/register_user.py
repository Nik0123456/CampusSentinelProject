#!/usr/bin/env python3
"""
Script para registrar usuario con selección de servicios/permisos
Permite elegir qué servicios puede acceder el usuario
"""
import mysql.connector
import getpass

DB_CONFIG = {
    'user': 'campus',
    'password': 'SQLgrupo3?',
    'host': 'localhost',
    'database': 'DB_Permissions'
}

RADIUS_DB = {
    'user': 'radius',
    'password': 'RadiusPass2025!',
    'host': 'localhost',
    'database': 'radius'
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

def get_radius_db():
    return mysql.connector.connect(**RADIUS_DB)

def list_available_services():
    """Lista todos los servicios disponibles en la tabla Permission"""
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

def register_user_radius(email, password):
    """Registra usuario en FreeRADIUS"""
    try:
        conn = get_radius_db()
        cur = conn.cursor()
        
        # Verificar si ya existe
        cur.execute("SELECT COUNT(*) FROM radcheck WHERE username=%s", (email,))
        if cur.fetchone()[0] > 0:
            print(f"\n⚠️  Usuario '{email}' ya existe en RADIUS. Actualizando contraseña...")
            cur.execute("DELETE FROM radcheck WHERE username=%s", (email,))
        
        # Insertar credenciales
        cur.execute("""
            INSERT INTO radcheck (username, attribute, op, value)
            VALUES (%s, 'Cleartext-Password', ':=', %s)
        """, (email, password))
        
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"✅ Usuario registrado en RADIUS: {email}")
        return True
        
    except mysql.connector.Error as e:
        print(f"❌ Error al registrar en RADIUS: {e}")
        return False

def register_user_db(email, is_guest=False):
    """Registra usuario en DB_Permissions"""
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Verificar si ya existe
        cur.execute("SELECT idUser FROM User WHERE username=%s", (email,))
        existing = cur.fetchone()
        
        if existing:
            user_id = existing[0]
            print(f"\n⚠️  Usuario '{email}' ya existe en DB_Permissions (ID: {user_id})")
        else:
            # Crear usuario
            cur.execute("""
                INSERT INTO User (username, is_guest, session_active)
                VALUES (%s, %s, 0)
            """, (email, is_guest))
            
            user_id = cur.lastrowid
            conn.commit()
            print(f"✅ Usuario creado en DB_Permissions (ID: {user_id})")
        
        cur.close()
        conn.close()
        
        return user_id
        
    except mysql.connector.Error as e:
        print(f"❌ Error al registrar en DB: {e}")
        return None

def assign_services_to_user(user_id, service_ids):
    """Asigna servicios (permisos) al usuario mediante AttributeValues"""
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        
        # Obtener los attributevalue_id de los servicios seleccionados
        if not service_ids:
            print("\n⚠️  No se seleccionaron servicios")
            return 0
        
        placeholders = ','.join(['%s'] * len(service_ids))
        cur.execute(f"""
            SELECT DISTINCT attributevalue_id 
            FROM Permission 
            WHERE id IN ({placeholders})
        """, service_ids)
        
        attribute_values = [row['attributevalue_id'] for row in cur.fetchall()]
        
        if not attribute_values:
            print("\n⚠️  No se encontraron atributos para los servicios seleccionados")
            return 0
        
        # Insertar relaciones User_has_AttributeValue
        inserted = 0
        for av_id in attribute_values:
            try:
                cur.execute("""
                    INSERT IGNORE INTO User_has_AttributeValue (user_id, attributevalue_id)
                    VALUES (%s, %s)
                """, (user_id, av_id))
                if cur.rowcount > 0:
                    inserted += 1
            except mysql.connector.Error:
                pass  # Ignorar duplicados
        
        # Inicializar User_Permission_Usage con usage_count=0 para todos los servicios asignados
        # Esto permite que el sistema de carga proactiva funcione desde el inicio
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
                    pass  # Ignorar duplicados
            
            if usage_initialized > 0:
                print(f"✅ Inicializadas {usage_initialized} estadísticas de uso para el usuario")
        
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"✅ Asignados {inserted} atributos (roles/cursos) al usuario")
        return inserted
        
    except mysql.connector.Error as e:
        print(f"❌ Error al asignar servicios: {e}")
        return 0

def main():
    print("=" * 70)
    print(" REGISTRO DE USUARIO - Campus Sentinel SDN")
    print("=" * 70)
    
    # 1. Datos del usuario
    email = input("\nEmail del usuario: ").strip().lower()
    if not email or '@' not in email:
        exit("❌ Email inválido")
    
    # 2. Contraseña
    while True:
        p1 = getpass.getpass("Contraseña: ")
        p2 = getpass.getpass("Repetir contraseña: ")
        if p1 == p2 and len(p1) >= 4:
            password = p1
            break
        print("❌ Las contraseñas no coinciden o son muy cortas (mín 4 caracteres)\n")
    
    # 3. Tipo de usuario
    print("\nTipo de usuario:")
    print("  1) Usuario regular (permanente)")
    print("  2) Usuario invitado (temporal)")
    tipo = input("Selecciona (1/2) [1]: ").strip() or "1"
    is_guest = (tipo == "2")
    
    # 4. Listar servicios disponibles
    print("\n" + "=" * 70)
    print(" SERVICIOS DISPONIBLES")
    print("=" * 70)
    
    services = list_available_services()
    
    if not services:
        print("❌ No hay servicios disponibles. Ejecuta init_attributes.py primero.")
        exit(1)
    
    print("\n{:<4} {:<35} {:<15} {:<8} {:<10} {:<20}".format(
        "ID", "Nombre del Servicio", "IP", "Puerto", "Protocolo", "Requiere Atributo"))
    print("-" * 110)
    
    for svc in services:
        print("{:<4} {:<35} {:<15} {:<8} {:<10} {:<20}".format(
            svc['id'],
            svc['serviceName'][:34],
            svc['serviceIP'],
            svc['servicePort'],
            svc['serviceProtocol'],
            svc['required_attribute'][:19]
        ))
    
    # 5. Seleccionar servicios
    print("\n" + "=" * 70)
    print("Selecciona los servicios que el usuario puede acceder")
    print("Puedes ingresar:")
    print("  - Números separados por comas: 1,3,5,7")
    print("  - Rangos: 1-5")
    print("  - Combinación: 1,3-7,10")
    print("  - 'all' para todos los servicios")
    print("=" * 70)
    
    selection = input("\nServicios: ").strip()
    
    if not selection:
        print("⚠️  No se seleccionaron servicios. Usuario creado sin permisos.")
        selected_ids = []
    elif selection.lower() == 'all':
        selected_ids = [svc['id'] for svc in services]
        print(f"✅ Seleccionados TODOS los servicios ({len(selected_ids)})")
    else:
        # Parsear selección
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
        
        # Filtrar IDs válidos
        valid_ids = [svc['id'] for svc in services]
        selected_ids = [sid for sid in selected_ids if sid in valid_ids]
        
        print(f"✅ Seleccionados {len(selected_ids)} servicios")
    
    # 6. Confirmar
    print("\n" + "=" * 70)
    print(" RESUMEN")
    print("=" * 70)
    print(f"Usuario: {email}")
    print(f"Tipo: {'Invitado (temporal)' if is_guest else 'Regular (permanente)'}")
    print(f"Servicios: {len(selected_ids)}")
    
    if selected_ids:
        print("\nServicios seleccionados:")
        for sid in selected_ids:
            svc = next((s for s in services if s['id'] == sid), None)
            if svc:
                print(f"  • {svc['serviceName']} ({svc['serviceIP']}:{svc['servicePort']})")
    
    confirm = input("\n¿Confirmar registro? (s/N): ").strip().lower()
    
    if confirm != 's':
        print("❌ Registro cancelado")
        exit(0)
    
    # 7. Registrar usuario
    print("\n" + "=" * 70)
    print(" REGISTRANDO USUARIO...")
    print("=" * 70)
    
    # Paso 1: RADIUS
    if not register_user_radius(email, password):
        exit(1)
    
    # Paso 2: DB_Permissions
    user_id = register_user_db(email, is_guest)
    if not user_id:
        exit(1)
    
    # Paso 3: Asignar servicios
    if selected_ids:
        assign_services_to_user(user_id, selected_ids)
    
    # 8. Éxito
    print("\n" + "=" * 70)
    print(" ✅ USUARIO REGISTRADO EXITOSAMENTE")
    print("=" * 70)
    print(f"Email: {email}")
    print(f"ID: {user_id}")
    print(f"Servicios asignados: {len(selected_ids)}")
    print("\nEl usuario ya puede autenticarse con campus_client.py")
    print("=" * 70)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Registro cancelado por el usuario")
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        import traceback
        traceback.print_exc()

