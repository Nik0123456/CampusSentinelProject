#!/usr/bin/env python3
# registro_usuario_plain.py
import mysql.connector
import getpass

RADIUS_DB = {
    'user': 'campus',
    'password': 'SQLgrupo3?',
    'host': 'localhost',
    'database': 'radius'
}

MYDB = {
    'user': 'campus',
    'password': 'SQLgrupo3?',
    'host': 'localhost',
    'database': 'mydb'
}

print("REGISTRO DE USUARIO (contraseña en texto plano)\n")

email = input("Email del usuario: ").strip().lower()
if not email:
    exit("Email obligatorio")

while True:
    p1 = getpass.getpass("Contraseña: ")
    p2 = getpass.getpass("Repetir contraseña: ")
    if p1 == p2 and p1:
        password = p1
        break
    print("No coinciden o está vacía\n")

# Guardar en RADIUS (texto plano)
conn = mysql.connector.connect(**RADIUS_DB)
cur = conn.cursor()

# Borrar entradas anteriores
cur.execute("DELETE FROM radcheck WHERE UserName = %s", (email,))

# Insertar en tabla oficial
cur.execute("""
    INSERT INTO radcheck (UserName, attribute, op, value)
    VALUES (%s, 'Cleartext-Password', ':=', %s)
""", (email, password))

conn.commit()
cur.close()
conn.close()

# Guardar en mydb para CampusSentinel
conn2 = mysql.connector.connect(**MYDB)
cur2 = conn2.cursor()
cur2.execute("""
    INSERT INTO User (username, session_active, session_token)
    VALUES (%s, 0, NULL)
    ON DUPLICATE KEY UPDATE username=username
""", (email,))
conn2.commit()
conn2.close()

print(f"\nUSUARIO '{email}' CREADO CORRECTAMENTE")

