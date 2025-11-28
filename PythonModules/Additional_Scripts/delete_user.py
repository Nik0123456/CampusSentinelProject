#!/usr/bin/env python3
import mysql.connector

RADIUS = {
    'user': 'campus',
    'password': 'SQLgrupo3?',
    'host': 'localhost',
    'database': 'radius'
}

MYDB = {
    'user': 'campus',
    'password': 'SQLgrupo3?',
    'host': 'localhost',
    'database': 'DB_Permissions'
}

email = input("Email del usuario a eliminar: ").strip().lower()
if not email:
    print("Email obligatorio")
    exit(1)

# RADIUS
conn_r = mysql.connector.connect(**RADIUS)
cur_r = conn_r.cursor()

cur_r.execute("DELETE FROM radcheck WHERE UserName = %s", (email,))
cur_r.execute("DELETE FROM radusergroup WHERE UserName = %s", (email,))

conn_r.commit()
conn_r.close()

# mydb
conn_m = mysql.connector.connect(**MYDB)
cur_m = conn_m.cursor()

# Borrar relaciones
cur_m.execute("""
    DELETE FROM User_has_AttributeValue 
    WHERE user_id = (SELECT idUser FROM User WHERE username = %s)
""", (email,))

# Borrar usuario
cur_m.execute("DELETE FROM User WHERE username = %s", (email,))

conn_m.commit()
conn_m.close()

print(f"Usuario '{email}' eliminado completamente de ambas bases de datos")

