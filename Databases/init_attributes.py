#!/usr/bin/env python3
import mysql.connector

config = {
    'user': 'campus',
    'password': 'SQLgrupo3?',
    'host': 'localhost',
    'database': 'DB_Permissions'
}

conn = mysql.connector.connect(**config)
cur = conn.cursor()

# Limpiar todo para poder volver a ejecutar sin errores
cur.execute("SET FOREIGN_KEY_CHECKS = 0")
cur.execute("TRUNCATE TABLE User_has_AttributeValue")
cur.execute("TRUNCATE TABLE AttributeValue")
cur.execute("TRUNCATE TABLE Attribute")
cur.execute("SET FOREIGN_KEY_CHECKS = 1")

# Crear atributos
cur.execute("INSERT INTO Attribute (name) VALUES ('Rol'), ('Facultad')")
conn.commit()

# Obtener IDs
cur.execute("SELECT idAttribute, name FROM Attribute")
attrs = {row[1]: row[0] for row in cur.fetchall()}
id_rol = attrs['Rol']
id_fac = attrs['Facultad']

# Roles
for rol in ['Estudiante', 'Profesor', 'Administrativo', 'Administrador TI', 'Invitado']:
    cur.execute("INSERT INTO AttributeValue (value, attribute_id) VALUES (%s, %s)", (rol, id_rol))

# Facultades
for fac in ['Ingeniería Civil', 'Ingeniería Industrial', 'Ingeniería de las Telecomunicaciones']:
    cur.execute("INSERT INTO AttributeValue (value, attribute_id) VALUES (%s, %s)", (fac, id_fac))

conn.commit()
cur.close()
conn.close()

print("Atributos creados correctamente:")
print("→ Rol: Estudiante, Profesor, Administrativo, Administrador TI, Invitado")
print("→ Facultad: Ingeniería Civil, Ingeniería Industrial, Ingeniería de las Telecomunicaciones")
