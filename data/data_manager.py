#!/usr/bin/python3

import yaml

class DataManager:

    def __init__(self, metadata=None):
        self.metadata = metadata if metadata else {}

    def load_yaml(self, file_path):
        try:
            with open(file_path, encoding="utf-8") as file:
                data = yaml.safe_load(file)
                return data
        except FileNotFoundError:
            print(f"No se encontró el archivo {file_path}")
            return None
        except Exception as e:
            print(f"Error leyendo YAML: {e}")
            return None

    
    def export_yaml(self, file_path, data):
        try:
            with open(file_path, 'w', encoding="utf-8") as file:
                yaml.safe_dump(data, file, allow_unicode=True, sort_keys=False, indent=4)
                print(f"Datos exportados a {file_path}")
        except Exception as e:
            print(f"Error exportando YAML: {e}")