Autores:

    Tony Flores - Nik0123456
    Christian Flores - Cjfs2005
    
Comentario del autor: 

    Para trabajar en versiones más complejas que implementen nuevas funcionalidades y que requieran trabajo colaborativo 
    se está diseñando el codigo de este proyecto de forma modular. Los módulos de python se pueden ejecutar independientemente cada uno, pero los módulos de java están escritos para ser compilados junto al controlador Floodlight

Recomendaciones: 

    El proyecto se ha desarrollado para que emplee un entorno virtual. El entorno virtual permite 
    que este proyecto tenga sus propias versiones de Python y librerías instaladas, aisladas del sistema 
    o de otros proyectos. Esto evita conflictos de dependencias, hace que el proyecto sea portable y facilita 
    que otros colaboradores instalen exactamente las mismas librerías necesarias para ejecutar el código. 

    Para crear un nuevo venv y acceder a este:

        1) Creación
        
        python -m venv venv
        
        2) Ejecucion 
        source venv/bin/activate  # Linux/Mac
        .\venv\Scripts\activate   # Windows
        
    Las librerias empleadas están especificadas en el archivo requirements.txt

    Puede instalar las librerias manualmente o usando: 
        
        pip install -r requirements.txt

    En caso instale más librerias y quiera compartirlas puede emplear el 
    siguiente comando para exportarlas en el archivo txt: 
    
        pip freeze > requirements.txt

    Para salir del venv solo necesita usar en su terminal: 
    
        deactivate
