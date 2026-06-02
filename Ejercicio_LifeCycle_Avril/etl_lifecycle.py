import pandas as pd
import numpy as np
import os
import logging
from sqlalchemy import create_engine, text
from datetime import datetime
import glob


#--------------
# Config Logs |
#--------------

os.makedirs('logs', exist_ok=True)
ruta_logs = 'logs/etl_lifecycle.log'

'''
1- comprobar qeu los archivos son csvs 
2- preguntar por  df_catalogo = pd.read_csv('catalogo.csv', sep=';') SEP=';' en decimales

'''

logging.basicConfig(
    filename=ruta_logs,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a', 
    force=True 
)
logging.info("Prueba log- todo funcionando")


#---------------------------
# Extracción de los fichero |
#----------------------------


try:
    logging.info("Iniciando la fase de extraccion de ficheros CSV")

    ruta_csvs = 'csv/*.csv'
    archivos_csv = glob.glob(ruta_csvs)

    #aquí voy a ir guardando los datos de cada archivo
    lista_dataframes =[]
    logging.info(f"Hay {len(archivos_csv)}varchivos para procesar")

    for archivo in archivos_csv:
        logging.info(f"Leyendo el fichero: {archivo} ...")

        #1º obtengo el nombre del archivo y le quito la extensión
        nombre_base = os.path.basename(archivo)
        fecha_auditoria = nombre_base.replace('.csv', '')

        #2º guardo todo el contenido de uno y lo guardo en un df
        df_auxiliar = pd.read_csv(archivo)

        #3º creo una columna nueva con todos los registros de ese archivo
        df_auxiliar['Audit_Date'] = fecha_auditoria

        #4º lo guardo en la lista_dataframes
        lista_dataframes.append(df_auxiliar)
        
        logging.info(f"Fichero {nombre_base} leido. Filas extraidas: {len(df_auxiliar)}")


    df_total = pd.concat(lista_dataframes) #uno TODOS los df de los ficheros

    logging.info(f"Extraccion de datos hecha, están todos los datos. Hay {len(df_total)} filas")

except Exception as e:
    logging.error(f"Fallo en la extraccion: {e}")



#--------
# SONAR |
#--------

try:
    logging.info("Iniciando limpieza del test Sonar:")

    # 1. recorto el DataFrame gigante para trabajar solo con lo de Sonar
    columnas_sonar = ['appName', 'startTime', 'Sonar', 'resultSonarAnalysis', 'Audit_Date']
    df_sonar = df_total[columnas_sonar].copy()

    # 2. borro los duplicados
    df_sonar = df_sonar.drop_duplicates(subset=['appName'])

    # 3. renombro startTme
    df_sonar = df_sonar.rename(columns={'startTime': 'startTime_Sonar'})

    # 4. toPassSonar = true si 'sonar' no es null
    df_sonar['ToPassSonar'] = df_sonar['Sonar'].notna() #así se rellena el campo si SÍ es null 'true', de lo contrario 'false

    #SonarTest; si 'resultSonarAnalysis está vacío ='KO'
    df_sonar['SonarTest'] = df_sonar['resultSonarAnalysis'].fillna('KO')


    logging.info(f"Tabla Sonar limpia con {len(df_sonar)} aplicaciones únicas")
    print("Tabla 'Sonar' limpia")

except Exception as e:
    logging.error(f"Error durante la limpieza de Sonar {e}")





#----------
# FORTIFY |
#----------

try:
    logging.info("Iniciando limpieza del test Fortity:")

    # 1. recorto el DataFrame gigante para trabajar solo con lo de Fortity
    columnas_Fortify = ['appName', 'startTime', 'forfify_security_test', 'fortify_security_high', 'fortify_security_critical']
    df_Fortify = df_total[columnas_Fortify].copy()

    # 2. borro los duplicados
    df_Fortify = df_Fortify.drop_duplicates(subset=['appName'])

    # 3. renombro startTme
    df_Fortify = df_Fortify.rename(columns={'startTime': 'startTime_Fortify'})

    # 4. relleno los nullos con 0.
    df_Fortify['fortify_security_critical'] = df_Fortify['fortify_security_critical'].fillna(0)
    df_Fortify['fortify_security_high'] = df_Fortify['fortify_security_high'].fillna(0)

    # 5. toPassFority = true si 'forfify_security_test' no es null
    df_Fortify['ToPassFortify'] = df_Fortify['forfify_security_test'].notna()

    # 6. la funcion que decide la nota nota
    def calcular_fortify(fila):
        if (fila['fortify_security_high'] + fila['fortify_security_critical']) ==0: 
            return 'OK' 
        elif fila['fortify_security_high'] > 0 and fila['fortify_security_critical'] > 0:
            return 'High&Critical'
        elif fila['fortify_security_high'] > 0:
            return 'High' 
        elif fila['fortify_security_critical']> 0:
            return 'Critical'
        else:
            return 'Desconocido' 

    df_Fortify['FortifyTest'] = df_Fortify.apply(calcular_fortify, axis=1)
    logging.info('Tabla fortify calculada completa')

    print("Tabla Fortify lista")
    print(df_Fortify)

except Exception as e:
    logging.error("Error en la limpieza de fortify")





#--------
# TRIVY |
#--------

try:
    logging.info("Iniciando limpieza del test Trivy:")
    # 1
    columnas_Trivy = ['appName', 'startTime', 'trivy_security_test', 'trivy_security_high', 'trivy_security_critical']
    df_Trivy = df_total[columnas_Trivy].copy()

    # 2.
    df_Trivy= df_Trivy.drop_duplicates(subset=['appName'])

    # 3.
    df_Trivy = df_Trivy.rename(columns={'startTime': 'startTime_Trivy'})

    # 4.
    df_Trivy['trivy_security_critical'] = df_Trivy['trivy_security_critical'].fillna(0)
    df_Trivy['trivy_security_high'] = df_Trivy['trivy_security_high'].fillna(0)

    # 5
    df_Trivy['ToPassTrivy'] = df_Trivy['trivy_security_test'].notna() 

    # 6. 
    def calcular_Trivy(fila):
        if (fila['trivy_security_high'] + fila['trivy_security_critical']) == 0: 
            return 'OK'  
        elif fila['trivy_security_high'] > 0 and fila['trivy_security_critical'] > 0:
            return 'High&Critical'
        elif fila['trivy_security_high'] > 0: 
            return 'High' 
        elif fila['trivy_security_critical']> 0:
            return 'Critical' 
        else:
            return 'Desconocido' 

    df_Trivy['TrivyTest'] = df_Trivy.apply(calcular_Trivy, axis=1)

    logging.info("Tabla Trivy calculada y completa.")
    print("Tabla 'Trivy' limpia")

except Exception as e:
    print(f"Error: {e}")
    logging.error(f"Error durante la limpieza de Tryvy: {e}")




#--------
# MERGE |
#--------

try:

    logging.info("Iniciando la fusión de las tablas Sonar, Fortify y Trivy")

    # 1. uno Sonar y Fortify
    df_aux = pd.merge(
        df_sonar, 
        df_Fortify,  
        on='appName', 
        how='outer'
    )

    # 2. 
    df_final = pd.merge(
        df_aux,
        df_Trivy,
        on='appName', 
        how='outer'
    )

    logging.info(f"Fusión terminada con {len(df_final)} registros finales")


    # pongo la fecha de hoy por seguir con el diseño
    fecha_hoy = datetime.now().strftime('%Y-%m-%d')
    nombre_archivo_final = f'Auditoria_Lifecycle_{fecha_hoy}.csv'

    # gruardo en la carpeta propia
    df_final.to_csv(nombre_archivo_final, index=False)

    logging.info(f"ARCHIVO FINAL GENERADO: {nombre_archivo_final}")
    logging.info("FIN DE LA  ETL")

    print(f"Limpieza completada: Datos limpios en: {nombre_archivo_final}")


except Exception as e:
    print(f"Error {e}") 
    logging.error(f"Error durante la función final MERGE {e}")



