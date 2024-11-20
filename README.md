# usuariosdj
proyecto de seccion de usuarios

Para ejecutar el proyecto:
1. Activar el entorno virtual
2. Situarse a la altura del archivo manage,py
3. Escribir en la terminal py manage.py runserver


Para hacer migraciones:
1. Activar el entorno virtual
2. Situarse a la altura del archivo manage,py
3. Escribir en la terminal py manage.py makemigrations
4. Escribir en la terminal py manage.py migrate


NOTA: Crear un archivo secret.json en usuariosdj/usuarios y rellenarlo con la siguiente información:
{
    "FILENAME": "secret.json",
    "SECRET_KEY": "django-insecure-6l@0*j30ix0*@^_o@ia1weqb_z^e-)eidbm==_^6i0tz&liime",
    "DB_NAME": "dbusers",
    "USER": "postgres",
    "PASSWORD": "tucontraseña",
    "EMAIL": "tucorreo",
    "PASS_EMAIL": "tu contraseña de aplicaciones(generarla desde tu configuracion de google)"
}
