# Tunneling-ICMP

Servidor mixto desarrollado en Python para el envio de datos cifrados a traves de ICMP. Usando la libreria Scapy el script controla el trafico de la red entrante para detectar si ha llegado un paquete ICMP y en tal caso tratar de descifrar el contenido de la seccion de datos. Los datos son cifrados por una contraseña previa que los dos nodos de comunicacion deben de conocer previamente.

Requerimientos:

  - Scapy -> pip install scapy
  - Uso de contraseña de 16 caracteres de tamaño
  - Mensaje de no mas de 320 bytes

Para iniciar el programa se puede realizar mediante la linea de comandos con el siguiente formato:

  python icmp_mail.py [interfaz] [ip_destino] [ip_host] [contraseña]
  
Para iniciar el programa con intercambio de datos manual:

  python icmp_mail.py
