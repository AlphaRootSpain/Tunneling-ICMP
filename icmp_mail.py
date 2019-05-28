import sys, os
from scapy.all import *
from threading import Thread
from Crypto.Cipher import AES
from termcolor import colored
import random
import time


ip_host = None
ip_dest = None
password = None
iface = None
cipher = None

def dialogo_inicial():
	global ip_host, ip_dest, password, iface, cipher
	if len(sys.argv) > 2:
		iface = sys.argv[1]
		ip_dest = sys.argv[2]
		ip_host = sys.argv[3]
		password = sys.argv[4]

	else:
		iface = raw_input("Introduzca la red local -> ")
		ip_dest = raw_input("Introduzca IP de destino -> ")
		ip_host = raw_input("Introduzca IP local -> ")
		password = raw_input("Introduzca la password -> ")


def busqueda_icmp(pkt):
	if pkt[IP].dst == ip_host:
		carga_util = pkt.load
		carga_descifrada = cipher.decrypt(carga_util.split(" ")[0])
		print(colored("[*] ", "green") + carga_descifrada)

def thread_de_escucha():
	sniff(iface=iface, prn=busqueda_icmp, filter="icmp")


def loop_de_envio():
	while True:
		mensaje = raw_input("[>] ")
		mensaje_encriptado = cipher.encrypt(mensaje.rjust(320))
		send(IP(frag=0, src=ip_host, proto=1, tos=0, dst=ip_dest, chksum=random.randrange(50000), options=[], version=4)/ \
			ICMP(gw=None, code=0, ts_ori=None, addr_mask=None, seq=1, nexthopmtu=None, ptr=None, unused=None, ts_rx=None, length=None, chksum=random.randrange(50000), reserved=None, ts_tx=None, type=0, id=random.randrange(5000))/ \
			Raw(load= mensaje_encriptado + ' !\"#$%&\\\'()*+,-./01234567\\'),verbose = 0)


def main():
	#Limpiar pantalla
	os.system("clear")

	#Actualizacion de parametros iniciales
	dialogo_inicial()

	#Creando util de encritacion
	global cipher
	cipher = AES.new(password, AES.MODE_ECB)

	#Creando hilo de esnifado
	Thread(target=thread_de_escucha).start()

	#Creando interfaz
	time.sleep(1)
	os.system("clear")
	print("\t" * 5 + colored("~ ICMP SECURE MESSENGER ~", "red") + "\n")

	#Enviador de paquetes
	loop_de_envio()


if __name__ == '__main__':
	main()


#PROYECTOS DE MEJORA

# 1 - Adaptarse a la medida de los ICMP corrientes para pasar mas desapercibido

# 2 - Calcular correctamente el check-sum