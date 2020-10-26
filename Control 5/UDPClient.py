import socket
import sys

#Creando el socket del cliente
client_sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#Asignamos direcion y puerto
server_address = ('localhost', 10000)

#Lectura del archivo en modo binario
f=open("200MB.zip","rb")
#De estos, primero se enviarán 65.000 bytes
data=f.read(65500)

while(data): #Este iterará hasta que se envie todo el archivo
    #El socket envia los primero dados al servidor 
    if(client_sock.sendto(data, server_address)): 
        #Se vuelve a leer 65.000 bytes del archivo
        data= f.read(65500)

f.close()
print("Enviado el archivo!")

#Se cierra la conexión
client_sock.close()


