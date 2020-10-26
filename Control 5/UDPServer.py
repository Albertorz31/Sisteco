import socket
import sys

#Creando el socket del servidor
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#Se enlaza el servidor a una ip con un puerto
server_address = ('localhost', 10000)
sock.bind(server_address)

#Se crea un ciclo el cual estará esperando que le lleguen mensajes
while True:
    print('\nEsperando recibir un mensaje')
    #Cuando llega, se guarda su contenido y la dirección del emisor
    data, address = sock.recvfrom(65500)
    print('recibidos {} bytes desde {}'.format(len(data), address))
    


    
