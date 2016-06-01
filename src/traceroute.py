#! /usr/bin/env python
from scapy.all import *

if __name__ == "__main__":
    hostname = "google.com"
    for i in range(1, 30):
        pkt = IP(dst=hostname, ttl=i) / ICMP()
        # Mandar paquete y obtener reply
        # Guardar en 'ans' una lista de (send, reply) por cada envio (en este caso solo pkt)
        ans, unans = sr(pkt, verbose=0, timeout=2)
        # Obtener paquete enviado y respuesta
        send, reply = ans[0]
        if reply is None:
            print "%d hops away: *" % i
        elif reply.type == 0:
            # Llegamos al destino (echo reply)
            RTT  = (reply.time - send.sent_time) * 1000
            print "%d hops away: %s in %.4f ms" % (i , reply.src, RTT)
            print "Done!"
            break
        else:
            # Estamos en un hop intermedio (time-exceeded)
            RTT  = (reply.time - send.sent_time) * 1000
            print "%d hops away: %s in %.4f ms" % (i , reply.src, RTT)
