#! /usr/bin/env python
from scapy.all import *
import operator
from scipy import stats

TIMEOUT = 1
VERBOSE = False

def obtener_ruta(hostname):
    ruta = []
    tiempos = []
    for i in range(1, 30):
        pkt = IP(dst=hostname, ttl=i) / ICMP()
        # Mandar paquete y obtener reply
        # Guardar en 'ans' una lista de (send, reply) por cada envio (en este caso solo pkt)
        ans, unans = sr(pkt, verbose=0, timeout=TIMEOUT)

        if not ans:
            # No llego respuesta
            if VERBOSE: print "%d hops away: *" % i
            ruta.append("*")
            tiempos.append(-1)
            continue

        # Obtener paquete enviado y respuesta
        send, reply = ans[0]
        if reply is None:
            if VERBOSE: print "%d hops away: *" % i
            ruta.append("*")
            tiempos.append(-1)
        else:
            RTT  = (reply.time - send.sent_time) * 1000
            if VERBOSE: print "%d hops away: %s in %.4f ms" % (i , reply.src, RTT)
            ruta.append(reply.src)
            tiempos.append(RTT)
            if reply.type == 0:
                # Llegamos al destino (echo reply)
                if VERBOSE: print "Done!"
                break
    return ruta, tiempos

def calcular_ruta_comun(rutas):
    ruta_comun = []
    rutas_a_procesar = rutas
    for i in range(0, 29):
        hops_en_posicion_i = {}
        # Cuento cuantas veces aparece cada ip en el hop numero i
        for (ruta, tiempos) in rutas_a_procesar:
            if len(ruta) <= i:
                continue
            ip = ruta[i]
            if ip in hops_en_posicion_i:
                hops_en_posicion_i[ip] = hops_en_posicion_i[ip] + 1
            else:
                hops_en_posicion_i[ip] = 1

        if len(hops_en_posicion_i) == 0:
            break

        # Veo cual es la ip que aparece mas veces en el hop numero i
        ip_con_mas_apariciones = max(hops_en_posicion_i.iteritems(), key=operator.itemgetter(1))[0]
        ruta_comun.append(ip_con_mas_apariciones)

        # Filtro todas las rutas que no tenian esa ip en el hop numero i
        nuevas_rutas = []
        for (ruta, tiempos) in rutas_a_procesar:
            if ruta[i] == ip_con_mas_apariciones:
                nuevas_rutas.append((ruta, tiempos))
        rutas_a_procesar = nuevas_rutas
    print ruta_comun


if __name__ == "__main__":
    hostname = "google.com"
    rutas = []
    intentos = 10
    for j in range(1,intentos):
        print "Realizando traceroute %d" % j
        ruta, tiempos = obtener_ruta(hostname)
        rutas.append((ruta, tiempos))

    calcular_ruta_comun(rutas)
    print rutas
