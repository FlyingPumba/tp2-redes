#! /usr/bin/env python
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import operator
from scipy import stats
from outliers import *

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

def calcular_ruta_comun(rutas_y_tiempos):
    ruta_comun = []
    rutas_a_procesar = rutas_y_tiempos
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

    return ruta_comun, [tiempos for (ruta, tiempos) in rutas_a_procesar]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print ''
        print "Usage: " + sys.argv[0] + " <IP>"
        exit(1)

    ip = sys.argv[1]

    rutas_y_tiempos = []
    intentos = 10
    for j in range(1,intentos):
        print "Realizando traceroute %d a IP %s" % (j, ip)
        ruta, tiempos = obtener_ruta(ip)
        rutas_y_tiempos.append((ruta, tiempos))

    print ""

    ruta_comun, tiempos = calcular_ruta_comun(rutas_y_tiempos)
    print "\tRuta establecida: %s\n" % ruta_comun
    print "\tTiempos obtenidos para la ruta:\n%s" % tiempos
    # Para cada hop, saco los outliers de los tiempos
    tiempos_sin_outliers = []
    for hop in xrange(len(tiempos[0])):
        if ruta_comun[hop] == "*":
            tiempos_sin_outliers.append(-1)
            continue
        # Guardo en una lista todos los tiempos de un hop
        tiempos_hop = []
        for tiempo in tiempos:
            tiempos_hop.append(tiempo[hop])
        quitarOutliers(tiempos_hop)
        tiempos_sin_outliers.append(calcularMedia(tiempos_hop))

    print ""
    print "\tTiempos sin outliers y promediados: %s\n" % tiempos_sin_outliers

    # Busco maximo delta en tiempos para ver posible candidato a salto continental
    max_delta = -1
    last_time = tiempos_sin_outliers[0]
    ip_src_salto = ""
    ip_dst_salto = ""
    for i in range(1, len(tiempos_sin_outliers)):
        new_time = tiempos_sin_outliers[i]
        if new_time != -1 and last_time != -1:
            delta = new_time - last_time
            if delta < 0:
                print "\tWarning: salto negativo entre los hops %d y %d" % (i-1, i)
            if delta > max_delta:
                max_delta = delta
                ip_src_salto = ruta_comun[i-1]
                ip_dst_salto = ruta_comun[i]
        last_time = new_time

    print "\nPosible salto continental entre las IPs: %s - %s" % (ip_src_salto, ip_dst_salto)
