#! /usr/bin/env python
import math
import statistics
from operator import itemgetter
from scipy import stats
from scapy.all import *

if __name__ == "__main__":
	if len(sys.argv) < 2:
        print ''
        print "Usage: " + sys.argv[0] + " <tipo> <datos>"
        print "\tDonde <tipo> puede ser: \"single\", \"pair\""
    elif len(sys.argv) > 2:
    	tipoOutlier = sys.argv[0]
        datos = sys.argv[1]
        cantDatos = len(datos)

        if tipoOutlier == "single":
        	min_, max_ = MinMax(datos)
        	media, desvio

        	media = statistics.mean(data)
		
        	desvio = statistics.stdev(data)

        	valorAbsolutoMin = abs(min_ - media)
        	valorAbsolutoMax = abs(max_ - media)

        	t_a2 = stats.t.ppf(1-(0.05/2.),cantDatos -2)
   		 	tau = (t_a2 * (cantDatos-1) ) /(math.sqrt(cantDatos) * math.sqrt(cantDatos-2 + t_a2**2))
    		tS = tau * desvio

        	if valorAbsolutoMax > valorAbsolutoMin:
        		if valorAbsolutoMax <= tS:
        			#Tengo que quitar el elemento
        			index
        			for i = 1 to cantDatos:
        				if datos[i] == _max:
        					index = i
        			datos.pop(index)
                    print "Se quito un outlier"
   			else: 
   				if valorAbsolutoMin <= tS:
   					#Tengo que quitar el elemento
   					index
        			for i = 1 to cantDatos:
        				if datos[i] == _min:
        					index = i
        			datos.pop(index)
                    print "Se quito un outlier"

        elif tipoOutlier == "pair":

        else:
            

