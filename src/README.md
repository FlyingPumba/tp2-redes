### Dependencias
* `sudo pip install scapy`
* `sudo pip install scipy`

### Traceroute normal
Para hacer un traceroute similar al que viene por defecto en Ubuntu, ejecutar `sudo ./traceroute.py <IP>`

### Traceroute debug
Este modo se obtiene al ejecutar `sudo ./traceroute.py <IP> -d`, y se puede utilizar para obtener los mismos resultados que se utilizaron en el TP. Los pasos que realiza son:
- 50 traceroutes
- Calcular la ruta habitual
- Calcular tiempos promedio de la ruta habitual
- Obtener información de geolocalización para las IPs de la ruta habitual, utilizando la herramienta ipinfo.io
