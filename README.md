# SnifferMemo

SnifferMemo es un sniffer de paquetes en Python que captura y analiza el tráfico de red en tiempo real. Soporta la captura de paquetes Ethernet, IP, TCP y UDP, además de permitir filtrado por protocolos y la opción de pausar/reanudar la captura con una tecla.

Es mi primera aproximación al mundo de la Ciberseguridad junto a Python.

## Características
- Captura paquetes en interfaces de red específicas.
- Decodificación de cabeceras Ethernet, IP, TCP y UDP.
- Visualización de datos legibles en los paquetes.
- Pausar y reanudar la captura con la tecla `ESPACIO`.
- Filtrado de tráfico por protocolos específicos (HTTP, FTP, etc.).

## Requisitos

Este sniffer requiere **Python 3.x** y dependencias adicionales. Para instalarlas:
```bash
pip install -r requirements.txt
```
### Dependencias
- `keyboard`: Para gestionar la pausa/reanudación del sniffer.
- `scapy` (opcional): Para futuras mejoras en el análisis de paquetes.

## Instalación
Clona el repositorio y entra en el directorio:
```bash
git clone https://github.com/tuusuario/SnifferMemo.git
cd SnifferMemo
```

## Uso
Ejecuta el sniffer con permisos de superusuario:
```bash
sudo python src/main.py
```
Para especificar una interfaz de red:
```bash
sudo python src/main.py -i eth0
```
### Controles
- **ESPACIO** → Pausa/Reanuda la captura de paquetes.

## Estructura del Proyecto
```
SnifferMemo/
├── src/
│   ├── captura/
│   │   ├── captura.py  # Módulo de captura y análisis de paquetes
│   ├── main.py         # Archivo principal de ejecución
├── test/
│   ├── test_analisis.py  # Pruebas de análisis de paquetes
│   ├── test_captura.py   # Pruebas de captura
│   ├── test_filtrado.py  # Pruebas de filtrado
├── README.md          # Manual de uso
├── requirements.txt   # Dependencias del proyecto
```

## Mejoras Futuras
- Soporte para más protocolos (DNS, ARP, ICMP...).
- Exportar capturas a formato `.pcap`.

## Licencia
Este proyecto se distribuye bajo la **MIT License