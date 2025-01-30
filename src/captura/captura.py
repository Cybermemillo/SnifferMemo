import socket
import platform
import struct
import string
import threading
import keyboard

pausado = False

def toggle_pausa():
    global pausado
    pausado = not pausado
    estado = "PAUSADA" if pausado else "REANUDADA"
    print(f"\n[!] Captura {estado}. Presiona 'ESPACIO' para continuar.")

def mostrar_paquete(eth, ip, tcp=None, udp=None, texto_legible=None):
    print(f"\nEthernet Frame:")
    print(f"  Dest MAC: {eth['dest_mac']}")
    print(f"  Src MAC: {eth['src_mac']}")
    print(f"  Protocol: {eth['eth_proto']}")
    if ip:
        print(f"  IPv4 Packet:")
        print(f"    Version: {ip['version']}")
        print(f"    TTL: {ip['ttl']}")
        print(f"    Protocol: {ip['proto']}")
        print(f"    Src IP: {ip['src_ip']}")
        print(f"    Dest IP: {ip['dest_ip']}")
    if tcp:
        print(f"    TCP Segment:")
        print(f"      Src Port: {tcp['src_port']}")
        print(f"      Dest Port: {tcp['dest_port']}")
        print(f"      Seq: {tcp['seq']}")
        print(f"      Ack: {tcp['ack']}")
        print(f"      Flags: {tcp['flags']}")
        print(f"      Window: {tcp['window']}")
        print(f"      Checksum: {tcp['checksum']}")
        print(f"      Urg Pointer: {tcp['urg_ptr']}")
    if udp:
        print(f"    UDP Segment:")
        print(f"      Src Port: {udp['src_port']}")
        print(f"      Dest Port: {udp['dest_port']}")
        print(f"      Length: {udp['longitud']}")
        print(f"      Checksum: {udp['checksum']}")
    if texto_legible:
        print(f"  📜 Contenido legible del paquete:\n{texto_legible}")

def extraer_texto_legible(data):
    try:
        # Decodificar como UTF-8, si falla usar latin-1
        text = data.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        text = data.decode('latin-1', errors='ignore')
    
    # Filtrar solo caracteres imprimibles
    texto_legible = ''.join(c if c in string.printable else '.' for c in text)
    
    return texto_legible if texto_legible.strip() else None

def obtener_interfaz_predeterminada():
    try:
        # Obtenemos nuestra IP local
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        
        # Creamos un socket para obtener la interfaza sociada a la IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        interfaz_ip = s.getsockname()[0]
        s.close()
        # Obtenemos la interfaz de red asociada a la IP
        if platform.system() == "Linux":
            # En Linux, podemos usar `socket.if_nameindex()` para obtener las interfaces
            interfaces = socket.if_nameindex()
            for interface in interfaces:
                if interface[1] == interfaz_ip:
                    return interface[1]
        elif platform.system() == "Windows":
            # En Windows, podemos usar `socket.gethostbyname_ex()` para obtener las interfaces
            interfaces = socket.gethostbyname_ex(socket.gethostname())[2]
            for interface in interfaces:
                if interface == interfaz_ip:
                    return interface
        
        # Si no encontramos la interfaz, devolvemos la primera interfaz activa
        return interfaces[0][1] if interfaces else None
    
    except Exception as e:
        print(f"Error al obtener la interfaz predeterminada: {e}")
        return None

def decodificar_paquete_ethernet(paquete):
    # Desempaquetamos el encabezado Ethernet (14 bytes)
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', paquete[:14])
    return {
        'dest_mac': ':'.join(f'{b:02x}' for b in dest_mac),
        'src_mac': ':'.join(f'{b:02x}' for b in src_mac),
        'eth_proto': socket.htons(eth_proto)
    }

def decodificar_paquete_ip(paquete):
    # Desempaquetamos el encabezado IP (20 bytes)
    version_longitud = paquete[0]
    version = version_longitud >> 4
    longitud_encabezado = (version_longitud & 0xF) * 4
    ttl, proto, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', paquete[:20])
    return {
        'version': version,
        'longitud_encabezado': longitud_encabezado,
        'ttl': ttl,
        'proto': proto,
        'src_ip': socket.inet_ntoa(src_ip),
        'dest_ip': socket.inet_ntoa(dest_ip)
    }

def decodificar_paquete_tcp(paquete):
    # Desempaquetamos el encabezado TCP (20 bytes)
    src_port, dest_port, seq, ack, offset_reservado, flags, window, checksum, urg_ptr = struct.unpack('! H H L L B B H H H', paquete[:20])
    offset = (offset_reservado >> 4) * 4
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'seq': seq,
        'ack': ack,
        'flags': flags,
        'window': window,
        'checksum': checksum,
        'urg_ptr': urg_ptr
    }

def decodificar_paquete_udp(paquete):
    # Desempaquetamos el encabezado UDP (8 bytes)
    src_port, dest_port, longitud, checksum = struct.unpack('! H H H H', paquete[:8])
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'longitud': longitud,
        'checksum': checksum
    }

def iniciar_captura(interface, filtro=None):
    global pausado
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((interface, 0))

        # Hilo para controlar la pausa
        keyboard.add_hotkey("space", toggle_pausa)

        print(f"Capturando paquetes en {interface}... Presiona 'ESPACIO' para pausar/reanudar.")

        while True:
            if pausado:
                continue  # Si está pausado, no hace nada

            paquete, _ = sock.recvfrom(65535)
            eth = decodificar_paquete_ethernet(paquete)

            if eth['eth_proto'] == 8:  # IPv4
                ip = decodificar_paquete_ip(paquete[14:])
                tcp, udp, texto_legible = None, None, None

                if ip['proto'] == 6:  # TCP
                    tcp = decodificar_paquete_tcp(paquete[14 + ip['longitud_encabezado']:])
                    payload = paquete[14 + ip['longitud_encabezado'] + tcp['src_port']:]
                    texto_legible = extraer_texto_legible(payload)

                    # Aplicar filtros
                    if filtro and not ((filtro == "HTTP" and (tcp['src_port'] == 80 or tcp['dest_port'] == 80 or tcp['src_port'] == 443 or tcp['dest_port'] == 443)) or
                                       (filtro == "FTP" and (tcp['src_port'] == 21 or tcp['dest_port'] == 21 or tcp['src_port'] == 20 or tcp['dest_port'] == 20))):
                        continue

                elif ip['proto'] == 17:  # UDP
                    udp = decodificar_paquete_udp(paquete[14 + ip['longitud_encabezado']:])
                    payload = paquete[14 + ip['longitud_encabezado'] + 8:]
                    texto_legible = extraer_texto_legible(payload)

                    if filtro == "DNS" and (udp['src_port'] != 53 and udp['dest_port'] != 53):
                        continue

                mostrar_paquete(eth, ip, tcp=tcp, udp=udp, texto_legible=texto_legible)

    except PermissionError:
        print("Error: Necesitas permisos de superusuario para capturar paquetes.")
    except Exception as e:
        print(f"Error inesperado: {e}")
    finally:
        if 'sock' in locals():
            sock.close()