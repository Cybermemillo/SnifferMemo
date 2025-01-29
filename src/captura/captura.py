import socket
import platform
import struct

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

def iniciar_captura(interface):
    # Creamos un socket en bruto para capturar paquetes
    try:
        # AF_PACKET y SOCK_RAW son específicos de Linux para capturar paquetes en bruto
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        # Asociamos el socket a la interfaz especificada
        sock.bind((interface, 0))
        print(f"Capturando paquetes en {interface}...")
        while True:
            # Capturamos un paquete
            paquete, _ = sock.recvfrom(65535)
            # Decodificamos el encabezado Ethernet
            eth = decodificar_paquete_ethernet(paquete)
            print(f"\nEthernet Frame:")
            print(f"  Dest MAC: {eth['dest_mac']}")
            print(f"  Src MAC: {eth['src_mac']}")
            print(f"  Protocol: {eth['eth_proto']}")
            # Si el protocolo es IPv4 (0x0800)
            if eth['eth_proto'] == 8:
                ip = decodificar_paquete_ip(paquete[14:])
                print(f"  IPv4 Packet:")
                print(f"    Version: {ip['version']}")
                print(f"    TTL: {ip['ttl']}")
                print(f"    Protocol: {ip['proto']}")
                print(f"    Src IP: {ip['src_ip']}")
                print(f"    Dest IP: {ip['dest_ip']}")
                # Si el protocolo es TCP (6)
                if ip['proto'] == 6:
                    tcp = decodificar_paquete_tcp(paquete[14 + ip['longitud_encabezado']:])
                    print(f"    TCP Segment:")
                    print(f"      Src Port: {tcp['src_port']}")
                    print(f"      Dest Port: {tcp['dest_port']}")
                    print(f"      Seq: {tcp['seq']}")
                    print(f"      Ack: {tcp['ack']}")
                    print(f"      Flags: {tcp['flags']}")
                    print(f"      Window: {tcp['window']}")
                    print(f"      Checksum: {tcp['checksum']}")
                    print(f"      Urg Pointer: {tcp['urg_ptr']}")
                # Si el protocolo es UDP (17)
                elif ip['proto'] == 17:
                    udp = decodificar_paquete_udp(paquete[14 + ip['longitud_encabezado']:])
                    print(f"    UDP Segment:")
                    print(f"      Src Port: {udp['src_port']}")
                    print(f"      Dest Port: {udp['dest_port']}")
                    print(f"      Length: {udp['longitud']}")
                    print(f"      Checksum: {udp['checksum']}")
    except PermissionError:
        print("Error: Necesitas permisos de superusuario para capturar paquetes.")
    except Exception as e:
        print(f"Error inesperado: {e}")
    finally:
        if 'sock' in locals():
            sock.close()