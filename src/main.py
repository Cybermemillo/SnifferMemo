import argparse
from captura.captura import iniciar_captura, obtener_interfaz_predeterminada

def main():
    # Configuramos el parseador de argumentos
    parser = argparse.ArgumentParser(description="Sniffer de Paquetes Personalizado")
    parser.add_argument('-i', '--interface', type=str, help="Interfaz de red para capturar paquetes (opcional)")
    
    # Parseamos los argumentos
    args = parser.parse_args()
    
    # Si no se proporciona una interfaz, obtenemos la interfaz predeterminada
    if args.interface is None:
        args.interface = obtener_interfaz_predeterminada()
        if args.interface is None:
            print("No se pudo determinar una interfaz de red activa.")
            return
    
    # Iniciamos la captura de paquetes en la interfaz especificada
    print(f"Iniciando sniffer en la interfaz: {args.interface}")
    iniciar_captura(args.interface)

if __name__ == "__main__":
    main()