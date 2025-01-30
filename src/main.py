import argparse
from captura.captura import iniciar_captura, obtener_interfaz_predeterminada

def main():
    # Configurar argparse con una descripción personalizada
    parser = argparse.ArgumentParser(
        description="Sniffer de paquetes en Python que captura y analiza tráfico en una interfaz de red."
    )

    # Agregar argumentos
    parser.add_argument(
        '-i', '--interface', 
        type=str, 
        help="Especifica la interfaz de red para capturar paquetes. Si no se indica, se usa la interfaz por defecto."
    )
    parser.add_argument(
        '-f', '--filtro', 
        type=str, 
        choices=['HTTP', 'FTP'], 
        help="Filtra los paquetes para mostrar solo tráfico HTTP o FTP. Opcional."
    )

    # Parseamos los argumentos
    args = parser.parse_args()
    
    # Si no se proporciona una interfaz, obtenemos la interfaz predeterminada
    if args.interface is None:
        args.interface = obtener_interfaz_predeterminada()
        if args.interface is None:
            print("No se pudo determinar una interfaz de red activa.")
            return
    
    # Iniciamos la captura de paquetes en la interfaz especificada con el filtro
    print(f"Iniciando sniffer en la interfaz: {args.interface}")
    iniciar_captura(args.interface, args.filtro)

if __name__ == "__main__":
    main()