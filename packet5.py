import scapy.all as scapy
import csv
import psutil  # Para listar as interfaces de rede
import time

# Função para determinar o protocolo
def get_protocol(pacote):
    """Retorna o protocolo (TCP, UDP, ICMP) ou 'Outro'"""
    if pacote.haslayer(scapy.TCP):
        return "TCP"
    elif pacote.haslayer(scapy.UDP):
        return "UDP"
    elif pacote.haslayer(scapy.ICMP):
        return "ICMP"
    else:
        return "Outro"

# Função para salvar os pacotes em um arquivo CSV
def save_logs(pacotes):
    """Salva os pacotes capturados em um arquivo CSV"""
    with open("pacotes.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Origem", "Destino", "Protocolo", "Tamanho"])
        for pacote in pacotes:
            writer.writerow(pacote)
    print("Pacotes salvos em pacotes.csv")

# Função para listar interfaces de rede
def list_interfaces():
    """Lista as interfaces de rede disponíveis"""
    interfaces = psutil.net_if_addrs()
    print("Interfaces de Rede Disponíveis:")
    for iface in interfaces:
        print(f"- {iface}")
    return list(interfaces.keys())

# Função principal para capturar pacotes
def capture_packets(interface):
    """Captura pacotes na interface escolhida e exibe informações no terminal"""
    pacotes = []
    print(f"Capturando pacotes na interface: {interface}... Pressione Ctrl+C para parar.")
    
    def packet_callback(pacote):
        """Função chamada para cada pacote capturado"""
        if pacote.haslayer(scapy.IP):
            origem = pacote[scapy.IP].src
            destino = pacote[scapy.IP].dst
            protocolo = get_protocol(pacote)
            tamanho = len(pacote)
            pacotes.append((origem, destino, protocolo, tamanho))
            # Exibe as informações do pacote no terminal
            print(f"Origem: {origem}, Destino: {destino}, Protocolo: {protocolo}, Tamanho: {tamanho}")
    
    try:
        # Captura pacotes usando a interface especificada
        scapy.sniff(iface=interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nCaptura interrompida.")
        save_logs(pacotes)  # Salva os pacotes quando a captura for interrompida

# Execução do script
if __name__ == "__main__":
    interfaces = list_interfaces()
    
    # Escolher a interface
    while True:
        interface = input(f"\nEscolha a interface (Digite o nome de uma das opções acima): ")
        if interface in interfaces:
            break
        else:
            print("Interface inválida. Tente novamente.")

    capture_packets(interface)
