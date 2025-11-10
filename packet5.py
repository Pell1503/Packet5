import scapy.all as scapy
import csv
import psutil
import tkinter as tk
from tkinter import messagebox
from threading import Thread
import time

# Função para determinar o protocolo
def get_protocol(pacote):
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
    with open("pacotes.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Origem", "Destino", "Protocolo", "Tamanho"])
        for pacote in pacotes:
            writer.writerow(pacote)
    print("Pacotes salvos em pacotes.csv")

# Função para listar interfaces de rede
def list_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

# Função de captura de pacotes
def capture_packets(interface, filtro, pacotes, output_text):
    def packet_callback(pacote):
        if pacote.haslayer(scapy.IP):
            origem = pacote[scapy.IP].src
            destino = pacote[scapy.IP].dst
            protocolo = get_protocol(pacote)
            tamanho = len(pacote)
            pacotes.append((origem, destino, protocolo, tamanho))
            output_text.insert(tk.END, f"Origem: {origem}, Destino: {destino}, Protocolo: {protocolo}, Tamanho: {tamanho}\n")
            output_text.yview(tk.END)  # Rola para baixo automaticamente

    try:
        # Se um filtro for especificado, ele será usado para filtrar pacotes
        if filtro:
            scapy.sniff(iface=interface, prn=packet_callback, store=0, filter=filtro)
        else:
            scapy.sniff(iface=interface, prn=packet_callback, store=0)
    except PermissionError:
        messagebox.showerror("Erro", "Permissões insuficientes. Execute o script com permissões de superusuário (root).")
    except KeyboardInterrupt:
        save_logs(pacotes)

# Função para iniciar a captura em um thread
def start_capture(interface, filtro, pacotes, output_text, button):
    button.config(state=tk.DISABLED)  # Desabilitar o botão para evitar múltiplos cliques
    output_text.insert(tk.END, f"Iniciando captura na interface: {interface}...\n")
    output_text.yview(tk.END)
    
    # Chama a função de captura de pacotes em um thread separado
    capture_thread = Thread(target=capture_packets, args=(interface, filtro, pacotes, output_text))
    capture_thread.daemon = True
    capture_thread.start()
    
    # Atualiza o botão para parar a captura
    button.config(state=tk.NORMAL)
    button.config(text="Parar Captura", command=lambda: stop_capture(capture_thread, button))

# Função para parar a captura
def stop_capture(capture_thread, button):
    button.config(state=tk.DISABLED)
    # No caso do Scapy, a captura vai continuar em um loop até ser interrompida manualmente (Ctrl+C),
    # então parar um thread do Scapy é um pouco mais complicado.
    # Por enquanto, o melhor é informar ao usuário e permitir que o processo seja encerrado.
    print("Captura de pacotes interrompida.")
    button.config(text="Captura Interrompida")

# Função para selecionar a interface e iniciar o processo
def select_interface():
    interfaces = list_interfaces()
    if not interfaces:
        messagebox.showerror("Erro", "Nenhuma interface de rede encontrada.")
        return

    # Interface de rede
    interface = interface_var.get()

    # Filtro
    filtro = filtro_var.get()

    # Inicia a captura
    pacotes = []
    start_capture(interface, filtro, pacotes, output_text, start_button)

# Interface gráfica com Tkinter
root = tk.Tk()
root.title("Captura de Pacotes")
root.geometry("600x400")

# Variáveis de interface
interface_var = tk.StringVar()
filtro_var = tk.StringVar()

# Label e lista suspensa para escolher a interface
interface_label = tk.Label(root, text="Escolha a interface de rede:")
interface_label.pack(pady=10)

interfaces_list = list_interfaces()
interface_menu = tk.OptionMenu(root, interface_var, *interfaces_list)
interface_menu.pack()

# Campo para inserir o filtro de pacotes
filtro_label = tk.Label(root, text="Filtro (opcional, ex: 'tcp port 80'):")
filtro_label.pack(pady=10)

filtro_entry = tk.Entry(root, textvariable=filtro_var)
filtro_entry.pack(pady=5)

# Botão para iniciar a captura
start_button = tk.Button(root, text="Iniciar Captura", command=select_interface)
start_button.pack(pady=20)

# Caixa de texto para exibir os pacotes capturados
output_text = tk.Text(root, height=10, width=70)
output_text.pack(pady=10)

# Inicia o loop da interface gráfica
root.mainloop()
