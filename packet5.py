import scapy.all as scapy
import csv
import psutil
import tkinter as tk
from tkinter import messagebox
from threading import Thread 

class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Captura de Pacotes Pro - Análise e Estatísticas")
        master.geometry("750x650") # Aumenta o tamanho para acomodar as estatísticas

        self.sniffer = None          # Objeto AsyncSniffer
        self.packets = []            # Lista para armazenar os pacotes capturados
        self.is_capturing = False    # Estado da captura
        
        # Dicionário para estatísticas em tempo real
        self.stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Outro': 0}

        # Variáveis de controle da GUI
        self.interface_var = tk.StringVar(master)
        self.filtro_var = tk.StringVar(master)
        self.limit_var = tk.StringVar(master, value='0') # Novo: Limite de pacotes, 0 para ilimitado
        
        self._setup_ui()
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    # --- Funções de Utilitário ---

    def _list_interfaces(self):
        """Lista as interfaces de rede disponíveis."""
        return list(psutil.net_if_addrs().keys())

    def get_protocol(self, pacote):
        """Determina o protocolo da camada de transporte."""
        if pacote.haslayer(scapy.TCP):
            return "TCP"
        elif pacote.haslayer(scapy.UDP):
            return "UDP"
        elif pacote.haslayer(scapy.ICMP):
            return "ICMP"
        else:
            return "Outro"

    # --- Lógica de Captura ---

    def packet_callback(self, pacote):
        """Função chamada para cada pacote capturado."""
        if self.sniffer and not self.sniffer.running:
            # Verifica se o sniffer foi parado pelo limite ou manualmente
            return

        if pacote.haslayer(scapy.IP):
            origem = pacote[scapy.IP].src
            destino = pacote[scapy.IP].dst
            protocolo = self.get_protocol(pacote)
            tamanho = len(pacote)
            
            # 1. Adiciona à lista de pacotes e atualiza estatísticas
            self.packets.append((origem, destino, protocolo, tamanho))
            self.stats[protocolo] += 1
            
            # 2. Atualiza a GUI (Logs)
            self.output_text.insert(tk.END, f"[{protocolo}] Origem: {origem}, Destino: {destino}, Tamanho: {tamanho}\n")
            self.output_text.yview(tk.END)

            # 3. Verifica o limite de pacotes (Nova Funcionalidade)
            packet_limit = int(self.limit_var.get())
            if packet_limit > 0 and len(self.packets) >= packet_limit:
                # Usa o método after para garantir que a parada seja chamada no thread principal
                self.master.after(10, lambda: self.stop_capture(message=f"Limite de {packet_limit} pacotes atingido. Captura interrompida."))
    
    def update_stats_ui(self):
        """Atualiza a caixa de estatísticas de forma periódica e segura (no thread principal)."""
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, "📊 Resumo de Protocolos:\n")
        self.stats_text.insert(tk.END, f"Total de Pacotes: {len(self.packets)}\n\n")
        
        for proto, count in self.stats.items():
            self.stats_text.insert(tk.END, f"  {proto}: {count}\n")
            
        # Agenda a próxima atualização se ainda estiver capturando
        if self.is_capturing:
            self.master.after(1000, self.update_stats_ui) # Atualiza a cada 1 segundo

    def start_capture(self):
        """Inicia a captura de pacotes."""
        interface = self.interface_var.get()
        filtro = self.filtro_var.get()
        
        self.clear_logs(gui_only=True)
        self.output_text.insert(tk.END, f"Iniciando captura na interface: {interface} com filtro '{filtro}'...\n")

        # Reinicia estatísticas e pacotes
        self.packets = [] 
        self.stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Outro': 0}

        self.sniffer = scapy.AsyncSniffer(
            iface=interface,
            prn=self.packet_callback,
            filter=filtro,
            store=0
        )
        
        try:
            self.sniffer.start()
            self.is_capturing = True
            self.start_button.config(text="⏹️ Parar Captura", bg="red")
            self.update_stats_ui() # Inicia a atualização de estatísticas
        except PermissionError:
            messagebox.showerror("Erro", "Permissões insuficientes. Execute o script com permissões de superusuário (root/sudo).")
            self.toggle_capture() 
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao iniciar a captura: {e}")
            self.toggle_capture()

    def stop_capture(self, message="Captura de pacotes interrompida manualmente."):
        """Para a captura de pacotes."""
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
            self.is_capturing = False
            self.start_button.config(text="▶️ Iniciar Captura", bg="green")
            self.output_text.insert(tk.END, f"\n--- {message} ---\n")

    def toggle_capture(self):
        """Alterna entre Iniciar e Parar a captura."""
        if self.is_capturing:
            self.stop_capture()
        else:
            self.start_capture()
            
    # --- Funções de Log e Limpeza ---

    def save_logs(self):
        """Salva os pacotes capturados em um arquivo CSV."""
        if not self.packets:
            messagebox.showinfo("Aviso", "Nenhum pacote capturado para salvar.")
            return
            
        try:
            # Novo: Inclui a data/hora no nome do arquivo para evitar sobrescrever
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"pacotes_{timestamp}.csv"
            with open(filename, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(["Origem", "Destino", "Protocolo", "Tamanho (bytes)"])
                writer.writerows(self.packets)
            messagebox.showinfo("Sucesso", f"Pacotes salvos em **{filename}**")
        except Exception as e:
            messagebox.showerror("Erro de Arquivo", f"Não foi possível salvar os logs: {e}")

    def clear_logs(self, gui_only=False):
        """Limpa a GUI e, opcionalmente, o buffer de pacotes (Nova Funcionalidade)."""
        self.output_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        
        if not gui_only and not self.is_capturing:
            self.packets = []
            self.stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Outro': 0}
            self.output_text.insert(tk.END, "Logs e buffer de pacotes limpos.\n")
        elif self.is_capturing:
            self.output_text.insert(tk.END, "Logs na tela limpos. A captura continua...\n")


    # --- Configuração da Interface (GUI) ---

    def _setup_ui(self):
        
        # Frame de Controles Principais (Interface, Filtro, Limite)
        controls_frame = tk.Frame(self.master)
        controls_frame.pack(pady=10)
        
        # 1. Escolha da Interface
        interfaces_list = self._list_interfaces()
        if not interfaces_list:
            messagebox.showerror("Erro", "Nenhuma interface de rede encontrada.")
            return
            
        tk.Label(controls_frame, text="🌐 Interface:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.interface_var.set(interfaces_list[0]) 
        interface_menu = tk.OptionMenu(controls_frame, self.interface_var, *interfaces_list)
        interface_menu.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        # 2. Campo de Filtro
        tk.Label(controls_frame, text="🔍 Filtro BPF:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        filtro_entry = tk.Entry(controls_frame, textvariable=self.filtro_var, width=30)
        filtro_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

        # 3. Limite de Pacotes (Novo)
        tk.Label(controls_frame, text="🔢 Limite (0=∞):").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        limit_entry = tk.Entry(controls_frame, textvariable=self.limit_var, width=10)
        limit_entry.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        # Frame de Botões
        buttons_frame = tk.Frame(self.master)
        buttons_frame.pack(pady=10)

        # Botão Iniciar/Parar
        self.start_button = tk.Button(buttons_frame, text="▶️ Iniciar Captura", command=self.toggle_capture, bg="green", fg="white", padx=10, pady=5)
        self.start_button.pack(side=tk.LEFT, padx=10)
        
        # Botão Salvar
        save_button = tk.Button(buttons_frame, text="💾 Salvar Logs (CSV)", command=self.save_logs, bg="blue", fg="white", padx=10, pady=5)
        save_button.pack(side=tk.LEFT, padx=10)

        # Botão Limpar (Novo)
        clear_button = tk.Button(buttons_frame, text="🧹 Limpar Logs", command=lambda: self.clear_logs(gui_only=False), bg="orange", fg="black", padx=10, pady=5)
        clear_button.pack(side=tk.LEFT, padx=10)

        # Frame principal para Logs e Estatísticas (para organização visual)
        main_display_frame = tk.Frame(self.master)
        main_display_frame.pack(pady=10, padx=10)

        # 4. Caixa de Texto para Estatísticas (Novo)
        stats_label = tk.Label(main_display_frame, text="Estatísticas em Tempo Real:")
        stats_label.pack(anchor='w')
        self.stats_text = tk.Text(main_display_frame, height=8, width=30, bg='#f0f0f0')
        self.stats_text.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.Y)
        self.stats_text.insert(tk.END, "Aguardando início da captura...")


        # 5. Caixa de Texto para exibir os pacotes capturados (Logs)
        output_label = tk.Label(main_display_frame, text="Logs de Pacotes:")
        output_label.pack(anchor='w')
        self.output_text = tk.Text(main_display_frame, height=20, width=60)
        self.output_text.pack(side=tk.RIGHT, padx=5, pady=5, fill=tk.BOTH, expand=True)
        
    def on_closing(self):
        """Chamado quando o usuário tenta fechar a janela."""
        if self.is_capturing:
            self.stop_capture("Fechamento da janela. Captura interrompida.")
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()