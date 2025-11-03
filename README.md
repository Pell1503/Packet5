🧾 PACKET SNIFFER

🧠 Descrição Geral
Um aplicativo simples que captura pacotes de rede em tempo real e exibe as informações — IP de origem, IP de destino, protocolo e tamanho — em uma interface gráfica amigável.

🎯 Escopo
🎯 Objetivo Geral
Desenvolver uma ferramenta em Python que permita visualizar o tráfego de rede local, mostrando os pacotes capturados de forma interativa.
🎯 Objetivos Específicos
Capturar pacotes de rede em tempo real.


Exibir informações básicas: IP de origem, destino, protocolo e tamanho.


Fornecer uma interface gráfica com botões de “Iniciar” e “Parar” captura.


Permitir salvar os pacotes capturados em um arquivo .csv ou .txt.



🧰 Tecnologias e Ferramentas
Categoria
Tecnologia / Biblioteca
Função
Linguagem
Python 3.11+
Linguagem principal
Captura de pacotes
Scapy
Capturar e analisar pacotes
Interface gráfica
Tkinter
Criação da GUI
Visualização
ttk.Treeview (Tkinter)
Exibição dos pacotes em tabela
Armazenamento
CSV
Exportação e salvamento de logs
Controle de versão
GitHub((https://github.com/Pell1503/Packet5)
Repositório e versionamento de código


👥 Equipe e Responsabilidades
Membro
Função
Responsabilidades
Pedro
Backend / Captura de Pacotes
- Implementar a captura de pacotes usando Scapy.
- Filtrar pacotes por protocolo (TCP, UDP, ICMP).
- Criar funções de tratamento de erros e logs.
- Otimizar o desempenho da captura.
Bruno
Frontend / Interface Gráfica
- Desenvolver a GUI com Tkinter.
- Criar botões de Iniciar, Parar e Salvar Logs.
- Exibir pacotes capturados em uma tabela interativa.
- Melhorar a experiência do usuário (layout, cores e ícones).
João
Exportação / Armazenamento de Logs
- Criar função para salvar pacotes capturados em arquivos .CSV ou .TXT.
- Organizar diretórios de saída dos logs.
- Garantir que os dados sejam legíveis e bem formatados.
- Auxiliar nos testes de gravação e leitura dos arquivos.
Glauco
Testes / Qualidade
- Criar scripts de teste para verificar o funcionamento dos módulos.
- Testar compatibilidade em Windows e Linux.
- Validar resultados da captura e da interface.
- Ajudar na correção de bugs e validação final.
Hilton
Documentação / DevOps
- Produzir documentação técnica e guia do usuário (README.md).
- Manter o repositório GitHub atualizado (commits, branches e issues).
- Criar instruções de instalação e execução do programa.
- Organizar a entrega final e os relatórios.


