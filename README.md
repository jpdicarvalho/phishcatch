# 🎣 PhishCatch

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED.svg?logo=docker)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Funcional_%26_Reprodutível-brightgreen.svg)]()

> Artefacto de segurança de redes para análise preventiva de ameaças homográficas e sequestro de domínios (Typosquatting).

## Sobre o Projeto

Na cibersegurança, o **Typosquatting** (ou sequestro de erros de digitação) é um vetor de ataque onde cibercriminosos registam domínios visualmente idênticos aos de empresas reais (ex: `googlee.com` em vez de `google.com`). O objetivo é enganar utilizadores em ataques de *Phishing* de credenciais ou realizar ataques de **BEC (Business Email Compromise)**, enviando e-mails fraudulentos que parecem ser da organização legítima.

O **PhishCatch** é uma ferramenta de OSINT (Open-Source Intelligence) automatizada. Gera permutações de um domínio alvo e realiza uma varredura na internet em busca de registos DNS e servidores de e-mail (Registos MX) ativos em domínios falsos, produzindo inteligência de ameaças acionável para equipas de *Blue Team*.

## Funcionalidades

* **Motor de Typosquatting:** Gera dezenas de permutações através de algoritmos de omissão e repetição de carateres.
* **Resolução Multithread:** Realiza consultas DNS concorrentes, garantindo uma varredura extremamente rápida.
* **Avaliação de Ameaça:** Distingue entre domínios apenas registados e domínios configurados para enviar e-mails maliciosos (Registo MX ativo).
* **Exportação Estruturada:** Gera um ficheiro `.csv` automático com os resultados da varredura, pronto a ser consumido por equipas de resposta a incidentes.
* **Isolamento Total:** Empacotado via Docker, garantindo 100% de reprodutibilidade e eliminando o *Software Rot* (deterioração de dependências).

## Como Executar (Via Docker)

Para garantir a reprodutibilidade, este artefacto foi construído para ser executado integralmente dentro de um contentor Docker. **Não precisa** ter o Python instalado na sua máquina local.

### 1. Construir a imagem (Apenas na primeira vez)
Faça clone do repositório, entre na pasta e construa a imagem Docker:

```bash
git clone [https://github.com/SEU_USUARIO/phishcatch.git](https://github.com/SEU_USUARIO/phishcatch.git)
cd phishcatch
docker build -t phishcatch .
```

### 2. Executar a ferramenta

Inicie o contentor passando o domínio alvo. A flag -v $(pwd):/app garante que o ficheiro .csv gerado seja guardado diretamente na sua diretoria atual.

```bash
docker run --rm -v $(pwd):/app phishcatch seu-alvo.com.br
```
### Exemplo de Saída

Ao executar a ferramenta contra um domínio real, a saída no terminal destacará as ameaças críticas (a vermelho):

```bash
[*] Iniciando PhishCatch no alvo: google.com.br
[*] 10 variações de typosquatting geradas.
[*] Varrendo a internet (Resolução DNS multithread)...

[+] Varredura Concluída! 7 domínios suspeitos encontrados.

[!] googlee.com.br | IP: 172.67.150.115 | Recebe E-mail: Sim (Phishing Alert!)
[!] goole.com.br | IP: 104.21.2.227 | Recebe E-mail: Não
[!] googe.com.br | IP: 104.247.81.99 | Recebe E-mail: Sim (Phishing Alert!)
[!] googl.com.br | IP: 147.79.105.22 | Recebe E-mail: Sim (Phishing Alert!)

[*] Relatório detalhado salvo em: phishcatch_report_google.csv
```
