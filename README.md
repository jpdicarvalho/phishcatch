# 🎣 PhishCatch

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED.svg?logo=docker)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Funcional_%26_Reprodutível-brightgreen.svg)]()

> Artefacto de segurança de redes para análise preventiva de ameaças homográficas e sequestro de domínios (Typosquatting).

## Sobre o Projeto

Na cibersegurança, o **Typosquatting** (sequestro de domínio por erro de digitação) e os **Ataques Homográficos** representam vetores críticos de ameaça. Cibercriminosos registam domínios visualmente muito semelhantes aos de organizações legítimas (ex: `googlee.com` ou `googel.com` em vez de `google.com`). O objetivo central é enganar utilizadores em campanhas de *Phishing* para roubo de credenciais ou orquestrar ataques sofisticados de **BEC (Business Email Compromise)**, enviando e-mails fraudulentos que escapam à perceção visual da vítima.

O **PhishCatch** é uma ferramenta automatizada de *Threat Intelligence* e OSINT (Open-Source Intelligence). Através da geração de múltiplas permutações de um domínio alvo, o artefacto realiza uma varredura veloz na internet em busca de registos DNS (IP), servidores de e-mail maliciosos (Registos MX) e páginas web ativas. O resultado final é a produção de inteligência de ameaças acionável, permitindo que equipas de *Blue Team* atuem proativamente no bloqueio (takedown) destas infraestruturas.

## Funcionalidades

* **Motor Avançado de Typosquatting:** Gera dezenas de permutações da ameaça utilizando múltiplos algoritmos: omissão, repetição, transposição (letras trocadas adjacentes) e substituição de homógrafos básicos (ex: "o" por "0").
* **OSINT Profundo (Integração WHOIS):** Consulta ativamente as bases de dados de registo global para extrair a data de criação do domínio malicioso, calculando a sua idade exata em dias.
* **Triagem Dinâmica de Criticidade:** O motor de risco avalia a ameaça cruzando 3 fatores: existência de servidor web (HTTP 200), servidor de e-mail malicioso (Registo MX) e a idade do domínio. Domínios recém-registados (menos de 30 dias) sofrem forte penalização de risco, refletindo ameaças iminentes.
* **Resolução Multithread e UX:** Realiza consultas DNS concorrentes apoiadas por uma interface de progresso visual, garantindo uma varredura extremamente rápida de vastos volumes de permutações.
* **Exportação Estruturada:** Gera automaticamente um relatório `.csv` rico e detalhado com as evidências da varredura, pronto a ser ingerido por plataformas SIEM ou consumido pela equipa de resposta a incidentes.
* **Isolamento Total (DevSecOps):** Integralmente empacotado via Docker (incluindo dependências de SO como utilitários de rede), garantindo 100% de reprodutibilidade em qualquer ambiente de avaliação e erradicando o problema do *Software Rot*.

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
[*] 15 permutações de ameaça geradas.
[*] A resolver DNS e sondar servidores web...

Verificando: 100%|██████████| 15/15 [00:02<00:00,  6.77it/s]


[+] Varredura Concluída! 8 domínios maliciosos detetados.

[!] googlee.com.br  | IP: 104.21.30.30    | E-mail MX: Sim | Site Web: Não | Risco: HIGH
[!] ggoogle.com.br  | IP: 99.83.176.46    | E-mail MX: Não | Site Web: Sim | Risco: MEDIUM
[!] goole.com.br    | IP: 104.21.2.227    | E-mail MX: Não | Site Web: Sim | Risco: MEDIUM
[!] googe.com.br    | IP: 104.247.81.99   | E-mail MX: Sim | Site Web: Não | Risco: HIGH
[!] googel.com.br   | IP: 104.247.81.99   | E-mail MX: Sim | Site Web: Não | Risco: HIGH
[!] googl.com.br    | IP: 89.116.213.44   | E-mail MX: Sim | Site Web: Sim | Risco: CRITICAL
[!] gogle.com.br    | IP: 104.21.59.145   | E-mail MX: Não | Site Web: Não | Risco: LOW
[!] googlle.com.br  | IP: 172.67.129.97   | E-mail MX: Não | Site Web: Não | Risco: LOW

[*] Relatório de Inteligência exportado para: phishcatch_report_google.csv
```
