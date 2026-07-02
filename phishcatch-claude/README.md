# 🎣 PhishCatch v2.0

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED.svg?logo=docker)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Funcional_%26_Reprodutível-brightgreen.svg)]()

> **Artefacto académico de Cibersegurança** — Ferramenta automatizada de *Threat Intelligence* focada na deteção proativa de ataques de **Typosquatting** e **Ataques Homográficos** contra domínios alvo.

---

## 📖 Sobre o Projeto

Na cibersegurança, o **Typosquatting** (sequestro de domínio por erro de digitação) e os **Ataques Homográficos** (substituição de caracteres por variantes visualmente similares) representam vetores críticos de ameaça. Cibercriminosos registam domínios visualmente muito semelhantes aos de organizações legítimas (ex: `googl3.com` ou `googel.com` em vez de `google.com`), com o objetivo de:

- 🎣 **Phishing**: Roubo de credenciais através de páginas falsas.
- 📧 **BEC (Business Email Compromise)**: Envio de e-mails fraudulentos a partir de domínios quase idênticos.
- 🦠 **Distribuição de Malware**: Hosting de payloads maliciosos em domínios semelhantes.

O **PhishCatch** automatiza a deteção destas ameaças através de:
1. Geração inteligente de permutações do domínio alvo.
2. Resolução DNS assíncrona massiva.
3. Verificação de infraestrutura (servidores web e de e-mail).
4. Análise de idade via WHOIS.
5. Cálculo de risco multi-fator.

---

## ✨ Funcionalidades

| Funcionalidade | Descrição |
|---|---|
| **Motor de Permutações** | Gera variantes usando 4 técnicas: Omissão, Repetição, Transposição e Homógrafos |
| **Concorrência Assíncrona** | Utiliza `asyncio` + `aiohttp` para análise massivamente paralela |
| **Resolução DNS** | Verifica registos A para detetar domínios registados |
| **Deteção de Servidor Web** | Verifica se o domínio responde com HTTP 200 |
| **Deteção de E-mail Malicioso** | Verifica a existência de registos MX |
| **OSINT via WHOIS** | Calcula a idade do domínio em dias |
| **Motor de Risco** | Classifica ameaças em LOW, MEDIUM, HIGH, CRITICAL com penalização por idade |
| **Relatório CSV** | Exporta resultados estruturados para análise posterior |
| **Interface Rica** | Output colorido com tabelas formatadas via `rich` |
| **Docker** | 100% reprodutível em qualquer ambiente |

---

## 🧮 Matriz de Risco

O PhishCatch calcula o nível de ameaça combinando múltiplos fatores:

| Servidor Web | Registo MX | Risco Base |
|:---:|:---:|:---:|
| ✘ | ✘ | 🟢 LOW |
| ✔ | ✘ | 🟡 MEDIUM |
| ✘ | ✔ | 🟠 HIGH |
| ✔ | ✔ | 🔴 CRITICAL |

> **Penalização por Idade:** Domínios com menos de **30 dias** de idade sobem **um nível** de risco (ex: LOW → MEDIUM, HIGH → CRITICAL).

---

## 🔧 Técnicas de Geração de Permutações

### 1. Omissão
Remove um caractere de cada vez:
```
google.com → oogle.com, gogle.com, goole.com, googe.com, googl.com
```

### 2. Repetição
Duplica um caractere de cada vez:
```
google.com → ggoogle.com, gooogle.com, googgle.com, googlle.com, googlee.com
```

### 3. Transposição
Troca pares de caracteres adjacentes:
```
google.com → ogogle.com, goolge.com, googel.com
```

### 4. Homógrafos
Substitui caracteres por variantes visualmente semelhantes:
```
google.com → g00gle.com, goo9le.com, go0gle.com, goog1e.com
```

Mapa de substituições suportado:

| Original | Substituições |
|:---:|:---:|
| a | 4, @ |
| b | 8 |
| e | 3 |
| g | 9 |
| i | 1, ! |
| l | 1, \| |
| o | 0 |
| s | 5, $ |
| t | 7 |

---

## 📋 Requisitos do Sistema

### Execução via Docker (Recomendado)
- [Docker](https://docs.docker.com/get-docker/) 20.10+
- Acesso à Internet (para resolução DNS e WHOIS)

### Execução Local
- Python 3.12+
- pip
- Utilitário `whois` instalado no sistema operativo
- Acesso à Internet

---

## 🚀 Como Executar

### Opção 1: Via Docker (Recomendado)

#### 1. Construir a imagem
```bash
cd phishcatch-antigravity
docker build -t phishcatch:v2 .
```

#### 2. Executar a ferramenta
```bash
# Análise básica
docker run --rm phishcatch:v2 google.com

# Com exportação CSV para a diretoria atual
docker run --rm -v $(pwd):/app phishcatch:v2 google.com

# Com parâmetros personalizados
docker run --rm -v $(pwd):/app phishcatch:v2 empresa.com -c 30 -t 5.0
```

#### 3. Executar os testes dentro do Docker
```bash
docker run --rm --entrypoint python phishcatch:v2 -m pytest test_phishcatch.py -v
```

### Opção 2: Execução Local

#### 1. Instalar dependências do sistema
```bash
# Debian/Ubuntu
sudo apt-get install whois

# macOS
brew install whois
```

#### 2. Instalar dependências Python
```bash
pip install -r requirements.txt
```

#### 3. Executar a ferramenta
```bash
python phishcatch.py google.com
```

#### 4. Executar os testes
```bash
python -m pytest test_phishcatch.py -v
```

---

## ⚙️ Opções da Linha de Comandos

```
usage: phishcatch.py [-h] [-c CONCURRENCY] [-t TIMEOUT] [-o OUTPUT] domain

positional arguments:
  domain                Domínio alvo a proteger (ex: google.com)

options:
  -h, --help            Mostrar esta mensagem de ajuda
  -c, --concurrency N   Número máximo de verificações concorrentes (default: 20)
  -t, --timeout SECS    Timeout em segundos para cada verificação (default: 3.0)
  -o, --output DIR      Diretoria de saída para o relatório CSV (default: .)
```

---

## 📊 Exemplo de Saída

### Terminal
```
    ____  __    _      __   ______      __       __
   / __ \/ /_  (_)____/ /_ / ____/___ _/ /______/ /_
  / /_/ / __ \/ / ___/ __ \/ /   / __ `/ __/ ___/ __ \
 / ____/ / / / (__  ) / / / /___/ /_/ / /_/ /__/ / / /
/_/   /_/ /_/_/____/_/ /_/\____/\__,_/\__/\___/_/ /_/

🎯 Alvo: google.com

⚡ 35 permutações geradas (Omissão, Repetição, Transposição, Homógrafos)

 ◐ A analisar domínios... ██████████████████████████████████████████ 100% • 0:00:12

┌──────────────────────────────────────────────────────────────┐
│ 📊 Resumo da Análise de Ameaças                             │
│                                                              │
│   Alvo: google.com                                           │
│   Permutações testadas: 35                                   │
│   Domínios registados: 8                                     │
│                                                              │
│   🔴 CRITICAL: 1  🟠 HIGH: 3  🟡 MEDIUM: 2  🟢 LOW: 2      │
└──────────────────────────────────────────────────────────────┘

         🎯 Domínios Suspeitos Detetados
╭────────────────┬──────────────┬─────┬─────┬──────────┬──────────╮
│ Domínio        │ IP           │ Web │ MX  │ Idade    │ Risco    │
├────────────────┼──────────────┼─────┼─────┼──────────┼──────────┤
│ googl.com      │ 1.2.3.4      │  ✔  │  ✔  │ 186      │ CRITICAL │
│ googe.com      │ 5.6.7.8      │  ✘  │  ✔  │ 8530     │ HIGH     │
│ googel.com     │ 9.10.11.12   │  ✘  │  ✔  │ 8005     │ HIGH     │
│ ...            │ ...          │ ... │ ... │ ...      │ ...      │
╰────────────────┴──────────────┴─────┴─────┴──────────┴──────────╯

📁 Relatório exportado para: phishcatch_report_google.csv
```

### Ficheiro CSV
```csv
domain,is_registered,ip_address,has_mx_record,has_website,age_days,threat_level
googl.com,True,1.2.3.4,True,True,186,CRITICAL
googe.com,True,5.6.7.8,False,True,8530,HIGH
googel.com,True,9.10.11.12,True,False,8005,HIGH
```

---

## 🏗️ Arquitetura

```
phishcatch-antigravity/
├── phishcatch.py          # Código principal da ferramenta
├── test_phishcatch.py     # Testes unitários
├── requirements.txt       # Dependências Python
├── Dockerfile             # Contentor reprodutível
└── README.md              # Esta documentação
```

### Módulos Internos

| Classe | Responsabilidade |
|---|---|
| `PermutationEngine` | Geração de permutações (omissão, repetição, transposição, homógrafos) |
| `DomainAnalyzer` | Análise assíncrona (DNS, HTTP, MX, WHOIS) |
| `RiskAssessor` | Cálculo do nível de ameaça com penalização por idade |
| `ReportExporter` | Exportação CSV e visualização formatada no terminal |
| `DomainResult` | Modelo de dados para os resultados de cada domínio |

---

## 🧪 Testes

O ficheiro `test_phishcatch.py` contém testes unitários abrangentes para:

- **PermutationEngine**: Valida cada técnica de geração individualmente
- **RiskAssessor**: Testa todas as combinações da matriz de risco e penalização por idade
- **DomainResult**: Verifica a serialização do modelo de dados

```bash
# Executar todos os testes com output detalhado
python -m pytest test_phishcatch.py -v

# Executar apenas testes de risco
python -m pytest test_phishcatch.py -k "Risk" -v

# Executar com cobertura de código
pip install pytest-cov
python -m pytest test_phishcatch.py --cov=phishcatch --cov-report=term-missing
```

---

## ⚠️ Aviso Legal

Esta ferramenta foi desenvolvida **exclusivamente para fins académicos e educacionais**. A utilização desta ferramenta contra domínios sem autorização explícita pode violar leis locais. O autor não se responsabiliza por qualquer uso indevido.

---

## 📄 Licença

Este projeto está licenciado sob a [Licença MIT](LICENSE).
