# 🎣 PhishCatch - Avaliação Comparativa de LLMs

[![Status](https://img.shields.io/badge/Status-Funcional_%26_Reprodutível-brightgreen.svg)]()

> Artefato académico de segurança de redes para análise preventiva de ameaças homográficas e sequestro de domínios (Typosquatting), gerado de forma independente por três modelos de IA de topo.

## 📖 Sobre o Projeto e Contexto Académico

Este repositório é o resultado da **Atividade Final de Avaliação Comparativa de Artefatos Gerados por IA**. 
O objetivo primário é comparar as capacidades arquiteturais, de escrita de código limpo e de sustentabilidade de três Modelos de Linguagem de Larga Escala (LLMs) distintos, confrontados com o mesmo desafio de Cibersegurança: o desenvolvimento integral de uma ferramenta automatizada de *Threat Intelligence* (o **PhishCatch**).

O PhishCatch atua de forma proativa gerando permutações de um domínio alvo (através de Omissão, Repetição, Transposição e Homógrafos), avaliando o nível de ameaça baseado na infraestrutura ativa (servidores Web e Registo MX/E-mail) e penalizando domínios recém-registados (WHOIS) para mitigar potenciais campanhas de Phishing e BEC (*Business Email Compromise*).

## 🤖 Modelos Avaliados

O código fonte gerado está isolado de forma estanque nos respetivos diretórios:

1. 📂 **`phishcatch-claude/` (Versão A):** Desenvolvido pelo **Claude 4.8 Opus**. Destaca-se por uma arquitetura orientada a objetos excecional, um motor de rede assíncrono e uma interface gráfica avançada no terminal.
2. 📂 **`phishcatch-gpt/` (Versão B):** Desenvolvido pelo **GPT-4.5 Omni**. Destaca-se pela fiabilidade absoluta, boas práticas (*Clean Code*), sustentabilidade a longo prazo e cobertura robusta de testes unitários.
3. 📂 **`phishcatch-glm/` (Versão C):** Desenvolvido pelo **GLM-4 Plus**. Focado na reprodutibilidade e no minimalismo extremo de dependências (imagem base em Alpine Linux, ideal para *pipelines* de DevSecOps rápidos).

📄 **Relatório Completo:** A avaliação metodológica e o apuramento técnico final podem ser consultados no ficheiro [Relatorio_Comparativo_PhishCatch.md](Relatorio_Comparativo_PhishCatch.md).

---

## 🚀 Como Executar (Avaliação Facilitada)

Para minimizar o esforço do avaliador e prevenir conflitos de dependências (Software Rot), preparámos um *script* de automação (`run_all.sh`). Este *script* constrói, de forma isolada, os contentores Docker de cada LLM e executa a ferramenta de forma sequencial contra o domínio alvo. **Não necessita de ter Python instalado**, sendo apenas exigido o motor Docker.

### 1. Clonar o Repositório
```bash
git clone https://github.com/jpdicarvalho/phishcatch.git
cd phishcatch
```

### 2. Dar Permissões de Execução
```bash
chmod +x run_all.sh
```

### 3. Executar as 3 Versões de Forma Sequencial
Substitua `google.com` (ou qualquer outro) pelo domínio que pretende analisar:

```bash
./run_all.sh google.com
```

### 🔍 O que vai acontecer?
O script irá, com um único clique:
1. Compilar e executar o código do **Claude**.
2. Compilar e executar o código do **GPT**.
3. Compilar e executar o código do **GLM**.

No final, os 3 relatórios de inteligência (`.csv` gerados por cada modelo) serão automaticamente exportados e agrupados na sua diretoria principal, permitindo uma comparação técnica imediata.

---

## 🧪 Como Executar os Testes Unitários

Para comprovar a sustentabilidade do código e atestar o funcionamento da geração de permutações e motor de avaliação de risco, criámos também um automatismo para testar o código dos 3 modelos isoladamente:

### 1. Dar Permissões de Execução
```bash
chmod +x test_all.sh
```

### 2. Executar os Testes
```bash
./test_all.sh
```
O script sobrescreve o `ENTRYPOINT` dos contentores Docker e utiliza o framework `unittest` nativo do Python para rodar as baterias de testes em segurança e mostrar-lhe os resultados lado-a-lado.
