# Relatório Comparativo de Artefatos – PhishCatch

## Identificação
* **Nome do aluno:** João Pedro Braga de Carvalho
* **Título do artefato:** PhishCatch - Automated Typosquatting Threat Intelligence
* **Problema de Cibersegurança abordado:** Typosquatting, Ataques Homográficos e Business Email Compromise (BEC).

## Modelos utilizados
* **LLM utilizada na geração da Versão A:** Claude 4.8 Opus (Anthropic)
* **LLM utilizada na geração da Versão B:** GPT-4.5 Omni (OpenAI)
* **LLM utilizada na geração da Versão C:** GLM-4 Plus (Zhipu AI)
* **LLM utilizada na avaliação:** Gemini 3.1 Pro (Google)

## Processo de geração
O mesmo *prompt* rigoroso (gerado previamente, detalhando os requisitos funcionais, métodos de permutação e regras de avaliação de risco) foi submetido às três LLMs independentes. O objetivo foi avaliar de forma justa como cada modelo pensa arquiteturalmente (concorrência, organização do projeto, dependências).

## Principais prompts
*O prompt primário utilizado exigia a criação de uma ferramenta capaz de gerar permutações de domínios, realizar varreduras DNS/HTTP/WHOIS e calcular um risco com base em regras estritas, tudo encapsulado em Docker.* (Ver ficheiro `INSTRUCOES_PARA_LLMS.md`).

## Avaliação dos artefatos (Critérios SBSeg 2026)

### Versão A: Claude
* **Pontos fortes (Funcionalidade & Disponibilidade):** Arquitetura excecional. Utiliza programação orientada a objetos de forma avançada (`dataclasses`), programação assíncrona madura e robusta (`asyncio`, `aiohttp`, `dns.asyncresolver`) e uma Interface de Linha de Comandos (CLI) absolutamente deslumbrante baseada na biblioteca `rich` (com tabelas coloridas e barras de progresso).
* **Limitações:** Maior complexidade do código fonte (mais de 600 linhas). O excesso de dependências externas (`rich`, `aiohttp`, etc.) torna a imagem Docker ligeiramente mais pesada.
* **Melhorias recomendadas:** Simplificar o número de dependências caso o objetivo seja executar o script em ambientes restritos de SOC/SIEM (como *serverless functions*).

### Versão B: GPT
* **Pontos fortes (Sustentabilidade):** Código altamente legível, equilibrado e guiado pelas boas práticas de *Clean Code*. Ao utilizar a biblioteca `concurrent.futures` (Multithreading), tornou-se extremamente compatível com a biblioteca `python-whois` nativa (que é síncrona). Apresenta excelente sustentabilidade com anotações de tipos estritas (`Type Hinting`).
* **Limitações:** O Multithreading puro em Python sofre com as limitações do GIL (Global Interpreter Lock), tornando-o marginalmente menos escalável do que soluções assíncronas em operações massivas de IO (rede).
* **Melhorias recomendadas:** Adicionar suporte a concorrência assíncrona se a ferramenta for usada contra milhares de alvos simultâneos.

### Versão C: GLM
* **Pontos fortes (Reprodutibilidade):** Código pragmático, curto e focado na performance crua. Adotou uma arquitetura assíncrona minimalista. O seu grande destaque é a imagem Docker baseada em `Alpine Linux`, resultando num contentor extremamente leve, seguro e rápido, excelente para pipelines de DevSecOps.
* **Limitações:** Interface de terminal rudimentar (saída básica com `print`). Faltam documentações e comentários robustos no código. Falha de lógica na exportação: se não detetar ameaças, aborta a execução sem criar o ficheiro CSV (violando o requisito de relatórios garantidos). A gestão de erros no bloco assíncrono do WHOIS também é frágil.
* **Melhorias recomendadas:** Melhorar a UX no terminal e adicionar uma cobertura de testes mais alargada.

## Comparação entre as versões

* **Qualidade do código e Sustentabilidade:** O **GPT** leva o prémio. O código é um modelo de manutenibilidade, não sobre-engenhado, mas perfeitamente organizado.
* **Facilidade de Uso / Funcionalidade:** O **Claude** esmaga a concorrência através da sua interface visual com `rich`, tornando os relatórios diretamente consumíveis por analistas sem terem sequer de abrir o ficheiro `.csv`.
* **Reprodutibilidade e Performance:** O **GLM** leva a coroa. O *footprint* da imagem Alpine e o código minimalista garantem execução ultra-rápida.

### 🏆 Vencedor (Melhor Qualidade Geral)
A versão do **Claude** apresenta a melhor qualidade geral como "Artefato Científico". Apesar de ser extenso, entrega uma verdadeira ferramenta *Enterprise-Grade* pronta a ser utilizada por uma equipa de Segurança. O esforço implementado no motor assíncrono e na separação de responsabilidades superou largamente os requisitos básicos pedidos.

## Reflexão Crítica
Durante a atividade, observou-se que todas as LLMs conseguem transpor regras complexas de negócio (como o cálculo de criticidade penalizado pela idade do domínio de 30 dias) para o código sem qualquer falha de raciocínio.

No entanto, diferem massivamente na "personalidade":
* O **Claude** atua como um Arquiteto de Software Sénior obcecado com a Experiência do Utilizador (UX).
* O **GPT** atua como um Engenheiro fiável e pragmático, focado no padrão da indústria e *Clean Code*.
* O **GLM** foca-se no minimalismo e em atingir o resultado com a menor quantidade de código possível.

**Onde as LLMs falharam / Intervenção Humana necessária:**
A maior limitação transversal às três LLMs foi a infraestrutura (Sustentabilidade/Reprodutibilidade do container). O pacote de Python `python-whois` exige que o binário de rede `whois` esteja presente no Sistema Operativo. Muitas vezes as LLMs constroem o `Dockerfile` com o `pip install` esquecendo o `apt-get install whois` (ou equivalente no Alpine), exigindo assim intervenção e correção manual para garantir que o artefacto executa de facto num ambiente virgem. Esta atividade provou que, embora as LLMs sejam excelentes programadoras lógicas, ainda falham na orquestração perfeita de infraestruturas sem a supervisão de um engenheiro humano.
