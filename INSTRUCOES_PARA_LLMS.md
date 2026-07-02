# 🎯 Prompt para Geração de Artefatos (Atividade de Cibersegurança)

**Instruções para o Aluno:** Copie todo o texto abaixo que se encontra entre a marcação e cole em outras LLMs (ex: ChatGPT, Claude, DeepSeek) para gerar as duas versões adicionais do projeto PhishCatch que precisa para a atividade.

---

**[COPIE A PARTIR DAQUI]**

Atue como um Engenheiro de Segurança de Software e Desenvolvedor Python Sénior. Eu preciso de criar um artefato de software de Cibersegurança para fins académicos.

O objetivo do projeto é construir uma ferramenta chamada **PhishCatch**. O PhishCatch é uma ferramenta automatizada de *Threat Intelligence* focada na deteção de ataques de *Typosquatting* e ataques homográficos contra domínios alvo.

**Requisitos Funcionais da Ferramenta:**
1. Receber um domínio alvo por linha de comandos (ex: `google.com`).
2. Gerar permutações do domínio usando técnicas de: Omissão (remover uma letra), Repetição (duplicar uma letra), Transposição (trocar letras adjacentes) e Homógrafos básicos (trocar letras por números visualmente parecidos).
3. Para cada permutação gerada, verificar se o domínio está registado fazendo uma resolução DNS (registo A).
4. Para os domínios registados, verificar:
   - Se possuem servidor web ativo (HTTP 200).
   - Se possuem servidor de e-mail malicioso (verificando a existência de Registos MX).
   - A idade do domínio em dias utilizando uma consulta WHOIS.
5. Calcular o Risco (LOW, MEDIUM, HIGH, CRITICAL):
   - Se tiver web e MX = CRITICAL.
   - Se tiver MX = HIGH.
   - Se tiver web = MEDIUM.
   - Domínios com menos de 30 dias de idade devem subir um nível de risco de penalização (ex: LOW passa a HIGH, HIGH passa a CRITICAL).
6. Executar estas verificações de forma muito rápida usando concorrência (*multithreading* ou *async*).
7. Exportar os resultados encontrados no final da execução para um ficheiro `.csv` contendo as seguintes colunas: `domain`, `is_registered`, `ip_address`, `has_mx_record`, `has_website`, `age_days`, `threat_level`. O terminal também deve exibir os resultados de forma colorida.

**Requisitos do Artefato (O que me deves fornecer):**
Por favor, gere o código e os ficheiros necessários para cumprir os critérios de "Disponibilidade, Funcionalidade, Sustentabilidade e Reprodutibilidade". Deves fornecer o conteúdo completo para os seguintes ficheiros:

1. `phishcatch.py`: O código principal da ferramenta. Deve estar limpo, ser modular e conter tratamento de erros adequado.
2. `requirements.txt`: Todas as bibliotecas externas necessárias.
3. `Dockerfile`: Para executar a ferramenta de forma 100% isolada e reprodutível. (Lembre-se de instalar as ferramentas necessárias de rede/whois no sistema operativo do Docker).
4. `README.md`: Documentação detalhada explicando os requisitos do sistema, como construir a imagem docker, exemplos de como executar e ler os resultados.
5. `test_phishcatch.py`: Ficheiro de testes unitários para validar a lógica de geração de permutações e o sistema de avaliação de risco.

Apresente o conteúdo completo e estruturado de cada ficheiro num bloco de código, para que eu possa guardá-los e testá-los diretamente.

**[FIM DA CÓPIA]**
