# 🎣 PhishCatch (Gemini Version)

Uma ferramenta otimizada de *Threat Intelligence* e OSINT para análise de ameaças de Typosquatting e Ataques Homográficos.

## 🚀 Melhorias desta Versão (por Gemini)
- **Qualidade de Código**: Adição de Type Hinting (`typing`) e Docstrings em todos os métodos para melhor legibilidade e manutenibilidade.
- **Testes Automatizados**: Inclusão de testes unitários (`test_phishcatch.py`) garantindo sustentabilidade e fiabilidade (Requisito da Atividade).
- **Otimização**: Tratamento de exceções e timeout melhorado nos testes de HTTP e DNS (separação de responsabilidades).
- **Containerização**: `Dockerfile` atualizado para incluir o pacote `whois` do SO, que é uma dependência sistémica do `python-whois`.

## 📦 Estrutura do Diretório
- `phishcatch.py`: O código principal otimizado da aplicação.
- `test_phishcatch.py`: Testes unitários para validar a lógica de negócio.
- `requirements.txt`: Dependências Python necessárias.
- `Dockerfile`: Instruções para criar o ambiente isolado.
- `README.md`: Este ficheiro.

## ⚙️ Como Executar

### Via Docker (Recomendado)
Para garantir que não ocorrem erros com dependências de sistema, utilize o Docker.

1. Construir a Imagem:
```bash
docker build -t phishcatch-gemini .
```

2. Executar a Ferramenta:
```bash
docker run --rm -v $(pwd):/app phishcatch-gemini google.com
```

### Executar Testes
Para correr os testes unitários garantindo que tudo está a funcionar corretamente:
```bash
python -m unittest test_phishcatch.py
```
