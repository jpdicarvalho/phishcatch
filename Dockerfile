# Usa uma imagem oficial e leve do Python 3.10
FROM python:3.10-slim

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia os requisitos e instala
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código-fonte da ferramenta
COPY phishcatch.py .

# Define o Entrypoint. 
# Quando o usuário rodar o container, ele automaticamente chama o script.
ENTRYPOINT ["python", "phishcatch.py"]