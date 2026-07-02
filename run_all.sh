#!/bin/bash

if [ -z "$1" ]; then
    echo "Uso: ./run_all.sh <dominio-alvo>"
    echo "Exemplo: ./run_all.sh google.com"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR=$(pwd)

echo "========================================================"
echo "🎯 Iniciando Avaliação Comparativa: PhishCatch"
echo "Alvo: $DOMAIN"
echo "========================================================"

echo ""
echo "🚀 [1/3] A executar Versão A: Claude 4.8 Opus..."
cd phishcatch-claude
docker build -t phishcatch-claude .
docker run --rm -v "$OUTPUT_DIR:/app" phishcatch-claude "$DOMAIN"
cd ..

echo ""
echo "🚀 [2/3] A executar Versão B: GPT-4.5 Omni..."
cd phishcatch-gpt
docker build -t phishcatch-gpt .
docker run --rm -v "$OUTPUT_DIR:/app" phishcatch-gpt "$DOMAIN"
cd ..

echo ""
echo "🚀 [3/3] A executar Versão C: GLM-4 Plus..."
cd phishcatch-glm
docker build -t phishcatch-glm .
docker run --rm -v "$OUTPUT_DIR:/app" phishcatch-glm "$DOMAIN"
cd ..

echo ""
echo "✅ Varredura Completa! Todos os relatórios CSV foram exportados para a diretoria atual."
echo "========================================================"
