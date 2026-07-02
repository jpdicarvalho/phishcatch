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
docker rm -f phish_claude 2>/dev/null
# Executamos SEM o volume e SEM --rm, para o container não se apagar no fim
docker run --name phish_claude phishcatch-claude "$DOMAIN"
# Criamos uma pasta temporária, extraímos tudo do container e movemos apenas o CSV gerado
mkdir -p tmp_out
docker cp phish_claude:/app/ tmp_out/
mv tmp_out/app/*.csv "$OUTPUT_DIR/phishcatch_report_claude.csv" 2>/dev/null
rm -rf tmp_out
docker rm phish_claude
cd ..

echo ""
echo "🚀 [2/3] A executar Versão B: GPT-4.5 Omni..."
cd phishcatch-gpt
docker build -t phishcatch-gpt .
docker rm -f phish_gpt 2>/dev/null
docker run --name phish_gpt phishcatch-gpt "$DOMAIN"
mkdir -p tmp_out
docker cp phish_gpt:/app/ tmp_out/
mv tmp_out/app/*.csv "$OUTPUT_DIR/phishcatch_report_gpt.csv" 2>/dev/null
rm -rf tmp_out
docker rm phish_gpt
cd ..

echo ""
echo "🚀 [3/3] A executar Versão C: GLM-4 Plus..."
cd phishcatch-glm
docker build -t phishcatch-glm .
docker rm -f phish_glm 2>/dev/null
docker run --name phish_glm phishcatch-glm "$DOMAIN"
mkdir -p tmp_out
docker cp phish_glm:/app/ tmp_out/
mv tmp_out/app/*.csv "$OUTPUT_DIR/phishcatch_report_glm.csv" 2>/dev/null
rm -rf tmp_out
docker rm phish_glm
cd ..

echo ""
echo "✅ Varredura Completa! Todos os relatórios CSV foram exportados para a diretoria atual:"
ls -l "$OUTPUT_DIR"/*.csv 2>/dev/null
echo "========================================================"
