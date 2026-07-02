#!/bin/bash

echo "========================================================"
echo "🧪 Iniciando Bateria de Testes Unitários: PhishCatch"
echo "========================================================"

echo ""
echo "⚙️ [1/3] A testar Versão A: Claude 4.8 Opus..."
cd phishcatch-claude
# Reconstruir a imagem apenas por precaução, redirecionando o output para não sujar o ecrã
docker build -t phishcatch-claude . > /dev/null
# Sobrescreve o ENTRYPOINT para correr os testes em vez da aplicação principal
docker run --rm --entrypoint python phishcatch-claude -m unittest test_phishcatch.py
cd ..

echo ""
echo "⚙️ [2/3] A testar Versão B: GPT-4.5 Omni..."
cd phishcatch-gpt
docker build -t phishcatch-gpt . > /dev/null
docker run --rm --entrypoint python phishcatch-gpt -m unittest test_phishcatch.py
cd ..

echo ""
echo "⚙️ [3/3] A testar Versão C: GLM-4 Plus..."
cd phishcatch-glm
docker build -t phishcatch-glm . > /dev/null
docker run --rm --entrypoint python phishcatch-glm -m unittest test_phishcatch.py
cd ..

echo ""
echo "✅ Testes Concluídos!"
echo "========================================================"
