# PhishCatch (GLM Version)

A fast, concurrent Threat Intelligence tool to discover typosquatting domains.
Built using `asyncio`, `aiohttp`, and `aiodns` for extreme performance.

## Execution
```bash
docker build -t phishcatch-glm .
docker run --rm phishcatch-glm <domain>
```
