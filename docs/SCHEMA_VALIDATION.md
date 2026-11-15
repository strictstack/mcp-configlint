# Validação dos adaptadores — 2026-11-13

Validação executada localmente com Node.js v24.22.1 e Python `jsonschema` 4.10.3, sem resolução de referências externas nem pedidos de rede. O pacote declara Node.js >=22; esta execução foi realizada na versão indicada acima.

| Documento produzido pelo código | Schema oficial local | Resultado |
| --- | --- | --- |
| Relatório SARIF, incluindo findings e localizações lógicas anónimas | SARIF 2.1.0 | PASS |
| `DiscoverResult` | MCP 2026-07-28 | PASS |
| `ListToolsResult` | MCP 2026-07-28 | PASS |
| `CallToolResult` | MCP 2026-07-28 | PASS |
| `InitializeResult` | MCP 2025-11-25 | PASS |
| `ListToolsResult` | MCP 2025-11-25 | PASS |
| `CallToolResult` | MCP 2025-11-25 | PASS |

Os documentos foram gerados por `exportSarif` e `createServer().handleRequest` usando uma configuração sintética e sem credenciais. A validação usou `jsonschema.validators.validator_for(schema)`; nos resultados MCP, a raiz apontou por `$ref` para a definição correspondente em `$defs` ou `definitions` do schema completo. `jsonschema` é uma ferramenta de verificação local, não uma dependência de execução do pacote.

Hashes SHA-256 dos schemas efetivamente validados:

| Ficheiro | SHA-256 |
| --- | --- |
| `schemas/sarif-2.1.0.schema.json` | `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` |
| `schemas/mcp-2026-07-28.schema.json` | `edbb197ed0f92e90d658866e23cf76f107df0caac5ce25c2b9e64e1ca9a6314a` |
| `schemas/mcp-2025-11-25.schema.json` | `268a5f82ba70fd7e4b6dc4aa1e64f116f74b4d0edcb69dc046829c79dd4e97e7` |

Os testes próprios dos adaptadores passaram 11/11, incluindo regressão dos envelopes de erro nas duas versões MCP:

```sh
node --experimental-vm-modules --test tests/adapters.test.mjs tests/offline.test.mjs tests/browser.test.mjs
```

O teste offline instala armadilhas antes de importar o código para `node:http`, `node:https`, `node:net`, `node:tls`, `node:dns`, `node:child_process`, `fetch` e `WebSocket`. Cada armadilha falha na primeira tentativa. A política `allow: []`, `policy: null` recusou três destinos de teste antes de qualquer operação; foram exercitadas tentativas de pedidos de saída `initialize` e `tools/call`. Os nomes desses destinos existem somente nos testes.

| Contador | Resultado |
| --- | ---: |
| Tentativas de conexões/consultas de rede | 0 |
| Tentativas de criação de processos | 0 |
| Pedidos de saída `initialize` | 0 |
| Pedidos de saída `tools/call` | 0 |
| Respostas locais do servidor aos pedidos de teste | 7 |

As respostas locais não são pedidos de saída. O servidor não produziu mensagens com `method`, isto é, não iniciou chamadas ao cliente.

O teste browser carregou e executou o grafo ESM transitivo de `src/index.mjs` usando `vm.SourceTextModule`, sem globais Node e recusando imports que não sejam relativos. Executou lint, verificação de versões, comparação, SARIF e a recusa de saída. Contador de tentativas de rede: 0. Este teste verifica execução em contexto JavaScript isolado; não substitui uma matriz de navegadores reais.

O protocolo preserva IDs numéricos e identificadores string curtos permitidos, recusa IDs detetados como credenciais/caminhos e nunca ecoa nomes de ferramentas desconhecidos, parâmetros inválidos ou conteúdo de configuração nos erros. IDs de protocolo não devem transportar segredos. Deteção estática não prova ausência de comportamento malicioso; esta verificação não é pentest nem certificação de segurança. Os relatórios indicam `ai_generated: false`.

## Envelopes de erro sem identificador legível

Os schemas oficiais MCP `2025-11-25` e `2026-07-28` têm `JSONRPCErrorResponse.id` opcional, com tipo `RequestId` limitado a string ou inteiro. A validação negativa confirmou que `id: null` falha em ambos; omitir `id` passa. Esta especialização também aparece nas descrições oficiais de [MCP 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic#error-responses) e [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic#error-responses). A [especificação JSON-RPC base](https://www.jsonrpc.org/specification#response_object) usa `null` para identificadores desconhecidos; o adaptador segue aqui o contrato MCP específico e documenta a diferença.

Por isso, erros de análise, pedidos inválidos sem identificador legível e IDs recusados por conterem possíveis segredos omitem `id` nas duas versões MCP. Erros associados a um identificador válido preservam-no, incluindo `-32022` para uma versão moderna não suportada. As notificações válidas continuam sem resposta.

A validação completa dos envelopes produzidos pelo código passou nos seguintes casos:

| Caso | MCP 2025-11-25 `JSONRPCErrorResponse` | MCP 2026-07-28 `JSONRPCErrorResponse` |
| --- | --- | --- |
| Erro de análise JSON | PASS | PASS |
| Pedido inválido sem identificador | PASS | PASS |
| Identificador recusado por possível segredo | PASS | PASS |
| Método desconhecido com identificador válido | PASS | PASS |
| Versão moderna não suportada com identificador válido | PASS | PASS |

O último caso também passou a definição específica `UnsupportedProtocolVersionError` de MCP 2026-07-28. Total adicional: 11 validações oficiais de erros aprovadas. O caso da versão moderna foi enviado com metadados por pedido, incluindo quando a mesma instância já tinha concluído uma inicialização anterior; a forma do erro permanece válida nos dois schemas.
