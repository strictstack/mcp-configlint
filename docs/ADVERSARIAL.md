# Revisão adversarial independente

Data: 2026-11-13 UTC. O revisor escreveu `tests/adversarial.test.mjs` sem alterar os módulos de produção. Os achados foram comunicados aos respetivos responsáveis, que aplicaram as correções. A execução independente terminou com **17 testes aprovados, zero falhas e zero testes ignorados**.

Reprodução local:

```sh
node --test tests/adversarial.test.mjs
```

| Área | Verificação concreta |
|---|---|
| JSONC e nomes | Membros duplicados após escapes Unicode, duplicados aninhados, nomes repetidos em listas e comentários sem reescrita de strings. |
| Objetos adversariais | Propriedades especiais não poluem protótipos; getters não são executados; ciclos, profundidade excessiva e tamanho UTF-8 são recusados. |
| Confidencialidade | Canários sintéticos colocados em nomes, argumentos, variáveis, cabeçalhos e URL não aparecem nas saídas de análise, comparação, parser, SARIF ou erros de regras. |
| Referências de pacotes | Instalações de vários pacotes inspecionam também referências posteriores ao primeiro pacote. |
| MCP legado | A inicialização exige a notificação de conclusão; reinicialização é recusada; uma nova sessão não herda o estado anterior. |
| MCP atual | Metadados por pedido obrigatórios; capacidades inválidas recusadas; versões inválidas não refletem conteúdo arbitrário. Identificadores inválidos ou considerados secretos são omitidos dos erros, em conformidade com os esquemas MCP. |
| Fronteira das ferramentas | Nomes não publicados e argumentos adicionais são recusados; notificações não executam chamadas com resposta. |
| Transporte | Uma mensagem excessiva é descartada e o pedido seguinte é processado; bytes UTF-8 repartidos preservam pedidos válidos. |

Dois achados funcionais motivaram correções: o analisador parava no primeiro pacote de uma instalação com vários argumentos e o servidor legado aceitava ferramentas antes da conclusão da inicialização. Os testes de regressão cobrem ambos. A revisão também verificou as restrições aplicadas a identificadores e versões para evitar reflexão de canários.

Estes testes são determinísticos e não contactam serviços externos. Usam dados e credenciais obviamente falsos apenas dentro de `tests/`. Os testes próprios dos autores e a validação de esquemas constam dos relatórios correspondentes; não estão incluídos na contagem de 17 acima.

A análise estática não executa comandos configurados, não descarrega pacotes e não comprova que um servidor remoto seja benigno. A comparação utiliza a posição dos servidores; reordenar a configuração pode produzir alterações aparentes. A deteção de segredos é heurística, embora as saídas evitem reproduzir os valores analisados. Esta revisão não constitui um teste de intrusão nem uma certificação de segurança.
