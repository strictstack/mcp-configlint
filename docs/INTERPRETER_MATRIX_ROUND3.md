# Matriz de intérpretes — ronda 3

Verificação local em 2026-11-13. O motor apenas interpreta dados de configuração: os comandos das fixtures não foram executados, nenhuma ligação de rede foi aberta e nenhum servidor MCP foi chamado.

| Corpus sintético | Configurações | Servidores analisados | Pares servidor/regra | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Original, preservado | 20 | 39 | 1092 | 69 | 0 | 0 | 1023 |
| Ronda 3 | 81 | 81 | 2268 | 157 | 0 | 0 | 2111 |
| Combinado | 101 | 120 | 3360 | 226 | 0 | 0 | 3134 |

Uma configuração original contém sintaxe inválida e é verificada separadamente; não contribui com pares servidor/regra. São comparadas todas as 28 regras para cada servidor, contra expectativas declaradas nas manifests. A precisão e a cobertura calculadas são 1 em ambos os corpora. Estas métricas descrevem somente os exemplos sintéticos e não estimam a eficácia em configurações reais.

Os 81 casos novos incluem 47 casos perigosos, 16 avaliações simples ou redireções que recebem apenas os avisos aplicáveis, e 18 configurações válidas sem findings. A [matriz JSON](INTERPRETER_MATRIX_ROUND3.json) inclui expectativas, resultados por servidor e contagens por regra.

Os casos cobrem wrappers recursivos `env`, `sudo`, `nohup`, `busybox`, `timeout`, `nice`, `setsid`, `stdbuf`, `ionice`, `taskset` e `chrt`; opções com valores, `--`, `env -S`, `bash --rcfile F -c`; avaliações Perl/Ruby, incluindo vários `-e`; e `npx -c`/`--call`. O código passado a `npx -c` deixa de ser confundido com um pacote sem versão.

Redireções `>`, `>>` e `<` no campo `command` recebem MCL-009. Operadores citados, escapados ou entregues como argumentos literais não recebem esse aviso. MCL-007 continua reservado ao encadeamento de comandos. O padrão PowerShell `IEX (New-Object Net.WebClient).DownloadString(...)`, incluindo `Invoke-Expression -Command`, recebe MCL-008 e MCL-009. Texto citado, comentários, download sem avaliação e execução de um ficheiro local conservam os limites esperados.

Verificação reproduzível:

```sh
node scripts/generate-fixtures.mjs
node --test tests/interpreters-round2.test.mjs tests/interpreters-round3.test.mjs
```

Resultado: 99 testes aprovados, zero falhas. O teste ronda 3 emite o dataset `synthetic-round3-per-server`, com as métricas e a distribuição por categoria. Também verifica localizações `command`/`args`, 150 wrappers encadeados, limites de scripts e opções, e ausência de canários privados em lint, comparação, verificação de versões, parser e SARIF.

A análise permanece limitada a padrões literais conhecidos; wrappers desconhecidos, aliases, código dinâmico, fluxo de dados entre fragmentos e conteúdo de payloads codificados ficam fora desta cobertura. Todos os exemplos usam domínios e dados sintéticos. Esta matriz não é uma certificação de ausência de comportamento malicioso.
