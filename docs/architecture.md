# Arquitetura

O projeto separa ingestão, normalização, detecção, orquestração e apresentação. Essa divisão permite analisar fontes Linux e Windows com as mesmas regras sem misturar sintaxe de logs com lógica de segurança.

## Visão geral

```text
CLI analyze-linux   -> LinuxLogFileAnalyzer   -> LinuxAuthenticationParser ----\
                                                                              \
                                                                               > AuthenticationEvent[]
                                                                              /             |
CLI analyze-windows -> WindowsJsonFileAnalyzer -> WindowsAuthenticationParser /              +-> BruteForceDetector
                                                                                            +-> OffHoursLoginDetector
                                                                                            +-> PasswordSprayDetector
                                                                                                    |
                                                                                                    v
                                                                                         resultado estruturado
                                                                                                    |
                                                                                                    v
                                                                                            relatório da CLI
```

As responsabilidades são:

- **CLI:** valida argumentos, compõe objetos configurados, inicia a análise e formata o resultado;
- **analisadores de arquivo:** leem a fonte, coordenam parsing e detectores e produzem um resultado estruturado;
- **parsers:** traduzem a representação específica da fonte;
- **`AuthenticationEvent`:** representa a semântica comum de autenticação;
- **detectores:** aplicam regras de segurança somente aos eventos normalizados.

## Normalização

Linux e Windows registram autenticação com estruturas diferentes. A normalização converte os campos necessários para uma representação comum e imutável:

- `timestamp`: `datetime` com timezone explícito;
- `username`: identidade preservada como observada;
- `outcome`: sucesso ou falha;
- `platform`: Linux ou Windows;
- `source_ip`: IPv4, IPv6 ou ausência de origem significativa.

Timestamps sem timezone são rejeitados para evitar comparações ambíguas. Endereços são validados pelos tipos de IP da biblioteca padrão. O modelo contém apenas o contexto exigido pelas regras atuais; informações específicas, como Windows Logon Type, não são acrescentadas sem uma necessidade concreta.

## Ingestão Linux

`LinuxLogFileAnalyzer` lê arquivos UTF-8 incrementalmente, linha a linha. `LinuxAuthenticationParser` reconhece um subconjunto explícito das mensagens OpenSSH de senha:

- `Accepted password`;
- `Failed password`;
- `Failed password for invalid user`.

O timestamp syslog não contém ano nem timezone, então o chamador fornece esse contexto explicitamente. Linhas não suportadas são contabilizadas. Uma mensagem de formato suportado com dados inválidos gera `LinuxLogParseError`, mas não interrompe as demais linhas.

## Ingestão Windows

`WindowsJsonFileAnalyzer` lê em UTF-8 um array JSON de eventos previamente extraídos. Cada timestamp é convertido de ISO 8601 com offset explícito antes de chegar ao `WindowsAuthenticationParser`, que aceita:

- Event ID 4624 como sucesso;
- Event ID 4625 como falha.

Event IDs inteiros diferentes são contabilizados como não suportados. Registros inválidos geram `WindowsJsonRecordError` e os registros seguintes continuam sendo processados. JSON sintaticamente inválido ou com raiz diferente de array impede a análise do documento. O JSON é um formato de intercâmbio; não existe coleta nativa do Windows Event Log nem leitura de EVTX.

## Detecção

Todos os detectores recebem a mesma coleção de `AuthenticationEvent` e não conhecem o formato original.

### Força bruta

`BruteForceDetector` correlaciona falhas pela combinação exata de username e IP de origem. O threshold e a janela inclusiva são configuráveis. Sucessos não contam nem reiniciam a sequência, e eventos sem IP não participam. Um achado é emitido por episódio contínuo para evitar alertas repetidos de janelas sobrepostas.

### Password spraying

`PasswordSprayDetector` correlaciona falhas pelo IP de origem e conta usernames distintos em uma janela inclusiva. Repetições contra a mesma identidade não aumentam a cardinalidade. Os usernames do achado têm ordem determinística e preservam seus valores exatos.

### Login fora do horário

`OffHoursLoginDetector` avalia somente sucessos contra weekdays e horários permitidos. O intervalo diário inclui o início e exclui o fim. Janelas que atravessam meia-noite usam o weekday de início: a parte após meia-noite pertence à janela iniciada no dia anterior. A avaliação usa o horário de parede e o timezone representados pelo evento.

## Resultados e erros

Os resultados Linux e Windows são dataclasses imutáveis com contagens, erros recuperáveis e findings separados por detector. Eles permanecem específicos para que linhas Linux e registros Windows sejam descritos com precisão.

Falhas de filesystem e decoding não são confundidas com registros malformados. Na CLI, uma análise concluída retorna `0`, mesmo com findings ou erros recuperáveis. Falhas operacionais retornam `1`, e argumentos ou configurações inválidas retornam `2`. Mensagens de erro não reproduzem a linha ou o objeto bruto potencialmente sensível.

## Limites arquiteturais

A aplicação não implementa coleta nativa do Windows, EVTX, persistência, exportação de relatório ou integração com SIEM. Os detectores mantêm semânticas explícitas e independentes; não há framework genérico de plugins ou estado persistente de incidentes. Extensões do modelo e dos fluxos devem ser justificadas por requisitos concretos.
