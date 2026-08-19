# Arquitetura

O projeto separa ingestão, normalização, detecção, orquestração e apresentação. Essa divisão permite analisar fontes Linux e Windows com as mesmas regras sem misturar sintaxe de logs com lógica de segurança.

## Visão geral

```text
CLI analyze-linux          -> LinuxLogFileAnalyzer ------> LinuxAuthenticationParser ----\
CLI analyze-windows        -> WindowsJsonFileAnalyzer ---> WindowsAuthenticationParser ----> AuthenticationEvent[]
CLI analyze-windows-native -> WindowsNativeEventAnalyzer -> WindowsAuthenticationParser --/             |
                                                                                                         +-> BruteForceDetector
                                                                                                         +-> OffHoursLoginDetector
                                                                                                         +-> PasswordSprayDetector
                                                                                                         +-> SuccessfulLoginAfterFailuresDetector
                                                                                                                 |
                                                                                                                 v
                                                                                                      resultado estruturado
                                                                                                         /          \
                                                                                              relatório da CLI   serialização
                                                                                                                  /       \
                                                                                                               JSON       CSV
```

As responsabilidades são:

- **CLI:** valida argumentos, compõe objetos configurados, inicia a análise, formata o resultado e solicita exportações opcionais;
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

O Windows possui dois caminhos independentes que convergem no mesmo `WindowsAuthenticationParser`.

### Windows JSON

`WindowsJsonFileAnalyzer` lê em UTF-8 um array JSON de eventos previamente extraídos. Cada timestamp é convertido de ISO 8601 com offset explícito antes de chegar ao parser, que aceita:

- Event ID 4624 como sucesso;
- Event ID 4625 como falha.

Event IDs inteiros diferentes são contabilizados como não suportados. Registros inválidos geram `WindowsJsonRecordError` e os registros seguintes continuam sendo processados. JSON sintaticamente inválido ou com raiz diferente de array impede a análise do documento. O JSON permanece como formato de intercâmbio para análise portátil ou offline.

### Windows Security Event Log nativo

`WindowsEventLogCollector` executa `wevtutil` sem shell e consulta somente o log `Security`, usando XPath limitado aos Event IDs 4624 e 4625. A saída XML estruturada fornece `EventID`, `TimeCreated SystemTime`, `TargetUserName` e `IpAddress`. O limite padrão de coleta é 100 eventos e permanece configurável.

`WindowsNativeEventAnalyzer` converte cada elemento XML para o mapeamento já aceito pelo `WindowsAuthenticationParser`. Assim, mapeamento de sucesso/falha, validação de username/IP e plataforma continuam centralizados no parser existente. Registros individuais inválidos são contabilizados sem armazenar o XML bruto; indisponibilidade do coletor, plataforma incompatível, falha da query e documento XML estruturalmente inválido são erros operacionais distintos.

Esse caminho é somente leitura, local e exclusivo do Windows. Ele não eleva privilégios, modifica políticas, limpa logs, lê EVTX nem coleta eventos remotos.

## Detecção

Todos os detectores recebem a mesma coleção de `AuthenticationEvent` e não conhecem o formato original.

### Força bruta

`BruteForceDetector` correlaciona falhas pela combinação exata de username e IP de origem. O threshold e a janela inclusiva são configuráveis. Sucessos não contam nem reiniciam a sequência, e eventos sem IP não participam. Um achado é emitido por episódio contínuo para evitar alertas repetidos de janelas sobrepostas.

### Password spraying

`PasswordSprayDetector` correlaciona falhas pelo IP de origem e conta usernames distintos em uma janela inclusiva. Repetições contra a mesma identidade não aumentam a cardinalidade. Os usernames do achado têm ordem determinística e preservam seus valores exatos.

### Login fora do horário

`OffHoursLoginDetector` avalia somente sucessos contra weekdays e horários permitidos. O intervalo diário inclui o início e exclui o fim. Janelas que atravessam meia-noite usam o weekday de início: a parte após meia-noite pertence à janela iniciada no dia anterior. A avaliação usa o horário de parede e o timezone representados pelo evento.

### Login bem-sucedido após falhas repetidas

`SuccessfulLoginAfterFailuresDetector` correlaciona falhas e um sucesso posterior pelo username exato e IP de origem. A janela inclusiva usa instantes absolutos, e eventos sem IP não participam. Falhas com o mesmo timestamp absoluto do sucesso não contam como anteriores. Um sucesso sempre encerra a sequência daquela chave: quando o threshold foi atingido, ele produz um finding; caso contrário, apenas reinicia o estado temporário. A plataforma preservada é a do evento de sucesso, mas não faz parte da correlação.

O detector é stateless entre chamadas e heurístico. O finding indica que tentativas repetidas foram seguidas por autenticação bem-sucedida, sem afirmar comprometimento da conta.

## Resultados e erros

Os resultados Linux e Windows são dataclasses imutáveis com contagens, erros recuperáveis e findings separados por detector. Eles permanecem específicos para que linhas Linux e registros Windows sejam descritos com precisão.

Falhas de filesystem e decoding não são confundidas com registros malformados. Na CLI, uma análise concluída retorna `0`, mesmo com findings ou erros recuperáveis. Falhas operacionais retornam `1`, e argumentos ou configurações inválidas retornam `2`. Mensagens de erro não reproduzem a linha ou o objeto bruto potencialmente sensível.

## Relatórios

A camada `reporting` recebe um resultado de análise concluído e permanece a jusante de ingestão, normalização e detecção. Ela não altera eventos nem findings.

O JSON representa o resultado completo com `report_version` 1, origem, resumo, erros recuperáveis e categorias de findings. As origens estáveis são `linux_file`, `windows_json` e `windows_native`. O CSV representa somente findings em colunas unificadas, usando os tipos `brute_force`, `off_hours`, `password_spray` e `successful_login_after_failures`; campos não aplicáveis permanecem vazios. O quarto tipo acrescenta `first_failure`, `last_failure` e `successful_login` ao conjunto unificado de colunas.

`report_version` permanece em 1 porque categorias de finding e colunas adicionais são extensões aditivas do contrato, que já separa findings por tipo. Nenhuma chave existente foi removida ou teve semântica alterada.

Ambos usam UTF-8 e timestamps ISO 8601 sem conversão para o timezone da máquina. A gravação ocorre primeiro em arquivo temporário no diretório de destino e depois por substituição atômica. Destinos existentes são preservados por padrão e só podem ser substituídos por solicitação explícita.

## Limites arquiteturais

A aplicação não implementa EVTX, coleta Windows remota, persistência, formatos de relatório além de JSON/CSV ou integração com SIEM. Os detectores mantêm semânticas explícitas e independentes; não há framework genérico de plugins ou estado persistente de incidentes. Extensões do modelo e dos fluxos devem ser justificadas por requisitos concretos.
