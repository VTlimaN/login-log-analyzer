# Arquitetura

O projeto separa ingestão, normalização, detecção, orquestração e apresentação. Essa divisão permite analisar fontes Linux e Windows com as mesmas regras sem misturar sintaxe de logs com lógica de segurança.

## Visão geral

```text
Linux -> LinuxAuthenticationParser -> AuthenticationEvent[] -> detectores heurísticos -------------------------\
Windows JSON/nativo -> roteamento -> 4624/4625 -> WindowsAuthenticationParser -> AuthenticationEvent[] --------> resultado
                                  |-> 4740 -> WindowsAccountLockoutParser -> AccountLockoutEvent[] -------------/
                                  \-> lifecycle IDs -> WindowsAccountLifecycleParser -> AccountLifecycleEvent[] /
                                                                                                                  |
                                                                                                       CLI / serialização
                                                                                                            /       \
                                                                                               JSON completo       CSV findings
```

As responsabilidades são:

- **CLI:** valida argumentos, compõe objetos configurados, inicia a análise, formata o resultado e solicita exportações opcionais;
- **analisadores de arquivo:** leem a fonte, coordenam parsing e detectores e produzem um resultado estruturado;
- **parsers:** traduzem a representação específica da fonte;
- **`AuthenticationEvent`:** representa a semântica comum de autenticação de Linux e Windows 4624/4625;
- **`AccountLockoutEvent`:** representa uma observação direta de bloqueio Windows 4740;
- **`AccountLifecycleEvent`:** representa uma transição explícita de ciclo de vida de conta Windows;
- **detectores:** aplicam regras heurísticas somente aos `AuthenticationEvent` normalizados.

## Normalização

Linux e Windows registram autenticação com estruturas diferentes. A normalização converte os campos necessários para uma representação comum e imutável:

- `timestamp`: `datetime` com timezone explícito;
- `username`: identidade preservada como observada;
- `outcome`: sucesso ou falha;
- `platform`: Linux ou Windows;
- `source_ip`: IPv4, IPv6 ou ausência de origem significativa.

Timestamps sem timezone são rejeitados para evitar comparações ambíguas. Endereços são validados pelos tipos de IP da biblioteca padrão. `AccountLockoutEvent` é uma família separada com contexto próprio do bloqueio. `AccountLifecycleEvent` possui conta alvo, `AccountLifecycleAction`, plataforma Windows e contextos opcionais de domínio, ator e computador de registro. Nenhuma das observações diretas possui `AuthenticationOutcome` ou é forçada a usar `source_ip`.

## Ingestão Linux

`LinuxLogFileAnalyzer` lê arquivos UTF-8 incrementalmente, linha a linha. `LinuxAuthenticationParser` reconhece um subconjunto explícito das mensagens OpenSSH de senha:

- `Accepted password`;
- `Failed password`;
- `Failed password for invalid user`.

O timestamp syslog não contém ano nem timezone, então o chamador fornece esse contexto explicitamente. Linhas não suportadas são contabilizadas. Uma mensagem de formato suportado com dados inválidos gera `LinuxLogParseError`, mas não interrompe as demais linhas.

## Ingestão Windows

O Windows possui dois caminhos de origem que aplicam o mesmo roteamento explícito por Event ID.

### Windows JSON

`WindowsJsonFileAnalyzer` lê em UTF-8 um array JSON de eventos previamente extraídos. Cada timestamp suportado é convertido de ISO 8601 com offset explícito. O roteamento usa:

- Event ID 4624 como sucesso;
- Event ID 4625 como falha;
- Event ID 4740 como observação de bloqueio por `WindowsAccountLockoutParser`;
- Event IDs 4720, 4722, 4725, 4726 e 4767 como observações de ciclo de vida por `WindowsAccountLifecycleParser`.

Event IDs inteiros diferentes são contabilizados como não suportados. Registros inválidos geram `WindowsJsonRecordError` e os registros seguintes continuam sendo processados. JSON sintaticamente inválido ou com raiz diferente de array impede a análise do documento. O JSON permanece como formato de intercâmbio para análise portátil ou offline.

### Windows Security Event Log nativo

`WindowsEventLogCollector` executa `wevtutil` sem shell e consulta somente o log `Security`, usando XPath limitado aos Event IDs 4624, 4625, 4720, 4722, 4725, 4726, 4740 e 4767. Os IDs 4723, 4724 e 4738 ficam deliberadamente fora da consulta. O limite padrão de coleta é 100 eventos e permanece configurável.

`WindowsNativeEventAnalyzer` roteia cada elemento XML pelo Event ID. 4624/4625 continuam no parser de autenticação; 4740 segue para o parser de bloqueio; os cinco IDs de lifecycle seguem para o parser de ciclo de vida. Para lifecycle, `TargetUserName`/`TargetDomainName` identificam a conta afetada, `SubjectUserName`/`SubjectDomainName` preservam o ator quando disponível e `System/Computer` torna-se `recording_computer`. Campos opcionais podem faltar conforme o evento. Registros individuais inválidos são contabilizados sem armazenar XML bruto.

Esse caminho é somente leitura, local e exclusivo do Windows. Ele não eleva privilégios, modifica políticas, limpa logs, lê EVTX nem coleta eventos remotos.

## Detecção

Todos os detectores recebem a mesma coleção de `AuthenticationEvent` e não conhecem o formato original.

`AccountLockoutEvent` e `AccountLifecycleEvent` nunca são enviados a detectores. Eles são observações explícitas do sistema operacional, não findings heurísticos nem falhas de autenticação sintéticas. Não existem detectores triviais que apenas espelham essas observações.

### Força bruta

`BruteForceDetector` correlaciona falhas pela combinação exata de username e IP de origem. O threshold e a janela inclusiva são configuráveis. Sucessos não contam nem reiniciam a sequência, e eventos sem IP não participam. Um achado é emitido por episódio contínuo para evitar alertas repetidos de janelas sobrepostas.

### Password spraying

`PasswordSprayDetector` correlaciona falhas pelo IP de origem e conta usernames distintos em uma janela inclusiva. Repetições contra a mesma identidade não aumentam a cardinalidade. Os usernames do achado têm ordem determinística e preservam seus valores exatos.

### Login fora do horário

`OffHoursLoginDetector` avalia somente sucessos contra weekdays e horários permitidos. O intervalo diário inclui o início e exclui o fim. Janelas que atravessam meia-noite usam o weekday de início: a parte após meia-noite pertence à janela iniciada no dia anterior. A avaliação usa o horário de parede e o timezone representados pelo evento.

### Login bem-sucedido após falhas repetidas

`SuccessfulLoginAfterFailuresDetector` correlaciona falhas e um sucesso posterior pelo username exato e IP de origem. A janela inclusiva usa instantes absolutos, e eventos sem IP não participam. Falhas com o mesmo timestamp absoluto do sucesso não contam como anteriores. Um sucesso sempre encerra a sequência daquela chave: quando o threshold foi atingido, ele produz um finding; caso contrário, apenas reinicia o estado temporário. A plataforma preservada é a do evento de sucesso, mas não faz parte da correlação.

O detector é stateless entre chamadas e heurístico. O finding indica que tentativas repetidas foram seguidas por autenticação bem-sucedida, sem afirmar comprometimento da conta.

### Múltiplos IPs de origem contra uma conta

`MultipleSourceIPsDetector` correlaciona falhas pelo username exato e conta IPs de origem distintos em uma janela inclusiva de instantes absolutos. Eventos sem IP e sucessos não participam; sucessos também não reiniciam o episódio. Plataforma não compõe a chave, permitindo correlação entre eventos Linux e Windows normalizados.

Um finding é emitido quando o threshold de IPs distintos é atingido e novos findings ficam suprimidos enquanto as falhas consecutivas do username permanecem separadas por no máximo a janela. Uma lacuna maior inicia novo episódio. A tupla de IPs é imutável e ordenada deterministicamente por versão e valor numérico. A regra é heurística e não afirma intenção maliciosa.

## Resultados e erros

Os resultados Linux e Windows são dataclasses imutáveis com contagens, erros recuperáveis e findings separados por detector. Resultados Windows mantêm coleções e contagens separadas para lockout e lifecycle; `parsed_event_count` continua contando apenas autenticações normalizadas.

Falhas de filesystem e decoding não são confundidas com registros malformados. Na CLI, uma análise concluída retorna `0`, mesmo com findings ou erros recuperáveis. Falhas operacionais retornam `1`, e argumentos ou configurações inválidas retornam `2`. Mensagens de erro não reproduzem a linha ou o objeto bruto potencialmente sensível.

## Relatórios

A camada `reporting` recebe um resultado de análise concluído e permanece a jusante de ingestão, normalização e detecção. Ela não altera eventos nem findings.

O JSON representa o resultado completo com `report_version` 1, origem, resumo, erros recuperáveis e categorias de findings. Resultados Windows acrescentam contagens e coleções `account_lockouts` e `account_lifecycle` para observações diretas. O CSV representa somente findings heurísticos e deliberadamente não converte observações em `finding_type`.

`report_version` permanece em 1 porque as coleções de observações e suas contagens são extensões aditivas para fontes Windows. Nenhuma chave existente foi removida ou reinterpretada, e o contrato CSV não mudou.

Ambos usam UTF-8 e timestamps ISO 8601 sem conversão para o timezone da máquina. A gravação ocorre primeiro em arquivo temporário no diretório de destino e depois por substituição atômica. Destinos existentes são preservados por padrão e só podem ser substituídos por solicitação explícita.

## Limites arquiteturais

A aplicação não implementa EVTX, coleta Windows remota, persistência, formatos de relatório além de JSON/CSV ou integração com SIEM. Os detectores mantêm semânticas explícitas e independentes; não há framework genérico de plugins ou estado persistente de incidentes. Extensões do modelo e dos fluxos devem ser justificadas por requisitos concretos.
