# Direção arquitetural

O projeto seguirá, inicialmente, um fluxo de análise em etapas:

```text
logs brutos de autenticação
            |
            v
parsing específico por plataforma
            |
            v
eventos de autenticação normalizados
            |
            v
regras de detecção
            |
            v
achados ou alertas
```

Logs de autenticação do Windows e do Linux possuem formatos, campos e semânticas diferentes. A normalização deverá representar as informações relevantes em um formato comum, permitindo que regras de detecção operem independentemente da plataforma de origem quando isso for tecnicamente adequado.

Essa separação também preserva as responsabilidades: componentes específicos interpretam cada fonte, enquanto a análise recebe eventos consistentes. Informações próprias de uma plataforma poderão continuar disponíveis quando forem necessárias para uma detecção correta.

Este documento registra uma direção arquitetural, não um contrato de implementação permanentemente congelado. Interfaces, modelos e limites entre componentes serão definidos somente quando os requisitos concretos dos próximos milestones justificarem essas decisões.

## Modelo normalizado atual

Normalizar um evento significa converter informações relevantes de formatos diferentes para uma representação comum. Assim, eventos equivalentes do Windows e do Linux poderão ser analisados sem que as futuras regras de detecção precisem conhecer a sintaxe original de cada log.

O `AuthenticationEvent` representa atualmente:

- `timestamp`: instante do evento como `datetime` com informação explícita de fuso horário;
- `username`: identidade usada na tentativa de autenticação;
- `outcome`: resultado fechado em sucesso ou falha;
- `platform`: plataforma de origem fechada em Linux ou Windows;
- `source_ip`: endereço IPv4 ou IPv6 de origem, opcional quando o evento não fornece um endereço significativo.

O modelo é imutável porque representa um fato observado. Timestamps sem fuso horário são rejeitados para evitar instantes ambíguos. O modelo preserva o offset informado pelo futuro parser e não executa conversões de fuso. Endereços IP usam os tipos da biblioteca padrão do Python, o que mantém uma representação validada sem dependências externas.

Os campos atuais atendem às necessidades conhecidas de correlação por usuário e origem, análise temporal e distinção entre sucessos e falhas. Novos campos somente deverão ser incluídos quando um requisito concreto demonstrar sua necessidade. A direção futura de parsers e detecções continua não vinculante.

## Caminho de parsing Linux

O primeiro caminho concreto de normalização é:

```text
linha de autenticação SSH em log Linux
                    |
                    v
LinuxAuthenticationParser
                    |
                    v
AuthenticationEvent
```

O parser reconhece um subconjunto explícito de mensagens de autenticação por senha do OpenSSH e traduz a sintaxe específica do Linux para o modelo normalizado. Linhas não suportadas são ignoradas, enquanto mensagens que correspondem aos eventos suportados, mas contêm dados malformados, produzem um erro de parsing.

Como o timestamp syslog tradicional não contém ano nem fuso horário, essas informações são fornecidas pelo chamador. O parser não consulta o relógio nem o fuso da máquina.

## Caminhos de normalização por plataforma

```text
linha de autenticação SSH em log Linux
                    |
                    v
LinuxAuthenticationParser
                    |
                    v
AuthenticationEvent
                    ^
                    |
WindowsAuthenticationParser
                    ^
                    |
dados estruturados do Windows Security
```

O `WindowsAuthenticationParser` recebe dados que já foram extraídos de um evento e reconhece somente os Event IDs 4624 e 4625. Ele não acessa APIs do sistema operacional nem interpreta XML ou arquivos EVTX. Eventos não suportados são ignorados e dados inválidos em eventos suportados produzem um erro de parsing.

Os parsers convergem representações específicas das plataformas para o mesmo modelo normalizado. Isso permite que futuras regras consumam `AuthenticationEvent` sem conhecer a sintaxe do OpenSSH ou a estrutura original do Windows Security.

Eventos Windows também oferecem informações como Logon Type. Esse contexto não integra o modelo atual porque ainda não existe um requisito de detecção que o justifique. A futura coleta de eventos, possíveis extensões do modelo e as etapas de detecção permanecem direções arquiteturais não vinculantes.

## Detecção de força bruta

```text
LinuxAuthenticationParser   --\
                                > AuthenticationEvent -> BruteForceDetector -> BruteForceFinding
WindowsAuthenticationParser --/
```

Parsing interpreta a representação específica de cada plataforma. Normalização converte os dados extraídos para `AuthenticationEvent`. Detecção opera somente sobre esses eventos e, por isso, não precisa conhecer formatos OpenSSH ou Windows Security.

A regra atual correlaciona falhas pela combinação exata de username e endereço IP de origem. Ela exige um número configurável de falhas dentro de uma janela inclusiva e compara instantes absolutos mesmo quando os eventos usam offsets diferentes. Sucessos não contam nem encerram a sequência, e eventos sem IP não participam da regra.

Depois que o threshold é atingido, o detector emite um único `BruteForceFinding` para a sequência contínua. Uma nova sequência para a mesma chave começa somente após uma lacuna maior que a janela entre falhas. Essa política evita findings repetidos para janelas sobrepostas sem introduzir estado persistente. A organização de futuras regras continua não vinculante.
