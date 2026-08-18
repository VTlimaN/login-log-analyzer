# Analisador de Logs de Login

Projeto educacional de cibersegurança defensiva voltado à análise de logs de autenticação. A proposta é transformar registros de login de Windows e Linux em eventos comparáveis e, em milestones futuros, identificar atividades que mereçam investigação por uma equipe Blue Team.

O problema abordado é a dificuldade de analisar, de forma consistente, registros de autenticação produzidos em formatos diferentes. O projeto planeja oferecer suporte a logs de Windows e Linux e detectar:

- tentativas de força bruta;
- logins fora dos horários esperados;
- comportamento de autenticação suspeito.

## Estado atual

O Milestone 8 adiciona uma interface de linha de comando para a análise de arquivos Linux. O projeto lê um log Linux em UTF-8, normaliza o subconjunto OpenSSH suportado, executa os três detectores e apresenta contagens, erros de parsing e findings. Ingestão e CLI para eventos Windows ainda não foram implementadas.

## Suporte atual

O parser Linux reconhece somente mensagens OpenSSH de senha claramente estruturadas:

- `Accepted password`;
- `Failed password`;
- `Failed password for invalid user`.

Outras mensagens SSH e entradas de serviços como sudo, cron ou PAM permanecem fora do suporte atual. O ano e o fuso horário, ausentes no timestamp syslog tradicional, devem ser informados explicitamente ao criar o parser.

O parser Windows reconhece dados estruturados previamente extraídos para:

- Event ID 4624, como autenticação bem-sucedida;
- Event ID 4625, como autenticação malsucedida.

O contrato de entrada usa um mapeamento com `event_id`, `timestamp`, `username` e `source_ip` opcional. O timestamp deve ser um `datetime` com fuso horário. Acesso nativo ao Windows Event Log, ingestão de XML e suporte aos demais eventos do Windows Security ainda não foram implementados.

## Detecção de força bruta

O `BruteForceDetector` correlaciona falhas pelo username exato e pelo mesmo endereço IP de origem. O número mínimo de falhas e a janela de tempo são configurados ao criar o detector. Eventos Linux e Windows podem participar da mesma correlação porque a regra consome somente `AuthenticationEvent`.

A janela inclui eventos exatamente no seu limite. Um finding é emitido quando o threshold é alcançado e eventos adicionais da mesma sequência contínua são suprimidos até existir uma lacuna maior que a janela. Autenticações bem-sucedidas não contam nem encerram a sequência, e eventos sem IP de origem são ignorados.

A regra de força bruta mantém usernames diferentes separados: ela procura repetição contra a mesma identidade.

## Detecção de password spraying

O `PasswordSprayDetector` correlaciona falhas pelo mesmo IP de origem e conta usernames distintos dentro de uma janela inclusiva. O threshold, com mínimo de duas identidades, e a duração da janela são configurados pela API. Repetições contra o mesmo username não aumentam a cardinalidade.

Password spraying difere de força bruta porque uma origem tenta várias identidades, enquanto força bruta exige repetição contra uma identidade específica. Os usernames são comparados exatamente como normalizados, e eventos Linux e Windows podem participar da mesma sequência.

Um finding é emitido ao atingir o threshold e eventos adicionais da sequência contínua são suprimidos até uma lacuna maior que a janela. Eventos de sucesso não contam nem encerram a sequência, e falhas sem IP de origem são ignoradas.

## Detecção de login fora de horário

O `OffHoursLoginDetector` avalia autenticações bem-sucedidas contra weekdays e horários configurados pela API. A convenção de weekdays segue o Python, de segunda-feira `0` a domingo `6`. O início da janela é incluído e o fim é excluído.

Janelas noturnas são suportadas. Em uma agenda `22:00 → 06:00`, horários a partir de 22:00 pertencem ao weekday atual e horários antes de 06:00 pertencem ao weekday anterior. O horário de parede e o weekday presentes no timezone de cada evento são preservados durante a avaliação.

A regra funciona igualmente para eventos Linux e Windows, inclusive quando não há IP de origem. Não existem agendas por usuário nem baseline comportamental.

## Análise de arquivo Linux

O `LinuxLogFileAnalyzer` recebe um `Path`, um `LinuxAuthenticationParser` já configurado e instâncias configuradas dos três detectores. O fluxo atual é:

```text
arquivo Linux -> parser SSH -> AuthenticationEvent -> detectores -> resultado estruturado
```

O arquivo é lido incrementalmente em UTF-8. Linhas não suportadas são contabilizadas e ignoradas. Mensagens suportadas malformadas geram erros estruturados com número da linha e mensagem, sem interromper o restante do arquivo. Falhas do filesystem e conteúdo inválido em UTF-8 continuam visíveis ao chamador.

A análise ainda reconhece somente o subconjunto OpenSSH documentado. Não existe coleta Windows, leitura de EVTX ou pipeline genérico de ingestão.

## Tecnologias

- **Python:** linguagem principal que será usada para implementar parsers, lógica de análise, detecções e a aplicação.
- **venv:** fornece um ambiente Python isolado para as dependências do projeto.
- **pytest:** executa testes automatizados de comportamento e ajuda a prevenir regressões.
- **Git:** mantém o histórico do código-fonte e permite acompanhar alterações.
- **Visual Studio Code:** ambiente de desenvolvimento principal, configurado para usar o interpretador local e o pytest.
- **pyproject.toml:** centraliza metadados, empacotamento, dependências de desenvolvimento e configuração do pytest.

## Pré-requisitos

- Python 3.11 ou superior;
- Git;
- Visual Studio Code com a extensão oficial Python, recomendado para desenvolvimento.

## Configuração local

No Windows PowerShell, a partir da raiz do projeto:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Para executar os testes:

```powershell
python -m pytest
```

## Uso da linha de comando

Com o ambiente virtual ativado, consulte a ajuda geral ou a ajuda do comando Linux:

```powershell
python -m login_log_analyzer --help
python -m login_log_analyzer analyze-linux --help
```

O caminho do arquivo é posicional. As opções `--year` e `--timezone-offset` são obrigatórias porque o timestamp syslog tradicional não contém esse contexto:

```powershell
python -m login_log_analyzer analyze-linux samples/linux_auth.log --year 2026 --timezone-offset=-03:00
```

Offsets usam `+HH:MM` ou `-HH:MM`. Horários usam `HH:MM`, e weekdays usam os nomes `mon,tue,wed,thu,fri,sat,sun`. As configurações padrão são:

- força bruta: 5 falhas em 5 minutos;
- password spraying: 5 usernames distintos em 10 minutos;
- agenda permitida: `mon,tue,wed,thu,fri`, das `08:00` até `18:00`, com fim exclusivo.

Esses valores podem ser alterados com `--brute-force-threshold`, `--brute-force-window-minutes`, `--password-spray-threshold`, `--password-spray-window-minutes`, `--allowed-weekdays`, `--allowed-start` e `--allowed-end`.

A saída apresenta contagens gerais, erros de parsing sem reproduzir a linha bruta e seções detalhadas para cada tipo de finding. O código de saída é `0` quando a análise termina, mesmo que existam findings. Argumentos ou configurações inválidas e falhas operacionais, como arquivo inexistente, retornam código diferente de zero com mensagem em stderr.

Após a instalação editável, o mesmo comando também fica disponível como `login-log-analyzer`. A CLI atual analisa somente arquivos Linux com o subconjunto OpenSSH suportado. A normalização Windows existe, mas ainda não há coleta, ingestão ou comando Windows. Também não existem GUI, exportação de relatórios ou integração com SIEM.

## Estrutura inicial

```text
.
|-- .vscode/                 Configuração compartilhada do VS Code
|-- docs/                    Documentação de arquitetura
|-- samples/                 Amostras sintéticas e orientações de segurança
|-- src/login_log_analyzer/  Modelo, parsers e detectores de autenticação
|-- tests/                   Testes automatizados
|-- pyproject.toml           Configuração central do projeto
`-- README.md                Visão geral e instruções de desenvolvimento
```

A direção arquitetural inicial está descrita em [docs/architecture.md](docs/architecture.md).
