# Analisador de Logs de Login

Analisador de autenticação para estudo e portfólio de Blue Team. O projeto converte registros Linux e Windows para um modelo comum e aplica regras determinísticas para destacar atividades que merecem investigação.

A versão declarada no pacote é `0.1.0`. O repositório está preparado como candidato a uma primeira versão pública, sem alegar prontidão para produção ou substituir um SIEM.

## Capacidades atuais

- parsing de autenticação por senha do OpenSSH em logs Linux tradicionais;
- normalização dos Windows Security Event IDs 4624 e 4625 a partir de JSON estruturado;
- detecção de força bruta, password spraying e login fora do horário;
- pipelines de análise de arquivo com erros recuperáveis estruturados;
- comandos de terminal para análise Linux e Windows;
- suporte a IPv4, IPv6 e timestamps com fuso horário explícito.

Os três detectores operam sobre `AuthenticationEvent`, sem depender da sintaxe original do Linux ou do Windows:

- **Força bruta:** falhas repetidas para o mesmo username exato, originadas do mesmo IP, dentro de uma janela configurável.
- **Password spraying:** falhas do mesmo IP contra vários usernames distintos dentro de uma janela configurável.
- **Login fora do horário:** autenticação bem-sucedida fora dos weekdays e do intervalo diário permitidos.

## Arquitetura

```text
arquivo Linux ----> parser OpenSSH ----\
                                      \
                                       > AuthenticationEvent -> detectores -> resultado
                                      /
arquivo Windows JSON -> conversão -> parser Windows
```

Os parsers traduzem formatos específicos, o evento normalizado fornece uma representação comum, os detectores contêm as regras de segurança e os analisadores de arquivo coordenam o fluxo. A CLI apenas recebe configuração, compõe esses componentes e apresenta o resultado.

Uma descrição mais detalhada está em [docs/architecture.md](docs/architecture.md).

## Requisitos

- Python 3.11 ou superior;
- Git, para desenvolvimento e controle de versão;
- Visual Studio Code com a extensão oficial Python, opcional.

O runtime usa somente a biblioteca padrão do Python. `pytest` é a única dependência de desenvolvimento.

## Instalação para desenvolvimento

No Windows PowerShell, entre na raiz clonada do projeto e prepare o ambiente isolado:

```powershell
Set-Location "C:\caminho\para\Analisador de Logs de Login"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest
python -m login_log_analyzer --help
```

O modo editável reflete alterações locais sem reinstalar o pacote e inclui as ferramentas de teste. Para instalar apenas a aplicação a partir deste diretório, sem dependências de desenvolvimento:

```powershell
python -m pip install .
```

O projeto não está publicado no PyPI; esse comando instala o código-fonte local.

## Uso da CLI

A mesma interface pode ser executada pelo módulo Python ou pelo console script instalado:

```powershell
python -m login_log_analyzer --help
python -m login_log_analyzer analyze-linux --help
python -m login_log_analyzer analyze-windows --help
login-log-analyzer --help
```

### Linux

Logs syslog tradicionais não registram ano nem timezone. Por isso ambos são obrigatórios e nunca são inferidos da máquina:

```powershell
python -m login_log_analyzer analyze-linux .\samples\linux_auth.log --year 2026 --timezone-offset=-03:00
```

O offset aceita o formato `+HH:MM` ou `-HH:MM`. Usar `--timezone-offset=-03:00` evita que o valor negativo seja interpretado como outra opção pelo shell ou pelo parser de argumentos.

### Windows

O comando Windows recebe um array JSON em UTF-8. Cada registro deve conter `event_id`, `timestamp`, `username` e, opcionalmente, `source_ip`:

```json
[
  {
    "event_id": 4625,
    "timestamp": "2026-08-18T10:15:00-03:00",
    "username": "DemoAdmin",
    "source_ip": "192.0.2.50"
  }
]
```

O timestamp ISO 8601 já precisa incluir seu offset, portanto o comando não recebe ano ou timezone adicionais:

```powershell
python -m login_log_analyzer analyze-windows .\samples\windows_auth.json
```

### Configuração dos detectores

Os dois comandos compartilham os seguintes defaults e opções:

| Regra | Default | Opções |
|---|---|---|
| Força bruta | 5 falhas em 5 minutos | `--brute-force-threshold`, `--brute-force-window-minutes` |
| Password spraying | 5 usernames em 10 minutos | `--password-spray-threshold`, `--password-spray-window-minutes` |
| Horário permitido | `mon,tue,wed,thu,fri`, `08:00`–`18:00` | `--allowed-weekdays`, `--allowed-start`, `--allowed-end` |

Weekdays usam `mon,tue,wed,thu,fri,sat,sun`; horários usam `HH:MM` em formato de 24 horas. O início do horário permitido é inclusivo e o fim é exclusivo. Consulte o `--help` do subcomando para a lista autoritativa de opções.

O relatório mostra contagens de entrada, eventos normalizados, entradas não suportadas, erros recuperáveis e achados. Depois do resumo, cada categoria com achados recebe uma seção detalhada. Linhas ou objetos malformados não são reproduzidos no terminal.

Os códigos de saída são:

- `0`: análise concluída, inclusive quando existem achados ou erros recuperáveis;
- `1`: falha operacional ou documento Windows inválido;
- `2`: argumento ou configuração inválida.

## Demonstração reproduzível

As amostras de ataque são sintéticas e foram construídas para acionar os três detectores usando os defaults da CLI:

```powershell
python -m login_log_analyzer analyze-linux .\samples\demo_linux_attack.log --year 2026 --timezone-offset=-03:00
python -m login_log_analyzer analyze-windows .\samples\demo_windows_attack.json
```

Em cada comando, o resumo esperado contém 10 eventos de autenticação e um achado em cada categoria:

```text
Eventos de autenticação: 10
Achados de força bruta: 1
Achados fora do horário: 1
Achados de password spraying: 1
```

## Testes

Execute a suíte completa no ambiente virtual:

```powershell
python -m pytest
```

Os testes cobrem modelos, parsers, regras, pipelines, CLI e as amostras de demonstração. Nenhum teste depende do relógio atual ou de caminhos permanentes da máquina.

## Estrutura do projeto

```text
.
|-- .vscode/                 Configuração compartilhada do VS Code
|-- docs/                    Documentação de arquitetura
|-- samples/                 Dados sintéticos básicos e de demonstração
|-- src/login_log_analyzer/  Domínio, parsers, detectores, pipelines e CLI
|-- tests/                   Testes automatizados
|-- pyproject.toml           Metadados, build, dependências e ferramentas
`-- README.md                Visão geral, instalação e uso
```

## Limitações

- o parser Linux cobre somente `Accepted password`, `Failed password` e `Failed password for invalid user` do OpenSSH;
- timestamps Linux tradicionais exigem ano e offset explícitos na CLI;
- a entrada Windows é um formato de intercâmbio JSON, não coleta nativa do Event Log;
- somente os Event IDs 4624 e 4625 são normalizados;
- arquivos EVTX e XML do Windows não são lidos;
- as regras são heurísticas configuráveis e não mantêm estado persistente de incidentes;
- não há baseline comportamental, machine learning, threat intelligence ou GeoIP;
- não há exportação de relatórios, banco de dados, integração com SIEM, GUI ou interface web.

## Segurança dos dados

Os arquivos em `samples/` são pequenos, sintéticos e usam identidades fictícias e redes reservadas para documentação. Logs de produção podem conter usernames, hostnames e endereços sensíveis; eles não devem ser adicionados ao repositório sem sanitização adequada. Credenciais e segredos nunca devem ser armazenados nas amostras.
