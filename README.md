# Analisador de Logs de Login

Analisador de autenticação para estudo e portfólio de Blue Team. O projeto converte registros Linux e Windows para um modelo comum e aplica regras determinísticas para destacar atividades que merecem investigação.

A versão declarada no pacote é `0.1.0`. O repositório está preparado como candidato a uma primeira versão pública, sem alegar prontidão para produção ou substituir um SIEM.

## Capacidades atuais

- parsing de autenticação por senha do OpenSSH em logs Linux tradicionais;
- normalização dos Windows Security Event IDs 4624 e 4625 a partir de JSON estruturado ou coleta nativa local;
- detecção de força bruta, password spraying, login fora do horário, login bem-sucedido após falhas repetidas e múltiplos IPs de origem contra uma conta;
- pipelines de análise de arquivo com erros recuperáveis estruturados;
- comandos de terminal para análise Linux, Windows JSON e Windows Security Event Log;
- exportação opcional de relatórios em JSON e CSV;
- suporte a IPv4, IPv6 e timestamps com fuso horário explícito.

Os cinco detectores operam sobre `AuthenticationEvent`, sem depender da sintaxe original do Linux ou do Windows:

- **Força bruta:** falhas repetidas para o mesmo username exato, originadas do mesmo IP, dentro de uma janela configurável.
- **Password spraying:** falhas do mesmo IP contra vários usernames distintos dentro de uma janela configurável.
- **Login fora do horário:** autenticação bem-sucedida fora dos weekdays e do intervalo diário permitidos.
- **Login bem-sucedido após falhas repetidas:** sucesso precedido por uma quantidade configurável de falhas para o mesmo username exato e IP dentro da janela configurada. É um indicador heurístico de possível adivinhação bem-sucedida de credenciais, não uma prova de comprometimento.
- **Múltiplos IPs de origem contra uma conta:** falhas contra o mesmo username exato a partir de vários IPs distintos dentro de uma janela configurável. É um indicador heurístico que pode refletir ataques distribuídos, rotação de proxies, bots ou infraestrutura compartilhada; não prova intenção maliciosa.

## Arquitetura

```text
arquivo Linux --------> parser OpenSSH --------\
arquivo Windows JSON -> conversão --------------> parser Windows -> AuthenticationEvent -> detectores -> resultado
Windows Security Log -> coletor XML wevtutil ---/
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
python -m login_log_analyzer analyze-windows-native --help
login-log-analyzer --help
```

### Linux

Logs syslog tradicionais não registram ano nem timezone. Por isso ambos são obrigatórios e nunca são inferidos da máquina:

```powershell
python -m login_log_analyzer analyze-linux .\samples\linux_auth.log --year 2026 --timezone-offset=-03:00
```

O offset aceita o formato `+HH:MM` ou `-HH:MM`. Usar `--timezone-offset=-03:00` evita que o valor negativo seja interpretado como outra opção pelo shell ou pelo parser de argumentos.

### Windows JSON

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

Esse caminho permanece útil para análise portátil ou offline de eventos previamente extraídos.

### Windows Security Event Log nativo

Em Windows, o comando nativo consulta diretamente o log `Security` local por meio do `wevtutil`. A consulta é somente leitura, solicita XML estruturado e limita os resultados aos Event IDs 4624 e 4625:

```powershell
python -m login_log_analyzer analyze-windows-native
python -m login_log_analyzer analyze-windows-native --max-events 250
```

O limite padrão é de 100 eventos e pode ser alterado com `--max-events`. A conta que executa o comando precisa possuir acesso de leitura ao Security log; uma falha de acesso é reportada sem tentativa de elevação de privilégios. O coletor não limpa, exporta nem modifica logs ou políticas de auditoria.

### Configuração dos detectores

Os três comandos compartilham os seguintes defaults e opções de detecção:

| Regra | Default | Opções |
|---|---|---|
| Força bruta | 5 falhas em 5 minutos | `--brute-force-threshold`, `--brute-force-window-minutes` |
| Password spraying | 5 usernames em 10 minutos | `--password-spray-threshold`, `--password-spray-window-minutes` |
| Horário permitido | `mon,tue,wed,thu,fri`, `08:00`–`18:00` | `--allowed-weekdays`, `--allowed-start`, `--allowed-end` |
| Sucesso após falhas | 5 falhas em 5 minutos | `--success-after-failures-threshold`, `--success-after-failures-window-minutes` |
| Múltiplos IPs contra uma conta | 5 IPs distintos em 10 minutos | `--multiple-source-ips-threshold`, `--multiple-source-ips-window-minutes` |

Weekdays usam `mon,tue,wed,thu,fri,sat,sun`; horários usam `HH:MM` em formato de 24 horas. O início do horário permitido é inclusivo e o fim é exclusivo. Consulte o `--help` do subcomando para a lista autoritativa de opções.

O relatório mostra contagens de entrada, eventos normalizados, entradas não suportadas, erros recuperáveis e achados. Depois do resumo, cada categoria com achados recebe uma seção detalhada. Linhas ou objetos malformados não são reproduzidos no terminal.

Os códigos de saída são:

- `0`: análise concluída, inclusive quando existem achados ou erros recuperáveis;
- `1`: falha operacional, documento Windows inválido ou falha ao gravar relatório;
- `2`: argumento ou configuração inválida.

### Exportação de relatórios

Todos os comandos de análise aceitam `--output-json PATH` e `--output-csv PATH`. Os formatos podem ser solicitados separadamente ou na mesma execução:

```powershell
python -m login_log_analyzer analyze-linux .\samples\demo_linux_attack.log --year 2026 --timezone-offset=-03:00 --output-json .\linux-report.json --output-csv .\linux-findings.csv
python -m login_log_analyzer analyze-windows .\samples\demo_windows_attack.json --output-json .\windows-report.json --output-csv .\windows-findings.csv
```

O JSON é o relatório estruturado completo: inclui resumo, erros recuperáveis e todas as categorias de achados. O CSV é uma tabela plana com uma linha por achado, destinada à inspeção em planilhas e ferramentas de dados; contagens e erros de ingestão não fazem parte dele. Um CSV sem achados contém somente o cabeçalho.

Por segurança, um destino existente é rejeitado. `--overwrite` permite sua substituição explícita. Os destinos JSON e CSV devem ser diferentes e seus diretórios-pai precisam existir.

O contrato inicial usa `report_version` igual a `1`. Os identificadores de origem são `linux_file`, `windows_json` e `windows_native`; os tipos de achado são `brute_force`, `off_hours`, `password_spray`, `successful_login_after_failures` e `multiple_source_ips`. Timestamps permanecem em ISO 8601 com seus offsets, IPs são strings e uma origem ausente é representada como `null` no JSON ou campo vazio no CSV. O finding de sucesso após falhas usa `first_failure`, `last_failure` e `successful_login`; o de múltiplas origens usa `distinct_source_ip_count` e `source_ips`. A lista de IPs no CSV é separada por `;`, e campos não aplicáveis permanecem vazios.

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
- a coleta nativa funciona somente no Windows e depende do acesso da conta ao Security log local;
- o formato JSON continua sendo necessário para análise Windows portátil ou offline;
- somente os Event IDs 4624 e 4625 são normalizados;
- arquivos EVTX não são lidos e não existe coleta de computadores remotos;
- as regras são heurísticas configuráveis e não mantêm estado persistente de incidentes;
- não há baseline comportamental, machine learning, threat intelligence ou GeoIP;
- a exportação se limita a JSON estruturado e CSV de achados; não há banco de dados, integração com SIEM, GUI ou interface web.

## Segurança dos dados

Os arquivos em `samples/` são pequenos, sintéticos e usam identidades fictícias e redes reservadas para documentação. Logs de produção podem conter usernames, hostnames e endereços sensíveis; eles não devem ser adicionados ao repositório sem sanitização adequada. Credenciais e segredos nunca devem ser armazenados nas amostras.
