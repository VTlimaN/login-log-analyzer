# Analisador de Logs de Login

Projeto educacional de cibersegurança defensiva voltado à análise de logs de autenticação. A proposta é transformar registros de login de Windows e Linux em eventos comparáveis e, em milestones futuros, identificar atividades que mereçam investigação por uma equipe Blue Team.

O problema abordado é a dificuldade de analisar, de forma consistente, registros de autenticação produzidos em formatos diferentes. O projeto planeja oferecer suporte a logs de Windows e Linux e detectar:

- tentativas de força bruta;
- logins fora dos horários esperados;
- comportamento de autenticação suspeito.

## Estado atual

O Milestone 2 implementa o primeiro parser específico de plataforma. Linhas de autenticação por senha do OpenSSH em logs Linux tradicionais agora podem ser convertidas no modelo normalizado e imutável. Regras de detecção, interface de linha de comando, leitura de arquivos e integrações ainda não foram implementadas.

## Suporte atual

O parser Linux reconhece somente mensagens OpenSSH de senha claramente estruturadas:

- `Accepted password`;
- `Failed password`;
- `Failed password for invalid user`.

Outras mensagens SSH e entradas de serviços como sudo, cron ou PAM permanecem fora do suporte atual. O ano e o fuso horário, ausentes no timestamp syslog tradicional, devem ser informados explicitamente ao criar o parser.

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

## Estrutura inicial

```text
.
|-- .vscode/                 Configuração compartilhada do VS Code
|-- docs/                    Documentação de arquitetura
|-- samples/                 Amostras sintéticas e orientações de segurança
|-- src/login_log_analyzer/  Modelo normalizado e parser Linux SSH
|-- tests/                   Testes automatizados
|-- pyproject.toml           Configuração central do projeto
`-- README.md                Visão geral e instruções de desenvolvimento
```

A direção arquitetural inicial está descrita em [docs/architecture.md](docs/architecture.md).
