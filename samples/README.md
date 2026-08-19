# Dados de exemplo

Todos os arquivos deste diretório são sintéticos e existem somente para estudo, testes manuais e demonstração do projeto.

| Arquivo | Formato | Categoria e resultado esperado |
|---|---|---|
| `linux_auth.log` | OpenSSH/syslog | Exemplo básico com mensagens suportadas e uma linha não suportada. |
| `windows_auth.json` | Windows JSON | Exemplo básico de autenticação com um Event ID não suportado. |
| `windows_account_lockout.json` | Windows JSON | Uma observação direta de bloqueio de conta 4740. |
| `windows_account_lifecycle.json` | Windows JSON | Cinco observações diretas: criação, habilitação, desabilitação, exclusão e desbloqueio. |
| `windows_brute_force_lockout.json` | Windows JSON | Um finding heurístico de força bruta, uma observação de bloqueio e um finding correlacionado. |
| `demo_linux_attack.log` | OpenSSH/syslog | Findings heurísticos de força bruta, password spraying e login fora do horário com os defaults. |
| `demo_windows_attack.json` | Windows JSON | Os mesmos três findings heurísticos pelo pipeline Windows JSON. |

As amostras usam identidades fictícias e blocos de endereços IP reservados para documentação. Dados adicionados ao repositório nunca devem conter credenciais reais, usernames ou hostnames confidenciais, informações privadas da organização nem logs de produção com conteúdo sensível.
