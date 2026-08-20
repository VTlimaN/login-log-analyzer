# Segurança

## Modelo de ameaça

Arquivos de log Linux, documentos JSON Windows e campos retornados pelo Windows Event Log são considerados não confiáveis. O analisador nunca executa conteúdo dos logs. O processamento e a geração de relatórios são locais e não transmitem dados para serviços externos.

## Fronteiras de saída

Os modelos normalizados preservam exatamente usernames e outros identificadores relevantes à análise. Na saída do terminal, caracteres de controle C0, DEL e controles Unicode são convertidos em escapes visíveis como `\x1b`, impedindo sequências ANSI, novas linhas e alterações de título injetadas por dados de origem.

No CSV, valores textuais não confiáveis que começam, após espaços ASCII, com `=`, `+`, `-` ou `@`, além de valores iniciados por tab, CR ou LF, recebem um apóstrofo. Caracteres de controle também são representados por escapes visíveis. O JSON preserva os valores semânticos originais.

## Limites de recursos

- JSON Windows: 50 MiB e 100.000 registros por arquivo;
- log Linux: 100 MiB, 1.000.000 de linhas, 100.000 eventos de autenticação, 100.000 erros recuperáveis e 65.536 caracteres por linha;
- coleta nativa Windows: de 1 a 10.000 eventos e no máximo 52.428.800 caracteres de XML processado;
- diagnóstico de erro do coletor nativo: no máximo 1.024 caracteres antes da indicação de truncamento.

Esses limites reduzem o risco de exaustão de memória e CPU em uma ferramenta local. Entradas que excedem os limites falham de forma controlada.

## Coleta nativa Windows

O coletor chama o `wevtutil.exe` do diretório fixo do sistema com argumentos separados, `shell=False` e uma consulta XPath somente de leitura. Ele não eleva privilégios, não altera políticas de auditoria e não modifica nem limpa logs. Acesso negado é reportado como falha operacional sem traceback.

## Relatórios e dados operacionais

JSON e CSV podem conter usernames, endereços IP, domínios, hostnames e timestamps. Relatórios de produção devem ser armazenados com permissões adequadas e fora de repositórios públicos. O diretório `.analysis-output/` é ignorado pelo Git apenas como defesa em profundidade contra inclusão acidental; não substitui controles de acesso, revisão antes de commits ou políticas de retenção.
