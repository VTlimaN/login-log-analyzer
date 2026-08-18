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

