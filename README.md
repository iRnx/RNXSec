# RNXSec

**Modular security testing framework for authorized labs, application security research, and security education.**

RNXSec é uma ferramenta modular de segurança desenvolvida em Python para estudo prático, automação e validação de técnicas em ambientes próprios ou expressamente autorizados.

O projeto está em **desenvolvimento ativo** e cresce de forma incremental: cada módulo é implementado, testado em laboratórios controlados, documentado e integrado à ferramenta somente quando está funcional.

---

## 🎯 Objetivo

O RNXSec foi criado para reunir, em uma única ferramenta, diferentes áreas de estudo em Segurança da Informação e Application Security.

A ideia é trabalhar sempre no ciclo:

```text
entender a vulnerabilidade
        ↓
testar manualmente
        ↓
automatizar partes do processo
        ↓
analisar o comportamento
        ↓
corrigir o alvo
        ↓
retestar
```

O foco do projeto não é apenas executar testes, mas compreender o que está acontecendo em cada etapa.

---

## 🚧 Status do projeto

O RNXSec ainda está em desenvolvimento.

### Password / Hash

| Módulo | Status |
| --- | --- |
| bcrypt | ✅ Funcional |
| PBKDF2 | ✅ Funcional |
| Argon2 | 🚧 Estrutura preparada |
| scrypt | 🚧 Estrutura preparada |
| MD5 | 🚧 Estrutura preparada |
| SHA-1 | 🚧 Estrutura preparada |
| SHA-256 | 🚧 Estrutura preparada |

### Web Security

| Módulo | Status |
| --- | --- |
| SQL Injection | 🚧 Estrutura inicial |
| XSS | 🚧 Estrutura inicial |

Novos módulos serão adicionados gradualmente conforme forem implementados e testados.

---

## 🧩 Arquitetura

A estrutura do projeto é organizada por responsabilidade.

```text
RNXSec/
├── config/
├── core/
├── modules/
│   ├── passwords/
│   │   ├── argon2/
│   │   ├── bcrypt/
│   │   ├── md5/
│   │   ├── pbkdf2/
│   │   ├── scrypt/
│   │   ├── sha1/
│   │   └── sha256/
│   │
│   ├── sqli/
│   └── xss/
│
├── resources/
│   └── wordlists/
│
├── scripts/
├── shared/
│   └── wordlists/
│
├── main.py
└── .gitignore
```

### `config/`

Configurações e caminhos centrais do projeto.

### `core/`

Componentes realmente globais, como exceções compartilhadas.

### `modules/`

Módulos de segurança organizados por domínio.

Cada algoritmo ou área possui sua própria implementação, configuração, serviço, runner e validação quando aplicável.

### `shared/`

Infraestrutura reutilizável por diferentes módulos.

Atualmente contém a camada compartilhada de wordlists.

### `resources/`

Dados utilizados pela ferramenta.

Os grandes datasets externos de wordlists **não são versionados neste repositório**.

### `scripts/`

Scripts auxiliares utilizados durante o desenvolvimento e manutenção do projeto.

---

## 🔐 Password / Hash

O RNXSec possui uma arquitetura comum para algoritmos de senha e hash.

Atualmente, os algoritmos registrados e disponíveis na ferramenta são:

- bcrypt
- PBKDF2

A arquitetura permite que novos algoritmos sejam adicionados sem duplicar a lógica genérica de cracking.

Entre os componentes compartilhados estão:

```text
PasswordAlgorithm
PasswordAlgorithmRegistry
PasswordCracker
PasswordHashTarget
CrackResult
CrackProgress
```

O hash é preparado uma única vez antes do processamento da wordlist, evitando trabalho repetitivo a cada candidato.

---

## 🔑 bcrypt

O módulo bcrypt permite:

- gerar hashes;
- verificar uma senha específica;
- testar hashes contra wordlists;
- gerar um hash e testá-lo contra wordlists;
- acompanhar tentativas, tempo e velocidade durante a execução.

O módulo também trata hashes bcrypt em formato válido e mantém compatibilidade com hashes de laboratório que precisem de normalização.

---

## 🔑 PBKDF2

O módulo PBKDF2 segue a mesma arquitetura compartilhada do bcrypt.

Ele permite:

- gerar hashes PBKDF2;
- verificar candidatos;
- testar hashes com wordlists;
- interpretar os parâmetros do hash;
- exibir informações como algoritmo, digest e número de iterações.

---

## 📚 Wordlists

O RNXSec possui uma camada própria para registrar e consumir diferentes fontes de wordlists.

As fontes atualmente reconhecidas pela infraestrutura incluem:

- RockYou
- SecLists
- Cybbaris Wordlists
- outras coleções locais compatíveis

Esses datasets **não são armazenados neste repositório**.

A ferramenta espera que eles estejam disponíveis localmente dentro de:

```text
resources/wordlists/
```

Exemplo:

```text
resources/
└── wordlists/
    ├── rockyou/
    ├── SecLists/
    ├── cybbaris_wordlists/
    └── wordlists/
```

A leitura é feita em streaming, sem carregar o arquivo inteiro na memória.

No futuro, o RNXSec poderá incluir pequenas wordlists próprias em:

```text
resources/wordlists/builtin/
```

---

## ▶️ Execução

Com o ambiente Python preparado e as dependências instaladas, a aplicação é iniciada com:

```bash
python main.py
```

O menu atual expõe:

```text
RNXSec
└── Password / Hash
    ├── bcrypt
    └── PBKDF2
```

A estrutura de SQL Injection e XSS já existe no projeto, mas esses módulos ainda estão em desenvolvimento e não são expostos no menu principal.

---

## 🧪 Laboratórios relacionados

O desenvolvimento do RNXSec é acompanhado por laboratórios próprios, deliberadamente vulneráveis.

Esses laboratórios ficam separados da ferramenta.

### Hub

https://github.com/iRnx/Cyber-Security-Hub

### SQL Injection Lab 01

https://github.com/iRnx/vulnlab-sqli-01

Esse laboratório possui uma versão vulnerável utilizada para estudo prático:

```text
branch: vulnerable
```

A versão corrigida será mantida separadamente quando a fase de remediação for concluída:

```text
branch: fixed
```

---

## 🧠 Metodologia de desenvolvimento

O projeto segue uma abordagem incremental:

1. estudar o conceito;
2. criar ou utilizar um laboratório controlado;
3. testar manualmente;
4. entender o comportamento técnico;
5. implementar a automação no RNXSec;
6. validar a ferramenta contra o laboratório;
7. corrigir o laboratório;
8. executar os mesmos testes novamente;
9. documentar o aprendizado.

Essa abordagem permite estudar tanto a perspectiva ofensiva quanto a defensiva em um ambiente autorizado.

---

## 🗺️ Roadmap

Entre os próximos objetivos do projeto estão:

- ampliar os algoritmos de Password / Hash;
- melhorar o gerenciamento de wordlists;
- adicionar detecção e roteamento de formatos de hash;
- evoluir o módulo de SQL Injection;
- evoluir o módulo de XSS;
- adicionar uma camada HTTP compartilhada para testes web;
- adicionar novos módulos de Application Security;
- melhorar relatórios e resultados;
- criar testes automatizados;
- preparar uma experiência de instalação mais simples;
- futuramente disponibilizar uma interface web.

O roadmap pode mudar conforme o projeto evolui.

---

## 🔬 Escopo

O RNXSec foi criado para:

- aprendizado;
- pesquisa;
- desenvolvimento;
- treinamento de segurança;
- laboratórios próprios;
- CTFs e ambientes educacionais;
- sistemas onde exista autorização explícita para testes.

---

## ⚠️ Uso responsável

Use o RNXSec somente em sistemas que você possui ou para os quais tenha autorização explícita de teste.

Os exemplos, módulos e laboratórios associados ao projeto foram criados para estudo em ambientes controlados.

O autor não incentiva o uso da ferramenta contra sistemas de terceiros sem autorização.

---

## 📌 Projeto

**RNXSec**

Modular security testing framework for authorized labs, application security research, and security education.

Desenvolvido e mantido como projeto de estudo e evolução contínua em Segurança da Informação.
