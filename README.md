# pgp-python-kurose
Implementação de um sistema de mensagens seguras utilizando o protocolo PGP (criptografia híbrida) em Python, baseado no caso de uso 'Protegendo o E-mail' do livro-texto de James Kurose para a disciplina de Segurança da Informação.

# PGP em Python - Caso de Uso Kurose

Este projeto foi desenvolvido como parte da atividade avaliativa de Segurança da Informação. O objetivo é implementar um fluxo completo de proteção de mensagens baseado no protocolo PGP (Pretty Good Privacy), conforme descrito no livro-texto de James Kurose.

## 🚀 Funcionalidades
- **Geração de Chaves:** Criação de chaves RSA (Pública/Privada) para os usuários.
- **Envelope Digital:** Criptografia híbrida usando AES para a mensagem e RSA para a chave de sessão.
- **Assinatura Digital:** Garantia de integridade e autenticidade via hashing e assinatura RSA.

## 🛠️ Tecnologias Utilizadas
- **Linguagem:** Python 3.x
- **Biblioteca:** `cryptography`

## 👥 Divisão do Grupo
| Integrante | Responsabilidade |
| :--- | :--- |
| **André Marques de Santana** | Configuração do ambiente e implementação das chaves RSA |
| **Maravania de Paula Souza** | Lógica de criptografia simétrica e "Envelope Digital" |
| **PIETRA CARACCO RUIZ** | Implementação da assinatura digital e scripts de testes |

## 📋 Como executar
1. Instale a biblioteca necessária:
   ```bash
   pip install cryptography
