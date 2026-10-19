# Transporte sintético entre jobs

Este scaffold demonstra, em memória e por artefato cifrado, a passagem de uma
prova sintética entre jobs GitHub Actions isolados. **Não publica pacotes e não
acessa R2 nem credenciais reais.** O resultado não comprova validade de
credenciais S3. `.github/workflows/t02-transport.yml` executa a prova em jobs
GitHub Actions separados; o resultado remoto ainda precisa ser registrado e
avaliado, não é inferido dos testes locais.

## Interface para os jobs

Requisitos: Python 3 e GnuPG em `/usr/bin/gpg`. Os jobs fornecem o contexto
GitHub (`GITHUB_REPOSITORY`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`,
`GITHUB_SHA`, `GITHUB_REF`) e executam no repositório `luminusOS/flatpak-repo`,
em `refs/heads/main`. `--channel` aceita somente `stable` ou `testing`.

No ambiente protegido **issuer** do canal, disponibilize:

- `T02_PARENT_CANARY`: canário sintético aleatório de 64 caracteres hexadecimais,
  exclusivo por canal;
- `T02_TRANSPORT_KEY`: chave de transporte sintética aleatória de 64 caracteres
  hexadecimais, exclusiva por canal.

```sh
python3 tools/credential_transport.py issue --channel stable \
  --output "$RUNNER_TEMP/t02-stable.gpg"
```

Passe somente esse arquivo cifrado ao job **publisher** do mesmo canal. Nesse
ambiente, defina `T02_TRANSPORT_KEY` com a mesma chave do issuer e deixe
`T02_PARENT_CANARY` totalmente ausente (inclusive se estiver definida como
string vazia, o consumo falha):

```sh
python3 tools/credential_transport.py consume --channel stable \
  --input "$RUNNER_TEMP/t02-stable.gpg"
```

O publisher também precisa receber o mesmo contexto GitHub. O resumo JSON em
stdout contém apenas estágio, canal, indicadores e tamanho do ciphertext; falhas
retornam código diferente de zero com mensagem genérica. Nenhum segredo ou valor
derivado é impresso. Crie o caminho de saída uma única vez: arquivos existentes
e links simbólicos são recusados. O artefato em disco contém exclusivamente o
ciphertext e é criado com modo `0600`.

## Formato e limites

O envelope fechado (versão 1) liga a prova a repositório, execução, tentativa,
commit, ref e canal. Ele contém um nonce, compromisso SHA-256 do canário pai e
um valor sintético derivado por HMAC-SHA-256; o canário pai bruto nunca entra no
envelope. O envelope expira em 300 segundos e admite no máximo 30 segundos de
adiantamento do relógio. A comparação de bindings bloqueia reutilização entre
execuções, tentativas, commits, refs e canais.

GnuPG cifra com AES-256 simétrico e passphrase entregue por pipe de descritor de
arquivo, nunca como argumento. O plaintext é processado em memória. Um diretório
temporário `GNUPGHOME` com permissões restritas é removido ao terminar; não há
arquivo de credencial nem cache de chave simétrica. Entrada ciphertext tem limite
de 64 KiB, saída plaintext de 8 KiB e operações GnuPG timeout de 15 segundos.
Erros do GnuPG são suprimidos. A integridade autenticada fornecida pelo formato
OpenPGP é verificada pelo GnuPG durante a descriptografia.

## Verificação local

```sh
/usr/bin/python3 -B -m unittest discover -s tests -v
```

Os testes usam canários e chaves dummy sintéticos e GnuPG local; não usam rede,
Actions, R2 ou secrets de CI. A confirmação de transporte entre jobs reais exige
execução posterior do workflow protegido com secrets sintéticos aleatórios e
artefato limitado ao canal. **Não** substitua os canários por credenciais de
produção nem interprete esta prova como teste de acesso a R2.

## Proteções do workflow

Somente `workflow_dispatch` dispara a prova. Emissão e consumo exigem `main`
protegida e usam o mesmo commit. Os quatro ambientes `t02-{issuer,publisher}-
{stable,testing}` aceitam deploy somente de `main`. A emissão estável exige
aprovação humana; testes são automáticos. As cadeias dos dois canais são
independentes para que a espera de aprovação não expire o envelope de testes.

O publisher verifica que o contexto de secrets do GitHub não disponibiliza o
canário pai, antes de executar o consumidor sem essa variável. Os jobs têm apenas
`contents: read`; checkout não persiste credenciais. O artefato contém um único
capsule cifrado, com retenção de um dia como fallback. Depois da inspeção, o
operador remove os artefatos e secrets sintéticos da prova. Não enviar secrets,
canários ou plaintext em outputs de jobs, logs ou artefatos.

A branch de controle negativo tenta acessar um ambiente de emissor e deve ser
bloqueada pela política de deploy antes de chegar a um runner. Não relaxar as
proteções para fazer esse run passar: sua falha é o resultado esperado.

Actions oficiais fixadas por SHA: checkout v4
`11d5960a326750d5838078e36cf38b85af677262`, upload-artifact v4
`ea165f8d65b6e75b540449e92b4886f43607fa02` e download-artifact v4
`d3f86a106a0bac45b974a628896c90dbdf5c8093`.

Referências do GnuPG: [manual](https://www.gnupg.org/documentation/manuals/gnupg/),
[opções de cifragem](https://www.gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html).
