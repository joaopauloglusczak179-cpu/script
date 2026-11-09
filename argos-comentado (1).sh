#!/usr/bin/env bash
# =============================================================================
# ARGOS - varredura de arquivos suspeitos numa conta cPanel
#
# Versão comentada do one-liner. A lógica é idêntica; só foi quebrada em linhas.
# Uso: entre em qualquer pasta da conta (ex.: cd /home2/usuario/public_html) e rode.
#
# Saída em 3 seções:
#   1. Arquivos encontrados pelo NOME (lista arquivos.txt baixada da URL)
#   2. Arquivos encontrados pelo HASH (lista hashes.txt baixada da URL)
#   3. Outros arquivos (verificações fixas do ARGOS original)
# Depois, o LISTDIRE mostra a raiz de cada domínio para análise visual.
# =============================================================================


# -----------------------------------------------------------------------------
# PREPARAÇÃO: descobre o usuário e a home a partir da pasta atual
# -----------------------------------------------------------------------------

# Pega o 3º campo do caminho atual: /home2/USUARIO/public_html -> USUARIO
USR=$(pwd | awk -F '/' '{print $3}')

# Expande ~USUARIO para o caminho real da home (ex.: /home2/usuario)
HOMEDIR=$(eval echo "~$USR")

# Se a conta não tem shell (noshell), ativa o jailshell temporariamente,
# porque o "su $USR -c ..." usado mais abaixo precisa de um shell.
# A variável jsenabled marca que foi ativado aqui, para poder desativar depois.
if grep $USR /etc/passwd | grep -q noshell ; then
    cppc --jailshell $USR
    jsenabled="ENABLED"
fi


# =============================================================================
# FUNÇÃO PRINCIPAL
# =============================================================================
ARGOS(){
    clear
    perms                 # corrige permissões da conta (ferramenta interna)
    cd $HOMEDIR

    # -------------------------------------------------------------------------
    # 1. BAIXAR AS LISTAS EXTERNAS
    # -------------------------------------------------------------------------

    # Endereço base. O script acrescenta "/arquivos.txt" e "/hashes.txt".
    BASEURL="http://malware.joaogluszczak.com.br"

    # Pasta temporária em /tmp com nome aleatório (ex.: /tmp/tmp.Ab12Cd34).
    # Tudo que o script baixa ou gera fica aqui, nunca na pasta do cliente.
    SIG=$(mktemp -d)

    # Se o usuário apertar Ctrl+C, apaga a pasta temporária antes de sair.
    trap 'rm -rf "$SIG"' INT TERM

    # O laço roda 2 vezes: L=arquivos e depois L=hashes.
    for L in arquivos hashes ; do
        # curl -f : falha em erro HTTP (404/500) em vez de salvar a página de erro
        #      -sS: silencioso, mas mostra erros
        #      --max-time 20: desiste após 20 segundos
        if curl -fsS --max-time 20 -o "$SIG/$L.raw" "$BASEURL/$L.txt" ; then
            # Limpa a lista baixada:
            #   s/\r$//                 remove o \r de arquivos editados no Windows
            #   s/^[[:space:]]*//       remove espaços no início da linha
            #   s/[[:space:]]*$//       remove espaços no fim da linha
            #   /^#/d                   apaga comentários
            #   /^$/d                   apaga linhas vazias (uma linha vazia casaria com tudo)
            sed 's/\r$//; s/^[[:space:]]*//; s/[[:space:]]*$//; /^#/d; /^$/d' \
                "$SIG/$L.raw" > "$SIG/$L.txt"
        else
            # Download falhou: cria a lista vazia (a verificação não acha nada)
            # e avisa em vermelho na tela.
            : > "$SIG/$L.txt"
            echo -e "\033[1;31m[AVISO] Falha ao baixar $BASEURL/$L.txt - essa verificação foi pulada\033[0m"
        fi
    done

    # Do hashes.txt, aproveita só a 1ª coluna (o hash) e só se for um sha256
    # válido (64 caracteres hexadecimais). Descrições após o hash são ignoradas.
    awk '{print $1}' "$SIG/hashes.txt" | grep -iE '^[0-9a-f]{64}$' > "$SIG/hashes.lst"

    # -------------------------------------------------------------------------
    # 2. LISTAR TODOS OS ARQUIVOS E PASTAS DA CONTA (uma única vez)
    # -------------------------------------------------------------------------
    # -prune pula as pastas virtfs (montagens do sistema), .security e remocao
    # (onde ficam arquivos já movidos), para não reportar o que já foi tratado.
    find "$HOMEDIR" \( -path "$HOMEDIR/virtfs" -o -path "$HOMEDIR/.security" -o -path "$HOMEDIR/remocao" \) \
        -prune -o -print > "$SIG/todos"

    # -------------------------------------------------------------------------
    # 3. SEÇÃO "BASE DE DADOS": compara o NOME de cada item com o arquivos.txt
    # -------------------------------------------------------------------------
    # 1º arquivo lido (NR==FNR): guarda cada nome da lista, em minúsculas.
    # 2º arquivo: para cada caminho, extrai só o nome final (remove tudo até a
    # última "/") e imprime o caminho se o nome estiver na lista.
    # tolower() faz a comparação ignorar maiúsculas/minúsculas.
    awk 'NR==FNR { n[tolower($0)]; next }
         { b=$0; sub(/\/+$/,"",b); sub(/.*\//,"",b); if (tolower(b) in n) print }' \
        "$SIG/arquivos.txt" "$SIG/todos" > "$SIG/r_base"

    # -------------------------------------------------------------------------
    # 4. SEÇÃO "HASHES": calcula o sha256 dos arquivos e compara com a lista
    # -------------------------------------------------------------------------
    : > "$SIG/r_hash"                                   # começa vazio
    # [ -s ... ] só executa se houver pelo menos um hash na lista.
    # Calcula o hash só de extensões onde malware costuma estar (bem mais rápido
    # do que calcular de imagens, backups e e-mails).
    # tr '\n' '\0' + xargs -0 : passa os caminhos com segurança, mesmo com espaços.
    # A saída do sha256sum é "HASH  CAMINHO"; substr($0,67) recorta só o caminho
    # (64 caracteres do hash + 2 espaços = começa na posição 67).
    [ -s "$SIG/hashes.lst" ] && \
        grep -iE '\.(php[0-9]?|phtml|phar|pht|inc|ico|mo|js|zip|txt)$' "$SIG/todos" \
        | tr '\n' '\0' \
        | xargs -0 -r sha256sum 2>/dev/null \
        | awk 'NR==FNR { h[tolower($1)]; next }
               (tolower($1) in h) { print substr($0,67) }' "$SIG/hashes.lst" - \
        > "$SIG/r_hash"

    # Junta o que já foi encontrado nas seções 1 e 2, para não repetir na seção 3.
    cat "$SIG/r_base" "$SIG/r_hash" > "$SIG/r_ja"

    # -------------------------------------------------------------------------
    # 5. DESCOBRIR AS INSTALAÇÕES WORDPRESS DA CONTA
    # -------------------------------------------------------------------------
    # vdetect lista os CMS instalados; o filtro pega só os WordPress na /home
    # e extrai o caminho (último campo após "::"). Os caminhos vão para o array
    # WORDPRESS separados por \0, o que funciona mesmo com espaços no nome.
    WORDPRESS=()
    while IFS= read -r -d '' dir; do
        WORDPRESS+=("$dir")
    done < <(vdetect 2>/dev/null | grep home | grep Wordpress \
             | awk -F'::' '{print $NF}' | sed 's/^ //g' | tr '\n' '\0')

    # A partir daqui, o shell separa palavras só por quebra de linha
    # (e não por espaço), para não quebrar caminhos com espaço nos laços.
    IFS=$'\n'

    # -------------------------------------------------------------------------
    # 6. SEÇÃO "OUTROS ARQUIVOS": verificações fixas do ARGOS original
    # -------------------------------------------------------------------------
    # Tudo dentro de { ... } é coletado e filtrado no final (passo 7).
    {
        # ===== 6a. Verificações em cada WordPress =====
        for dir in "${WORDPRESS[@]}" ; do
            dir=$(echo $dir | sed 's/[[:space:]]*$//g')    # remove espaço no fim
            cd "$dir"

            # PHP na raiz com nome de 8 a 10 caracteres alfanuméricos
            # (padrão de webshells com nome aleatório, ex.: xz7l6w5h.php)
            find $PWD -maxdepth 1 -iname "*.php" | grep -E "/[0-9a-zA-Z]{8,10}.php"

            # Nomes suspeitos SÓ NA RAIZ do WordPress (-maxdepth 1).
            # Ficam aqui, e não no arquivos.txt, porque vários existem
            # legitimamente dentro de wp-admin/ ou de plugins.
            find $PWD -maxdepth 1 -type f \( -iname "admin.php" -o -iname "about.php" -o -iname "text.php" \
                -o -iname "credits.php" -o -iname "inputs" -o -iname "input.php" -o -iname "xxx.php" \
                -o -iname "network.php" -o -iname "output.php" -o -iname "module.php" -o -iname "style.php" \
                -o -iname "top.php" -o -iname "shop.php" -o -iname "shops.php" -o -iname "options.php" \
                -o -iname "123.php" -o -iname "good.php" -o -iname "index2.php" -o -iname "admin-ajax.php" \)

            # Arquivos que contêm "_0x9e23" (JavaScript ofuscado injetado)
            # -F texto literal, -l só o nome do arquivo, -r recursivo, -i sem caixa
            grep -Flri "_0x9e23" $PWD

            # Arquivos EXTRAS dentro de plugins: o wp-cli compara os plugins com
            # os originais do wordpress.org e lista os "File was added".
            # Roda como o dono da conta (su), com limite de 10 segundos.
            # A saída "plugin arquivo File was added" vira "plugin/arquivo".
            # Arquivos .css são ignorados (muitos plugins geram CSS legítimo).
            for PLG in $(su $USR -c "timeout 10 wp plugin verify-checksums --all --fpath=$dir 2>/dev/null" \
                         | grep added | grep -Ev ".css" | sed 's/File was added//g' \
                         | awk '$1=$1"/"' | sed 's/\/[[:space:]]/\//'g); do
                FILE="$PWD/wp-content/plugins/$PLG"
                echo $FILE
            done

            # Se existe a pasta uploads...
            if [ -s "$dir/wp-content/uploads" ] ; then
                # Qualquer PHP dentro de uploads (lá só deveria haver mídia)
                cd "wp-content/uploads"
                find $PWD -iname "*.php"

                # Em wp-content (até 2 níveis): pastas de plugins falsos conhecidos,
                # e qualquer .txt ou .php solto. Ignora traduções (l10n) e o Hello Dolly.
                cd "$dir/wp-content"
                find $PWD -maxdepth 2 \( -iname "wpress-security-wordpress" -o -iname "WordPressCore" \
                    -o -iname "form-builder-pro" -o -iname "*.txt" -o -iname "*.php" \) \
                    | grep -Ev "l10n|hello.php"

                # Arquivos com links de scripts maliciosos conhecidos
                grep -lriE "cdn.scriptsplatform.com/scripts/|l-in.link/|bagelseven.com/" $PWD
            fi

            # Em languages: PHP e .htaccess não deveriam existir
            # (exceto as traduções .l10n.php do WordPress 6.5+)
            if [ -s "$dir/wp-content/languages" ] ; then
                cd "$dir/wp-content/languages"
                find $PWD -type f \( -iname "*.php" -o -iname ".htaccess" \) | grep -v "l10n.ph"
            fi
        done

        # ===== 6b. Verificações na conta inteira =====
        cd $HOMEDIR

        # Arquivos com assinaturas de malware conhecidas no conteúdo
        # (ignora as pastas de arquivos já movidos)
        grep -Elri "Matigan1337|compresssavvydetected|cloudswiftcdn|Leafmail3" $PWD \
            | grep -Ev "$HOMEDIR/.security|$HOMEDIR/remocao"

        # Pastas "wp-optional-*" (usadas por um malware conhecido)
        find $PWD -iname "wp-optional-*" -type d

        # Pastas "config" seguidas de 3 maiúsculas (ex.: configABC), padrão de malware
        find $PWD -type d -iname "config*" | grep -E "config[A-Z]{3}"

        # Arquivos com permissão de execução (binários, scripts plantados)
        find $PWD/ -type f -executable -not -path '*/virtfs/*'

        # encfind (ferramenta interna) procura código ofuscado/codificado;
        # aqui pega só o caminho das linhas "Matches found in file:"
        encfind | grep "Matches found in file:" | awk '{print $NF}'

        # PASTAS com nome terminando em .php (truque para enganar listagens)
        find $PWD -type d -iname "*.php"

        # PHP em pastas de sistema da conta, onde nunca deveria haver PHP
        find $PWD/mail $PWD/ssl $PWD/etc $PWD/.cpanel -iname "*.php"

        # Arquivos ocultos com nome aleatório de 8 caracteres e extensão disfarçada
        # (ex.: .Ab3dE9xZ.ico, .k2j4h6g8.mo), além de extensão dupla .js.php
        # e extensões falsas .ccss/.hph
        find $PWD -not -path '*/.security/*' -not -path '*/remocao/*' -type f \( -iname "*.mo" -o -iname "*.ott" \
            -o -iname "*.inc" -o -iname "*.otc" -o -iname "*.oti" -o -iname "*.ccss" -o -iname "*.ico" \
            -o -iname "*.js.php" -o -iname "*.hph" \) \
            | grep -E "\/\.[A-Za-z0-9]{8}\.mo|\/\.[A-Za-z0-9]{8}\.inc|\/\.[A-Za-z0-9]{8}\.otc|\/\.[A-Za-z0-9]{8}\.ico|\/\.[A-Za-z0-9]{8}\.ccss|\/\.[A-Za-z0-9]{8}\.ott|\/\.[A-Za-z0-9]{8}\.oti|.js.php|.ccss|.hph"

        # Pasta de dados do webshell ALFA
        find $PWD -type d -iname "ALFA_DATA"

        # Qualquer arquivo em .well-known (normalmente só tem arquivos de validação SSL)
        find $PWD -path "*/.well-known/*" -type f

    # -------------------------------------------------------------------------
    # 7. FILTRAR A SEÇÃO "OUTROS"
    # -------------------------------------------------------------------------
    # Carrega em memória o que já apareceu nas seções 1 e 2 (r_ja) e imprime só
    # as linhas que (a) não estão lá e (b) ainda não foram impressas (sem repetição).
    } | awk -v f="$SIG/r_ja" 'BEGIN { while ((getline l < f) > 0) ja[l] }
                               !($0 in ja) && !visto[$0]++' > "$SIG/r_outros"

    unset IFS        # volta o shell ao comportamento normal

    # -------------------------------------------------------------------------
    # 8. MOSTRAR O RESULTADO EM SEÇÕES
    # -------------------------------------------------------------------------
    # SECAO "título" arquivo : imprime o título em ciano e o conteúdo do arquivo
    # (sem linhas repetidas), ou "(nenhum)" se estiver vazio.
    SECAO(){
        echo -e "\n\033[1;36m$1\033[0m"
        if [ -s "$2" ] ; then
            awk '!v[$0]++' "$2"
        else
            echo "(nenhum)"
        fi
    }
    SECAO "Estes são os arquivos identificados por meio da base de dados:" "$SIG/r_base"
    SECAO "Estes são os arquivos identificados com os Hashes:"             "$SIG/r_hash"
    SECAO "Outros arquivos:"                                               "$SIG/r_outros"

    # Apaga a pasta temporária com as listas baixadas e desarma o trap do Ctrl+C
    rm -rf "$SIG"
    trap - INT TERM

    # -------------------------------------------------------------------------
    # 9. LISTDIRE: raiz de cada domínio da conta, para análise visual
    # -------------------------------------------------------------------------
    # /etc/userdomains     -> "dominio: usuario"   (quais domínios são da conta)
    # /etc/userdatadomains -> o 5º campo (separado por "==") é a pasta raiz do domínio
    # Para cada pasta raiz (sem repetição):
    #   - título em vermelho com o caminho
    #   - arquivos da raiz
    #   - em amarelo, as subpastas, exceto wp-admin, wp-content e wp-includes
    LISTDIRE(){
        for DIR in $(for DOMAIN in $(grep -w $USR /etc/userdomains | awk -F":" '{print $1}'); do
                         grep $DOMAIN /etc/userdatadomains | grep -w $USR | awk -F"==" '{print $5}'
                     done | sort | uniq); do
            echo -e "\033[1;31m\n${DIR}\033[0m"
            find "$DIR" -maxdepth 1 -type f | sort
            echo -e "\033[38;5;11m"
            find "$DIR" -maxdepth 1 -type d | sort | grep -vE "wp-admin|wp-content|wp-includes|$DIR$"
            echo -e "\033[0m"
        done
    }
    LISTDIRE
}


# =============================================================================
# EXECUÇÃO
# =============================================================================
# "time" mede a duração. O 2> manda para ~/argos.time tudo o que sai em stderr:
# o tempo e também as mensagens de erro dos comandos (ex.: "find: Permission
# denied"), deixando a tela limpa. Por isso os avisos do script usam stdout.
{ time ARGOS ; } 2>$HOMEDIR/argos.time

# Observação: o one-liner ativa o jailshell no início (se a conta não tinha
# shell), mas não desativa no fim. No APOLO isso é feito com:
#   [[ $jsenabled ]] && cppc --disableshell $USR ; unset jsenabled
