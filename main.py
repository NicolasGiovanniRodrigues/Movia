# IMPORTAÇÕES
import fdb
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "movia-secret-key"

# CONEXÃO COM O BANCO
host = "localhost"
database = r"C:\Users\Aluno\Downloads\Nicolas - Movia UPD 1\Nicolas - Movia\banco\MOVIA.FDB"
user = "SYSDBA"
password = "sysdba"

con = fdb.connect(
    host=host,
    database=database,
    user=user,
    password=password
)


# VERIFICAÇÃO DE SENHA FORTE
def senha_forte(senha):
    if len(senha) < 8:
        return False

    if " " in senha:
        return False

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_especial = False

    for caractere in senha:
        if caractere >= "A" and caractere <= "Z":
            tem_maiuscula = True
        elif caractere >= "a" and caractere <= "z":
            tem_minuscula = True
        elif caractere >= "0" and caractere <= "9":
            tem_numero = True
        elif caractere in "!@#$%&*_-":
            tem_especial = True

    return tem_maiuscula and tem_minuscula and tem_numero and tem_especial


# VERIFICAÇÃO DA SESSÃO (LOGIN E BLOQUEIO)
def sessao_valida():
    if "id_usuario" not in session:
        flash("Faça login para continuar.", "erro")
        return False

    cursor = con.cursor()

    try:
        cursor.execute(
            "SELECT ATIVO, TENTATIVAS FROM USUARIOS WHERE ID_USUARIO = ?",
            (session["id_usuario"],)
        )
        usuario = cursor.fetchone()
    finally:
        cursor.close()

    # Usuário removido ou bloqueado perde o acesso na hora
    if not usuario or usuario[0] == 0 or (usuario[1] or 0) >= 3:
        session.clear()
        flash("Sua conta está bloqueada.", "erro")
        return False

    return True


# ROTAS
@app.route("/")
def index():
    return render_template("index.html")


# INÍCIO (PROTEGIDA)
@app.route("/inicio")
def inicio():
    if not sessao_valida():
        return redirect(url_for("login"))

    return render_template(
        "inicio.html",
        usuario=session["usuario"],
        id_usuario=session["id_usuario"]
    )


# MEU PERFIL (PROTEGIDA)
@app.route("/perfil")
def perfil():
    if not sessao_valida():
        return redirect(url_for("login"))

    cursor = con.cursor()

    try:
        cursor.execute(
            """
            SELECT NOME, EMAIL, TELEFONE, TIPO_USUARIO, ATIVO
            FROM USUARIOS
            WHERE ID_USUARIO = ?
            """,
            (session["id_usuario"],)
        )

        usuario = cursor.fetchone()

        return render_template(
            "perfil.html",
            usuario=usuario,
            id_usuario=session["id_usuario"]
        )

    finally:
        cursor.close()


# CADASTRO DE ALUNO
@app.route("/cadastro", methods=["GET", "POST"])
def cadastrar_aluno():
    if request.method == "POST":
        nome = request.form["nome"].strip()
        email = request.form["email"].strip().lower()
        telefone = request.form["telefone"].strip()
        senha = request.form["senha"]
        confirmar_senha = request.form["confirmar_senha"]

        if not nome:
            flash("Preencha o nome completo.", "erro")
            return redirect(url_for("cadastrar_aluno"))

        if not email:
            flash("Preencha o e-mail.", "erro")
            return redirect(url_for("cadastrar_aluno"))

        if not telefone:
            flash("Preencha o telefone.", "erro")
            return redirect(url_for("cadastrar_aluno"))

        if not telefone.isdigit():
            flash("O telefone deve conter apenas números.", "erro")
            return redirect(url_for("cadastrar_aluno"))

        if not senha or not confirmar_senha:
            flash("Preencha os dois campos de senha.", "erro")
            return redirect(url_for("cadastrar_aluno"))

        if senha != confirmar_senha:
            flash("As senhas não são iguais.", "erro")
            return redirect(url_for("cadastrar_aluno"))

        if not senha_forte(senha):
            flash(
                "A senha precisa ter pelo menos 8 caracteres, letra maiúscula, "
                "minúscula, número, símbolo (!@#$%&*_-) e não pode ter espaços.",
                "erro"
            )
            return redirect(url_for("cadastrar_aluno"))

        cursor = con.cursor()

        try:
            cursor.execute(
                "SELECT ID_USUARIO FROM USUARIOS WHERE LOWER(EMAIL) = ?",
                (email,)
            )

            if cursor.fetchone():
                flash("Este e-mail já está cadastrado.", "erro")
                return redirect(url_for("cadastrar_aluno"))

            senha_hash = generate_password_hash(senha).decode("utf-8")

            cursor.execute(
                """
                INSERT INTO USUARIOS
                (NOME, EMAIL, TELEFONE, SENHA, TIPO_USUARIO)
                VALUES (?, ?, ?, ?, ?)
                """,
                (nome, email, telefone, senha_hash, "Aluno")
            )

            con.commit()
            return redirect(url_for("cadastro_concluido"))

        except Exception as e:
            con.rollback()
            flash(f"Ocorreu um erro -> {e}", "erro")
            return redirect(url_for("cadastrar_aluno"))

        finally:
            cursor.close()

    return render_template("cadastro.html")


@app.route("/cadastro-concluido")
def cadastro_concluido():
    return render_template("cadastro_concluido.html")


# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    # Quem já está logado vai direto para o início
    if request.method == "GET" and "id_usuario" in session:
        return redirect(url_for("inicio"))

    if request.method == "POST":
        email = request.form["email"].strip().lower()
        senha = request.form["senha"]

        cursor = con.cursor()

        try:
            cursor.execute(
                """
                SELECT ID_USUARIO, NOME, SENHA, ATIVO, TENTATIVAS
                FROM USUARIOS
                WHERE LOWER(EMAIL) = ?
                """,
                (email,)
            )

            usuario = cursor.fetchone()

            # Mensagem genérica para não revelar se o e-mail existe
            if usuario is None:
                flash("E-mail ou senha incorretos.", "erro")
                return render_template("login.html", email=email)

            id_usuario = usuario[0]
            nome = usuario[1]
            senha_hash = usuario[2]
            ativo = usuario[3]
            tentativas = usuario[4] or 0

            if tentativas >= 3:
                flash("Usuário bloqueado após 3 tentativas.", "erro")
                return render_template("login.html", email=email)

            if ativo == 0:
                flash("Este usuário está inativo.", "erro")
                return render_template("login.html", email=email)

            if check_password_hash(senha_hash, senha):
                cursor.execute(
                    "UPDATE USUARIOS SET TENTATIVAS = 0 WHERE ID_USUARIO = ?",
                    (id_usuario,)
                )
                con.commit()

                session.clear()
                session["id_usuario"] = id_usuario
                session["usuario"] = nome
                return redirect(url_for("inicio"))

            tentativas += 1

            if tentativas >= 3:
                cursor.execute(
                    """
                    UPDATE USUARIOS
                    SET TENTATIVAS = ?, ATIVO = 0
                    WHERE ID_USUARIO = ?
                    """,
                    (tentativas, id_usuario)
                )
                con.commit()

                flash(
                    "Senha incorreta. Usuário bloqueado após 3 tentativas.",
                    "erro"
                )
            else:
                cursor.execute(
                    "UPDATE USUARIOS SET TENTATIVAS = ? WHERE ID_USUARIO = ?",
                    (tentativas, id_usuario)
                )
                con.commit()

                restantes = 3 - tentativas
                flash(
                    f"E-mail ou senha incorretos. Restam {restantes} tentativa(s).",
                    "erro"
                )

            return render_template("login.html", email=email)

        except Exception as e:
            con.rollback()
            flash(f"Ocorreu um erro -> {e}", "erro")
            return render_template("login.html", email=email)

        finally:
            cursor.close()

    return render_template("login.html", email="")


# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    flash("Você saiu da sua conta.", "info")
    return redirect(url_for("login"))


# EDITAR USUÁRIO (PROTEGIDA)
@app.route("/editar/<int:id>", methods=["GET", "POST"])
def editar_usuario(id):
    if not sessao_valida():
        return redirect(url_for("login"))

    # O usuário só pode editar a própria conta
    if id != session["id_usuario"]:
        flash("Você não pode editar outro usuário.", "erro")
        return redirect(url_for("inicio"))

    cursor = con.cursor()

    try:
        cursor.execute(
            """
            SELECT ID_USUARIO, NOME, EMAIL, TELEFONE
            FROM USUARIOS
            WHERE ID_USUARIO = ?
            """,
            (id,)
        )

        usuario = cursor.fetchone()

        if not usuario:
            flash("Usuário não encontrado.", "erro")
            return redirect(url_for("inicio"))

        if request.method == "POST":
            nome = request.form["nome"].strip()
            email = request.form["email"].strip().lower()
            telefone = request.form["telefone"].strip()

            if not nome:
                flash("O nome não pode estar vazio.", "erro")
                return redirect(url_for("editar_usuario", id=id))

            if not email:
                flash("O e-mail não pode estar vazio.", "erro")
                return redirect(url_for("editar_usuario", id=id))

            if not telefone.isdigit():
                flash("O telefone deve conter apenas números.", "erro")
                return redirect(url_for("editar_usuario", id=id))

            cursor.execute(
                """
                SELECT ID_USUARIO
                FROM USUARIOS
                WHERE LOWER(EMAIL) = ? AND ID_USUARIO <> ?
                """,
                (email, id)
            )

            if cursor.fetchone():
                flash("Este e-mail já está cadastrado.", "erro")
                return redirect(url_for("editar_usuario", id=id))

            cursor.execute(
                """
                UPDATE USUARIOS
                SET NOME = ?, EMAIL = ?, TELEFONE = ?
                WHERE ID_USUARIO = ?
                """,
                (nome, email, telefone, id)
            )

            con.commit()

            session["usuario"] = nome
            flash("Dados atualizados com sucesso.", "sucesso")
            return redirect(url_for("perfil"))

        return render_template("editar_usuario.html", usuario=usuario)

    except Exception as e:
        con.rollback()
        flash(f"Ocorreu um erro -> {e}", "erro")
        return redirect(url_for("perfil"))

    finally:
        cursor.close()


# ALTERAR SENHA (PROTEGIDA)
@app.route("/alterar_senha", methods=["GET", "POST"])
def alterar_senha():
    if not sessao_valida():
        return redirect(url_for("login"))

    if request.method == "POST":
        senha_atual = request.form["senha_atual"]
        nova_senha = request.form["nova_senha"]
        confirmar_senha = request.form["confirmar_senha"]

        cursor = con.cursor()

        try:
            cursor.execute(
                "SELECT SENHA FROM USUARIOS WHERE ID_USUARIO = ?",
                (session["id_usuario"],)
            )

            usuario = cursor.fetchone()

            if not usuario:
                session.clear()
                flash("Usuário não encontrado.", "erro")
                return redirect(url_for("login"))

            senha_hash_atual = usuario[0]

            if not check_password_hash(senha_hash_atual, senha_atual):
                flash("Senha atual incorreta.", "erro")
                return redirect(url_for("alterar_senha"))

            if nova_senha != confirmar_senha:
                flash("As senhas não são iguais.", "erro")
                return redirect(url_for("alterar_senha"))

            if not senha_forte(nova_senha):
                flash(
                    "A nova senha precisa ter pelo menos 8 caracteres, letra maiúscula, "
                    "minúscula, número, símbolo (!@#$%&*_-) e não pode ter espaços.",
                    "erro"
                )
                return redirect(url_for("alterar_senha"))

            if check_password_hash(senha_hash_atual, nova_senha):
                flash("Utilize uma senha diferente da atual.", "erro")
                return redirect(url_for("alterar_senha"))

            # Impede reutilizar as 3 últimas senhas
            cursor.execute(
                """
                SELECT FIRST 3 SENHA
                FROM HISTORICO_SENHA
                WHERE ID_USUARIO = ?
                ORDER BY ID_HISTORICO DESC
                """,
                (session["id_usuario"],)
            )

            for senha_antiga in cursor.fetchall():
                if check_password_hash(senha_antiga[0], nova_senha):
                    flash("Você não pode reutilizar suas 3 últimas senhas.", "erro")
                    return redirect(url_for("alterar_senha"))

            senha_hash = generate_password_hash(nova_senha).decode("utf-8")

            # Guarda a senha anterior no histórico
            cursor.execute(
                "INSERT INTO HISTORICO_SENHA (ID_USUARIO, SENHA) VALUES (?, ?)",
                (session["id_usuario"], senha_hash_atual)
            )

            cursor.execute(
                "UPDATE USUARIOS SET SENHA = ? WHERE ID_USUARIO = ?",
                (senha_hash, session["id_usuario"])
            )

            con.commit()

            flash("Senha alterada com sucesso.", "sucesso")
            return redirect(url_for("perfil"))

        except Exception as e:
            con.rollback()
            flash(f"Ocorreu um erro -> {e}", "erro")
            return redirect(url_for("alterar_senha"))

        finally:
            cursor.close()

    return render_template("alterar_senha.html")


# EXECUÇÃO
if __name__ == "__main__":
    app.run(debug=True)
