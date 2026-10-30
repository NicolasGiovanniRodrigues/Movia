# IMPORTAÇÕES
import fdb
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import generate_password_hash
from flask_bcrypt import check_password_hash

app = Flask(__name__)
app.secret_key = 'movia-secret-key'

# CONEXÃO COM O BANCO
host = 'localhost'
database = r'C:\Users\Aluno\Desktop\Nicolas\banco\MOVIA.FDB'
user = 'SYSDBA'
password = 'sysdba'

con = fdb.connect(host=host, database=database, user=user, password=password)

def senha_forte(senha):
    tem_maiuscula = False
    tem_numero = False
    tem_especial = False

    for caractere in senha:
        if caractere.isupper():
            tem_maiuscula = True
        elif caractere.isdigit():
            tem_numero = True
        elif not caractere.isalnum():
            tem_especial = True

    return tem_maiuscula and tem_numero and tem_especial


# ROTAS
@app.route('/')
def index():
    return render_template('index.html')


@app.route("/cadastro", methods=["GET", "POST"])
def cadastrar_aluno():
    if request.method == "POST":
        nome = request.form["nome"].strip()
        email = request.form["email"].strip()
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
                "A senha precisa ter uma letra maiúscula, um número e um caractere especial.",
                "erro"
            )
            return redirect(url_for("cadastrar_aluno"))

        cursor = con.cursor()

        cursor = con.cursor()

        try:
            cursor.execute(
                "SELECT ID_USUARIO FROM USUARIOS WHERE EMAIL = ?",
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
            flash("Usuário cadastrado com sucesso!", "sucesso")
            return redirect(url_for("login"))

        finally:
            cursor.close()

    return render_template("cadastro.html")
@app.route('/login')
def login():
    return render_template('login.html')


# EXECUÇÃO
if __name__ == '__main__':
    app.run(debug=True)
