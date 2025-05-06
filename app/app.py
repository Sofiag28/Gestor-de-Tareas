from flask import Flask,render_template,request, redirect,url_for,session,abort
import mysql.connector
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from itsdangerous import URLSafeTimedSerializer
from itsdangerous.exc import BadSignature
from flask_mail import Mail,Message

app =Flask(__name__)

#Configurar la conexión a la base de pip install datos

app.config['SECRET_KEY']='1234567'
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db= mysql.connector.connect(
    host="localhost",
    user= "root",
    password= "",
    database= "gestor_tareas"
)

##### HACER LAS CONFIGURACIONES DE LOS PUERTOS Y CONTRASEÑA PARA QUE AGARRE
cursor=db.cursor()
app.config['MAIL_SERVER']= 'smtp.gmail.com'
app.config['MAIL_PORT']=465
app.config['MAIL_USERNAME']='laurasofiag1012@gmail.com'
app.config['MAIL_PASSWORD']='bsax aozb yeyc kiyx'
app.config['MAIL_USE_TLS']=False #Este funciona para bloquear los posibles ataques
app.config['MAIL_USE_SSL']=True #Este funciona de igual manera, el cual permite el envio del correo
app.config['MAIL_DEFAULT_SENDER']=('Ingeniera- Laura', 'laurasofiag1012@gmail.com')
mail=Mail(app)

#FUNCION PARA ENVIAR CORREO
def enviar_correo(email):
    #se genera un token para el correo proporcionado
    token= serializer.dumps(email,salt='restablecimiento de contraseña')   #LOS TOKEN SON ÚNICOS #SE IMPORTAN MÁS LIBRERIAS
    
    #SE CREA LA URL 
    enlace=url_for('restablecer_contraseña',token=token, _external=True) 
    
    #SE CREA EL MENSAJE QUE LLEVARA EL CORREO
    mensaje= Message(subject='Restablecimiento de contraseña',recipients=[email],body=f'Para restablecer contraseña, click en el siguiente enlace: {enlace}')# En este caso se envia el correo con el enlace para restablecer la contraseña

    mail.send(mensaje)


#FUNCION PARA RESTABLECER LA CONTRASEÑA
@app.route('/restablecer_contraseña/<token>',methods=['GET', 'POST'])
def restablecer_contraseña(token):

    if request.method=='POST':
        Nueva_Contraseña=request.form['Nueva_Contraseña']
        confirmar_contraseña=request.form['confirmar_contraseña']


        #verificar que las contraseñas sean iguales
        if Nueva_Contraseña != confirmar_contraseña:
            return 'Las contraseñas no coinciden'
        #VERIFICAR CORREO DEL TOKEN
        
        passwordnuevo=generate_password_hash(Nueva_Contraseña)

        #Actualizar en la base de datos
        cursor=db.cursor()
        email=serializer.loads(token, salt='restablecimiento de contraseña', max_age=3600)
        consulta="UPDATE usuarios SET Contraseña_Usuario =%s WHERE Email_usuario =%s"
        cursor.execute(consulta,(passwordnuevo, email))
        db.commit()
        print (consulta)
        return redirect(url_for('login'))
    return render_template('restablecer_contraseña.html')

#RECUPERAR CONTRASEÑA 
@app.route('/recuperar_contraseña',methods=['GET', 'POST'])
def recuperar_contraseña():
    if request.method=='POST':
    
        email=request.form.get('email')
        enviar_correo(email)

        return redirect(url_for('login'))
    return render_template('recuperar_contraseña.html')

#RUTA PARA EL LOGIN
@app.route('/', methods=['GET', 'POST'])

def login():

    #VERIFICACIÓN DE CREDENCIALES DE INGRESO DE ACUERDO AL ROL
    usuario=request.form.get('Usuario_name')
    contraseña=request.form.get('Contraseña_Usuario')

    cursor=db.cursor(dictionary=True, buffered=True)
    query="SELECT Nombre_usuario, Apellidos_usuario, Genero, Usuario_name,Contraseña_Usuario,Rol FROM usuarios WHERE Usuario_name =%s"
    cursor.execute(query,(usuario,))
    usuarios=cursor.fetchone()

    if(usuarios and check_password_hash(usuarios['Contraseña_Usuario'],contraseña)): #COMPARACIÓN
    #CREAR SESIÓN 
        
        session['nickname']= usuarios['Usuario_name']
        session['Rol']= usuarios['Rol']
        session['Nombre']=usuarios['Nombre_usuario']
        session['Apellido']=usuarios['Apellidos_usuario']
        session['genero']=usuarios['Genero']

        if usuarios['Rol']=='Administrador':
            return render_template('PrincipalAD.html', nickname=usuarios['Usuario_name'],genero=usuarios['Genero'],nombre_usuario=usuarios['Nombre_usuario'], apellidos=usuarios['Apellidos_usuario'])
        
        else:
            return render_template('PrincipalUS.html', nickname=usuarios['Usuario_name'],genero=usuarios['Genero'],nombre_usuario=usuarios['Nombre_usuario'], apellidos=usuarios['Apellidos_usuario'])
    else:
        print("Credenciales incorrectas")
    return render_template('Index.html')

#CERRAR SESIÓN 
@app.route('/salir')
def salir():
    session.pop('usuario',None)
    return redirect(url_for('login'))

#NO ALMACENA EL CACHE DE LA PÁGINA
@app.after_request
def add_header(response):
    response.headers['Cache-Control']='no-cache,no-store,must-revalidate' #Controla la cache que ingresa
    response.headers['Pragma']='no-cache' #No almacena la url 
    response.headers['Expires']=0 #establece un vencimiento de respuesta

    return response


#Crear un objeto y llamar una función para la bd
cursor=db.cursor()

#CREAR RUTAS REGISTRO USUARIOS

@app.route('/RegistroUsuarios', methods=['GET','POST']) 
def RegistroUsuarios():

    if request.method == 'POST':
        NombreU = request.form.get('Nombre_usuario')
        ApellidosU = request.form.get('Apellidos_usuario')
        emailU = request.form.get('Email_usuario')
        genero=request.form.get('Genero')
        nmUsuario = request.form.get('Usuario_name')
        ContraseñaU = request.form.get('Contraseña_Usuario')
        RolUsuario = request.form.get('Rol')
        Cencriptada = generate_password_hash(ContraseñaU) # ENCRIPTAR LA CONTRASEÑA
    
    # Verificar si el usuario y el email ya existen

        cursor = db.cursor()
        cursor.execute('SELECT * FROM usuarios WHERE Usuario_name = %s OR Email_usuario = %s ', (nmUsuario,emailU))
        resultado = cursor.fetchone()
        if resultado:
            print("Usuario o email ya se encuentra registrado en la base de datos")
            render_template('RegistroUsuarios.html')
        # INSERTAR DATOS EN LA BASE
        else:
            cursor.execute("INSERT INTO usuarios(Nombre_usuario, Apellidos_usuario, Email_usuario, Genero, Usuario_name, Contraseña_Usuario, Rol) VALUES (%s, %s, %s, %s, %s, %s, %s)", (NombreU, ApellidosU, emailU, genero, nmUsuario, Cencriptada, RolUsuario)),
            db.commit()
            print("Usuario registrado con éxito")
        return redirect(url_for('lista'))

    return render_template('RegistroUsuarios.html',Rol=session['Rol'],nickname=session['nickname'],genero=session['genero'],nombre_usuario=session['Nombre'], apellidos=session['Apellido'], ver_tareas=True)

#LISTAR USUARIOS

@app.route('/lista',methods=['GET','POST'])
def lista():
    cursor=db.cursor()
    cursor.execute("SELECT * FROM usuarios")
    usuario=cursor.fetchall()
    return render_template('PrincipalAD.html',Rol=session['Rol'],nickname=session['nickname'],genero=session['genero'],nombre_usuario=session['Nombre'], apellidos=session['Apellido'],usuarios=usuario, ver_usuarios=True)
    
@app.route('/tareas', methods=['GET', 'POST'])
def tareas():  
    cursor = db.cursor()  

    if session['Rol'] == 'Administrador':
        # TAREAS DEL ADMINISTRADOR (TODAS LAS TAREAS CON DATOS DEL USUARIO)
        cursor.execute("""
            SELECT tareas.*, usuarios.Usuario_name, usuarios.Nombre_usuario, usuarios.Apellidos_usuario 
            FROM tareas JOIN usuarios ON tareas.id_usuarios = usuarios.Id_Usuarios
        """)
        tareas = cursor.fetchall()
        return render_template('PrincipalAD.html', Rol=session['Rol'],nickname=session['nickname'],genero=session['genero'],nombre_usuario=session['Nombre'], apellidos=session['Apellido'],task=tareas, ver_tareas=True)

    else:
        # TAREAS DEL USUARIO ACTUAL
        cursor.execute("SELECT * FROM tareas WHERE Id_Usuarios=%s", (session['Id_Usuarios'],))
        tareas = cursor.fetchall()
        return render_template('PrincipalUS.html', Rol=session['Rol'], nickname=session['nickname'], 
                               genero=session['genero'], nombre_usuario=session['Nombre_usuario'], 
                               apellidos=session['Apellidos_usuario'], task=tareas, ver_tareas=True)


#############################ACCIONES-###############################

#ELIMINAR USUARIOS
@app.route('/eliminarusuario/<int:Id_Usuarios>', methods = ['GET', 'POST'])
def eliminar_usuario(Id_Usuarios):
    cursor=db.cursor()
    cursor.execute('DELETE FROM usuarios WHERE Id_Usuarios =%s', (Id_Usuarios,))
    db.commit()
    print("usuario eliminado")

    return redirect(url_for('lista'))

#EDITAR
@app.route('/EditarUsuarios/<int:Id_Usuarios>',methods=['GET', 'POST'])
def editar_usuarios(Id_Usuarios):

    if request.method=='POST':
        #codigo=request.form['codigo']
        nombre=request.form['nombre']
        apellido=request.form['apellido']
        email=request.form['email']
        nickname=request.form['nickname']
        rol=request.form['rol']

#ACTUALIZAR LOS DATOS DEL FORMULARIO
        cursor=db.cursor()
        sql= 'UPDATE usuarios SET Nombre_usuario =%s, Apellidos_usuario =%s, Email_usuario =%s, Usuario_name =%s, Rol =%s WHERE Id_Usuarios = %s'
        cursor.execute(sql,(nombre,apellido,email,nickname,rol, Id_Usuarios))
        db.commit()
        return redirect(url_for('lista'))

    else:
        cursor=db.cursor()
        #OBTENER DATOS DE LA TAREA
        cursor.execute('SELECT * FROM usuarios WHERE Id_Usuarios =%s',(Id_Usuarios,))
        data=cursor.fetchall() #GUARDAR EL RESULTADO EN LISTAS
        cursor.close()
        return render_template('Modalusuarios.html', usuario=data[0],Rol=session['Rol'], nickname=session['nickname'],genero=session.get('genero'),nombre_usuario=session.get('Nombre'),apellidos=session.get('Apellido'))
    
#ELIMINAR TAREAS
@app.route('/eliminartareas/<int:id_Tareas>',methods=['GET'])
def eliminar_tareas(id_Tareas):
    cursor=db.cursor()
    cursor.execute('DELETE FROM tareas WHERE id_Tareas =%s', (id_Tareas,))
    db.commit()
    print("Tarea eliminada")
    return redirect(url_for('tareas'))
    
#FILTRADO DE LAS TAREAS

@app.route('/buscar_tarea', methods=['POST'])
def buscar_tarea():
    busqueda=request.form.get('busqueda')

#realiza la búsqueda en la bd
    cursor=db.cursor(dictionary=True)
    consulta="SELECT * FROM tareas WHERE id_Tareas= %s OR Nombre LIKE %s"
    cursor.execute(consulta,(busqueda, "%" + busqueda +"%"))
    tareas=cursor.fetchall()
    return render_template('Resultadobusqueda.html', task=tareas, busqueda=busqueda, Rol=session['Rol'], nickname=session['nickname'],genero=session.get('genero'),nombre_usuario=session.get('Nombre'),apellidos=session.get('Apellido'))

    

#EDITAR TAREAS
@app.route('/EditarTareas/<int:id_Tareas>',methods=['GET', 'POST'])
def editar_tareas(id_Tareas):

    if request.method=='POST':
        #codigotar=request.form['codigo']
        nombretar=request.form['nombretar']
        fechainicio=request.form['finicio']
        fechafin=request.form['ftermino']
        estadotar=request.form['estadotar']

#ACTUALIZAR LOS DATOS DEL FORMULARIO
        cursor = db.cursor()
        sql= 'UPDATE tareas SET Nombre =%s, Fecha_Inicio =%s, Fecha_final =%s, Estado =%s WHERE id_Tareas = %s '
        cursor.execute(sql,(nombretar,fechainicio,fechafin,estadotar,id_Tareas))
        db.commit()
        return redirect(url_for('tareas'))

    else:
        cursor=db.cursor()
        #OBTENER DATOS DE LA TAREA
        cursor.execute('SELECT * FROM tareas WHERE id_Tareas =%s',(id_Tareas,))
        data=cursor.fetchall() #GUARDAR EL RESULTADO EN LISTAS
        cursor.close()
        return render_template('Modaltareas.html', tareas=data[0], Rol=session['Rol'], nickname=session['nickname'],genero=session.get('genero'),nombre_usuario=session.get('Nombre'),apellidos=session.get('Apellido'))
    
#Creación de rutas- TAREAS 
@app.route('/Registrotareas', methods=['GET','POST']) #SE DECLARAN LOS MÉTODOS
def registrarTarea():
    if request.method=='POST':
        #Variables donde se llama los campos del formulario
        NombreTarea=request.form.get('Nombre')
        FechaInicio=request.form.get('Fecha_Inicio')
        FechaFinal=request.form.get('Fecha_final')
        EstadoTar=request.form.get('Estado')
        
        
        cursor=db.cursor()
#obtener el id 
        #cursor.execute("SELECT usuarios.Id_Usuarios, tareas.id_usuarios FROM usuarios INNER JOIN tareas ON usuarios.Id_Usuarios = tareas.id_usuarios")
    #verificar que el nombre de la tarea no esta registrado
        cursor.execute('SELECT id_usuarios FROM tareas WHERE Nombre = %s',(NombreTarea,))
        Existe=cursor.fetchall()

        if Existe:
            print("Nombre de la tarea ya se encuentra registrado")
            return render_template('RegistroTareas.html')
        


    #Insertar las tareas a la tabla de tareas

        cursor.execute("INSERT INTO tareas(Nombre, Fecha_Inicio, Fecha_final,Estado) VALUES(%s,%s,%s,%s)",(NombreTarea,FechaInicio,FechaFinal,EstadoTar))
        db.commit()
        print("Tarea registrada")
        return redirect(url_for('tareas'))
    return render_template('RegistroTareas.html',Rol=session['Rol'],nickname=session['nickname'],genero=session['genero'],nombre_usuario=session['Nombre'], apellidos=session['Apellido'])

if __name__=='__main__': #INVESTIGAR
    app.run(debug=True)
    app.add_url_rule('/',view_func=registrarTarea)