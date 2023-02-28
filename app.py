from flask import Flask,render_template,request,session,flash,jsonify,Response,redirect
import pymongo
import random
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime,timedelta
from flask_mail import Mail,Message
import threading
from flask_cors import CORS

app = Flask(__name__)
CORS(app,supports_credentials=True)
app.secret_key = "ubaidqwrtyu"
# Configuring mail servicve
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_USERNAME'] = 'ubaidpatel595@gmail.com'
app.config['MAIL_PASSWORD'] = 'dzavvnlewlytlute'
app.config['MAIL_DEFAULT_SENDER'] = 'ubaidpatel595@gmail.com'
mail = Mail(app)
#Password Encoder To secure passwords
bcrypt = Bcrypt(app)

#Mongo Db Comfiguration
client = pymongo.MongoClient("mongodb+srv://ubaidpatel595:ubaidP123@cluster0.oacc2sw.mongodb.net/")
db = client['urlshort']
collect = db['urls']
users = db['users']

#Generates Unique Endpoint for shorted Url
def uniqueEnd(len):
    str = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm12234567890"
    rand = random.choices(str,k=len)
    return "".join(rand)

#Generates JWT for password reset link
def generateJwt(userid,time):
        paload = {
            'exp':datetime.utcnow()+timedelta(minutes=time),
            'iat':datetime.utcnow(),
            'sub':userid
          }
        token = jwt.encode(
        paload,
        app.config['SECRET_KEY'],
        algorithm='HS256'
        )
        return token

#Send Mails To Users
def SendEmail(email,token):
    with app.app_context():
        msg = Message("Password Reset 595_URL_SHORTNER",recipients=[email],sender="ubaidpatel595@gmail.com")
        msg.html = '<h4>Password Reset Link Valid for 10 Minutes </h4><a href='+token+'>Click Here To Reset Password</a>'
        try:
           mail.send(msg)
           print("sent")
        except RuntimeError as e:
            print(e.__context__)

def verifyToken(token):
    try:
            token = jwt.decode(token.encode(),app.secret_key,'HS256')
            return {"isVerified":True,"userid":token['sub']}
    except Exception as e:
            return {"isVerified":False,"userid":None}

@app.route("/",methods=["GET","POST"])
def home():
    return render_template('index.html')

@app.route("/createLink",methods=["POST"])
def createLink():
    url = request.args.get('url')
    token = request.args.get('token')
    tokenVerification = verifyToken(token)
    alvail = False
    endpoint = ''
    while alvail == False:
        endpoint= uniqueEnd(6)
        cursor =  collect.find_one({"endpoint":endpoint})
        if cursor == None:
            if tokenVerification['isVerified']:
                print(tokenVerification['userid'])
                collect.insert_one({"url":url,"endpoint":endpoint,"user":tokenVerification['userid']})
            else:
             collect.insert_one({"url":url,"endpoint":endpoint})
            alvail = True
    return(jsonify({"auth":tokenVerification["isVerified"],"endpoint":endpoint,"message":"Link Created Successfull"}))   

@app.route("/login",methods=["POST"])
def login():
        email = request.args.get('email')
        password = request.args.get('password')
        cursor = users.find_one({"email":email})
        if cursor != None:
            passh = cursor['password']
            if bcrypt.check_password_hash(passh,password):
                token = generateJwt(cursor['email'],400) 
                links = []
                newcursor = collect.find({"user":email})
                for link in newcursor:
                    linkobj = {"endpoint":link['endpoint'],"url":link['url']}
                    links.append(linkobj)
                return jsonify({"status":1,"token":token,"links":links,"message":"Login success"})
            else:
                return jsonify({"status":0,"token":None,"links":[],"message":"Incorrect Password"})
        else:
            return jsonify({"status":-1,"token":None,"links":[],"message":"User not found please create account"})

@app.route("/signup",methods=["POST"])
def register():
        password = request.args.get('password')
        mobile = request.args.get('mobile')
        email = request.args.get('email')
        cursor = users.find_one({"email":email})
        passh = bcrypt.generate_password_hash(password).decode('utf-8')
        if cursor == None:
            users.insert_one({"email":email,"mobile":mobile,"password":passh})
            token = generateJwt(email,400)
            return jsonify({"status":1,"token":token,"message":"Account Created Successfully"})
        else:
            return jsonify({"status":0,"token":None,"message":"User Already Exist Please Login"})

@app.route("/changepassword",methods=["POST"])
def changepass():
    token = request.args.get('token')
    password = request.args.get('oldPassword')
    newpassword = request.args.get('newPassword')
    tokenverify = verifyToken(token)
    if tokenverify['isVerified']:
        if(password == None or newpassword == None):
            return jsonify({"status":0,"message":"Passwords Cant Be Empty"})
        cursor =  users.find_one({"email":tokenverify['userid']})
        print(tokenverify['userid'])
        if bcrypt.check_password_hash(cursor['password'],password):
            newpass = bcrypt.generate_password_hash(newpassword).decode('utf-8')
            result = users.update_one({"email":tokenverify['userid']},{"$set":{"password":newpass}})
            if result.modified_count == 1:
                return jsonify({"status":1,"message":"Password Changed Successfully"}) 
        else:
            return jsonify({"status":0,"message":"Incorrect Old Password"})
    else:
        return jsonify({"status":-1,"message":"Invalid Token"})

@app.route("/forgotPassword",methods = ['POST'])
def reset():
    email = request.args.get('email')
    cursor = users.find_one({"email":email})
    if cursor !=None:
        token =request.host_url+"ResetPassword/"+generateJwt(cursor['email'],10)
        threading.Thread(target=SendEmail,args=(email,token)).start()
        return jsonify({"status":1,"message":"Reset link sent to registered email"})
    else:
        return jsonify({"status":0,"message":"User Not Found"})

@app.route("/ResetPassword/<token>",methods=["GET","POST"])
def ResetPass(token):
    logged = False
    if request.method == 'POST':
        try:
            token = jwt.decode(token.encode(),app.secret_key,'HS256')
            print(token['sub'])
            password = request.form['password']
            email = token['sub']
            passh =  bcrypt.generate_password_hash(password=password).decode('utf-8')
            users.update_one({"email":email},{'$set':{"password":passh}})
            flash("Password Change Success")
        except Exception as e:
            flash("Link Expired")
    return render_template("resetPassword.html",logged=logged)
@app.route("/editLink",methods=["POST"])
def editlink():
    endpoint = request.args.get('endpoint')
    url = request.args.get('url')
    token = request.args.get('token')
    tokenverify = verifyToken(token)
    if tokenverify['isVerified']:
        if(collect.find_one({"endpoint":endpoint}) == None):
            return jsonify({"status":0,"message":"Invalid Endpoint"})
        collect.update_one({"endpoint":endpoint},{"$set":{"url":url}})
        return jsonify({"status":1,"message":"Link Updated Successfully"})
    else:
        return jsonify({"status":-1,"message":"Invalid Token"})

@app.route("/Logout")
def Logout():
    session['userId']=None
    session['loggedIn'] = False
    flash("Succesfully Logged Out")
    return render_template("logout.html",logged = True)

@app.route("/delete",methods=['POST'])
def delete():
    endpoint = request.args.get('endpoint')
    url = request.args.get('url')
    token = request.args.get('token')
    tokenverify = verifyToken(token)
    if tokenverify['isVerified']:
        res = collect.delete_one({"endpoint":endpoint})
        return jsonify({"status":1,"message":"Link Deleted Successfully"})
    else:
        return jsonify({"status":-1,"message":"Invalid Token"})
 
@app.route("/<endpoint>",)
def redir(endpoint):
    data  = collect.find_one({"endpoint":endpoint})
    try:
        return redirect(data['url'])
    except:
        return "<script>setTimeout(()=>{window.location.href='/'},800)</script><h1 style='text-align:center'>invalid Url<h1>"

if __name__ == "__main__":
    app.run(debug=True,host="192.168.43.160",port=5000)