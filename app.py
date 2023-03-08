from flask import Flask,render_template,request,session,flash,jsonify,Response,redirect
import pymongo
import random
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime,timedelta
from flask_mail import Mail,Message
import threading
from flask_cors import CORS
otpdict={}
app = Flask(__name__)
CORS(app,supports_credentials=True)
app.secret_key = "ubaidqwrtyu"
# Configuring mail servicve
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_USERNAME'] = 'urlpro595@gmail.com'
app.config['MAIL_PASSWORD'] = 'nvufqxsdqdgnqoay'
app.config['MAIL_DEFAULT_SENDER'] = 'urlpro595@gmail.com'
mail = Mail(app)
#Password Encoder To secure passwords
bcrypt = Bcrypt(app)

#Mongo Db Comfiguration
client = pymongo.MongoClient("mongodb+srv://ubaidpatel595:ubaidP123@cluster0.oacc2sw.mongodb.net/")
db = client['urlpro']
allLinks = db['links']
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
def SendEmail(message):
    with app.app_context():
        try:
           mail.send(message)
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
    title = request.args.get('title')
    token = request.args.get('token')
    tokenVerification = verifyToken(token)
    alvail = False
    endpoint = ''
    while alvail == False:
        endpoint= uniqueEnd(6)
        cursor =  allLinks.find_one({"endpoint":endpoint})
        if cursor == None:
            if tokenVerification['isVerified']:
                allLinks.insert_one({"url":url,"endpoint":endpoint,"title":title,"views":0})
                users.update_one({"email":tokenVerification["userid"]},{"$addToSet":{"endpoints":endpoint}})
                print(tokenVerification['userid'])
            else:
             allLinks.insert_one({"url":url,"endpoint":endpoint,"title":title,"views":0})
            alvail = True
    return(jsonify({"status": 1 if tokenVerification["isVerified"] else 0,"endpoint":endpoint,"message":"Link Created Successfull"}))   

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
                newcursor = allLinks.aggregate([
                    {
                    "$match":{
                    "endpoint":{
                    "$in":users.find_one({'email': email})['endpoints']
                    }
                    }
                    }
                ])
                for link in newcursor:
                    linkobj = {"endpoint":link['endpoint'],"url":link['url'],"title":link['title'],"views":link['views']}
                    links.append(linkobj)
                return jsonify({"name":cursor['name'],"status":1,"token":token,"links":links,"message":"Login success"})
            else:
                return jsonify({"name":None,"status":0,"token":None,"links":[],"message":"Incorrect Password"})
        else:
            return jsonify({"name":None,"status":-1,"token":None,"links":[],"message":"User not found please create account"})

@app.route("/signup",methods=["POST"])
def register():
        password = request.args.get('password')
        name = request.args.get('name')
        email = request.args.get('email')
        otp = request.args.get('otp')
        auth = verifyotp(email,otp)
        if auth['status'] != 1:
            return auth
        cursor = users.find_one({"email":email})
        passh = bcrypt.generate_password_hash(password).decode('utf-8')
        if cursor == None:
            users.insert_one({"email":email,"name":name,"password":passh,"endpoints":[]})
            token = generateJwt(email,400)
            return jsonify({"status":1,"token":token,"name":name,"links":[],"message":"Account Created Successfully"})
        else:
            return jsonify({"status":0,"token":None,"name":name,"links":[],"message":"User Already Exist Please Login"})

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
    otp = request.args.get('otp')
    password = request.args.get('password')
    auth = verifyotp(email,otp)
    if auth['status'] !=1:
        return auth
    cursor = users.update_one({"email":email},{"$set":{"password":bcrypt.generate_password_hash(password).decode("utf-8")}})
    return jsonify({"status":1,"message":"Password Reset Successfull"})

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
    title = request.args.get('title')
    token = request.args.get('token')
    tokenverify = verifyToken(token)
    if tokenverify['isVerified']:
        if(allLinks.find_one({"endpoint":endpoint}) == None):
            return jsonify({"status":0,"message":"Invalid Endpoint"})
        allLinks.update_one({"endpoint":endpoint},{"$set":{"url":url,"title":title}})
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
        res = allLinks.delete_one({"endpoint":endpoint})
        return jsonify({"status":1,"message":"Link Deleted Successfully"})
    else:
        return jsonify({"status":-1,"message":"Invalid Token"})
 
@app.route("/<endpoint>")
def redir(endpoint):
    data  = allLinks.find_one_and_update({"endpoint":endpoint},{"$inc":{"views":1}})
    try:
        return redirect(data['url'])
    except:
        return "<script>setTimeout(()=>{window.location.href='/'},800)</script><h1 style='text-align:center'>invalid Url<h1>"
@app.route("/sendOtp",methods=['POST'])
def sendotp():
    email = request.args.get("email")
    otp = random.randint(000000,999999)
    msg = Message("URL PRO",recipients=[email],sender="urlpro595@gmail.com")
    html =  render_template('email.html',otp=otp)
    msg.html = html
    #SendEmail(msg)
    threading.Thread(target=SendEmail,args=(msg,)).start()
    otpdict[email] = otp
    return {"status":1,"message":"otp sent successfully"}

@app.route("/userSendOtp",methods=['POST'])
def userSendOtp():
    email = request.args.get("email")
    otp = random.randint(00000,99999)
    user = users.find_one({"email":email})
    if user == None:
        return {"status":-1,"message":"User not found"}
    msg = Message("URL PRO",recipients=[email],sender="urlpro595@gmail.com")
    html =  render_template('email.html',otp=otp)
    msg.html = html
    threading.Thread(target=SendEmail,args=(msg,)).start()
    otpdict[email] = otp
    return {"status":1,"message":"otp sent successfully"}
# @app.route("/fakeUserSendOtp",methods=['POST'])
# def fakeuserSendOtp():
#     email = request.args.get("email")
#     otp = random.randint(00000,99999)
#     user = users.find_one({"email":email})
#     if user == None:
#         return {"status":-1,"message":"User not found"}
#     msg = Message("Password Reset URL PRO",recipients=[email],sender="urlpro595@gmail.com")
#     msg.html = '<h4>OTP to signup on URL PRO is '+str(otp)+' Valid for 5 minutes</h4>'
#     threading.Thread(target=SendEmail,args=(msg,)).start()
#     otpdict[email] = otp
#     return {"status":1,"message":"otp sent successfully"}

# @app.route("/fakeSendOTP",methods=['POST'])
# def fakesendotp():
#     email = request.args.get("email")
#     otp = random.randint(00000,99999)
#     otpdict[email] = otp
#     return {"status":1,"message":"otp sent successfully"}

# @app.route("/getOTPS",methods=['POST'])
# def getOTPS():
#     return otpdict

def verifyotp(email,otp):
    try:
        if otpdict[email] == int(otp):
            otpdict.pop(email)
            return {"status":1,"message":"Verified"}
        else:
            return {"status":0,"message":"Incorrect Otp"}
    except:
        return {"status":-1,"message":"Otp Not Generated"}   
@app.route("/ChangeName",methods=['POST'])
def Changename():
    newname = request.args.get("newName")
    token = request.args.get('token')
    tokenverify = verifyToken(token)
    if tokenverify['isVerified']:
        users.update_one({"email":tokenverify["userid"]},{"$set":{"name":newname}})
        return jsonify({"status":1,"message":"Name Updated Successfully"})
    else:
        return jsonify({"status":-1,"message":"Session Expired"})
@app.route("/DeleteAccount",methods=['DELETE'])
def deleteacc():
    password = request.args.get('password')
    if password == None:
        password =""
    token = request.args.get('token')
    tokenverify = verifyToken(token)
    if tokenverify['isVerified']:
        user = users.find_one({"email":tokenverify['userid']})
        if user == None:
            return jsonify({"status":-1,"message":"Account doesn't exist"})
        if bcrypt.check_password_hash(pw_hash=user['password'],password=password):
            allLinks.delete_many({"endpoint":{"$in":user['endpoints']}})
            users.delete_one({"email":tokenverify['userid']})
            return jsonify({"status":1,"message":"Account Deleted Successfully"})
        else:
            return jsonify({"status":0,"message":"Incorrect Password"})
    else:
        return jsonify({"status":-1,"message":"Session Expired"})
@app.route("/checkmailTemplate",methods=["GET"])
def mailtemp():
    return render_template("email.html",otp="123458")
if __name__ == "__main__":
    app.run()
