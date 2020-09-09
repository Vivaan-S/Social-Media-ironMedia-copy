var beforeStart = Date.now()
//this shoudnt be undefined
//console.log(process.env.REPLIT_DB_URL, "db url")
//Stopping repl to prevent database loss when bug is fixed
//process.exit()
nodemailer = require("nodemailer");
var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAILNAME,
    pass: process.env.MAILPASSWORD
  }
});
function sendMail(person,subject,content){
  var options = {
    "from":process.env.MAILNAME,
    "to":person,
    "subject":subject,
    "html":content,
    "text":content
  }
  transporter.sendMail(options, function(err,info){
    console.log(`err: ${err}. info: ${info}`)
  })
}
BadWordFilter = require("bad-words");
filter = new BadWordFilter({placeHolder:"@"})
var fs = require("fs")
markdown = require("./scripts/md.js");
//console.log(markdown("**BOLD** https://google.com/"))
fetch = require("node-fetch")
/*
adds password functions
*/
function isPassword(password,username){
 var basicKey = env.PWBASICKEY
 var dynamicKey = password + basicKey + password
 var account = users.data.f(username)
 //account doesnt exist
 if(!account){return false}
 //recreates encrypted password
 var encrypted = enc.encrypt(password,dynamicKey)
 //recreate hashed value
 var hashed = SHA2["SHA-224"](encrypted).toString("base64")
 return hashed == account.password
}
function encryptPassword(password){
  //secure 300 character length key
 var basicKey = env.PWBASICKEY
 //create dynamic key
 var dynamickey = password + basicKey + password
 //encrypt password with dynamic key
 var encrypted = enc.encrypt(password, dynamickey)
 //hash the encrypted password. Attackers cannot bruteforce this, since they don't know the encryption key. All information about the password is erased in this step and replaced with a representative value that only can get reproduced by knowing the password
 return SHA2["SHA-224"](encrypted).toString("base64")
}
function hash(input){
  return SHA2["SHA-224"](input).toString("base64")
}
//id for posts and comments
function generateID(){
  return enc.id()
}
/*
database help functions
*/
function account(name){
  return users.data.f(name)
}
function mail(name){
  return mailDB.data.f(name)
}
function filterXSS(input){
  return input.replace(/</, "&lt;").replace(/>/, "&gt;")
}
function notifyUser(name, type, message,url){
  var acc = account(name);
  if(!acc){
    return;
  }
  var user = onlineUser(name);
  var data = {
    "type":type,
    "for":name,
    "read":false,
    "message":filterXSS(message.slice(0,20)) + ((message.length>20)?"...":""),
    "url":url
  }
  notifyDB.data.push(data)
  if(user){
    user.emit("notify",JSON.stringify(notifyDB.data.fAll("for",name)))
  }
}
function markUsers(message){
var marked = []
var text = String(message).replace(/( |^)@([a-zA-Z0-9\-_]{3,20})/, function(_, _, name){
marked.push(name)
return ` <a href="/profile/${name}">@${name}</a>`
})
return [text,marked]
}
/*
load as template, similar to python flask templates
*/
function tempString(filename){
return fs.readFileSync(__dirname + '/' + filename, 'utf8')
}
function temp(string, strings){
var plain = String(string)
strings.forEach(function(stringobj){
  //if value is not marked secure, filter xss. Escape attempts to fake templating anyway
  plain = plain.split(`[[${stringobj.name}:safe]]`).join(String(stringobj.content).replace("[","&#91;"))
  plain = plain.split(`[[${stringobj.name}]]`).join(String(stringobj.content).replace(/</g,"&lt;").replace(/>/g, "&lt;").replace(/"/g,"&quot;").replace("[", "&#91;"))
})
return plain
}
var accTemp = tempString("html/profile.html")
var notifTemp = tempString("svg/hasNotification.svg")
var postTemp = tempString("html/viewPost.html")
var pwTemp = tempString("html/resetpassword.html")
/*
require modules
*/
env = process.env
exp = require("express")
app = exp()
app.use(function(req,res,next){
  res.set("X-XSS-Protection", "0")
  next()
})
var https = require("http").createServer(app);
var io = require("socket.io")(https)
https.listen(3000)
var svgCaptcha = require('svg-captcha');
Database = require("./database.js")
enc = require("./encryptSimple.js")
app.use(require('cookie-parser')());
SHA2 = require("sha2");
/*
prepare databases
*/
(async function(){
//create encrypted database
users = new Database("users")
console.log(users.data)
//creates encrypted database with 300 character key and AES-128
mailDB = new Database("maildb")
//website logs
statsDB = new Database("sitestats", false, [{"name":"imageLog","logs":[]},{"name":"errors","logs":[]},{"name":"signups","logs":[]}])
//a database for all user-submitted posts
postsDB = new Database("posts");
//database for comments
commentDB = new Database("comments")
//db for notifications
notifyDB = new Database("notifications")
//db for all chats
chatDB = new Database("chats")
await chatDB.promise
await notifyDB.promise
await commentDB.promise
await users.promise
await mailDB.promise
await statsDB.promise
await postsDB.promise
//chatDB.reset();
//notifyDB.reset()
//commentDB.reset();
//users.reset()
//mailDB.reset()
//statsDB.reset()
//postsDB.reset()
//all databases are ready
chatDB.autosave()
notifyDB.autosave()
commentDB.autosave()
users.autosave()
mailDB.autosave()
statsDB.autosave()
postsDB.autosave()
//save once all 2 minutes
//console.log(users.data)
mainCode()
//run main code
})().catch(function(err){console.log(err)})
var onlineUsers = Array()
function onlineUser(username){
  return onlineUsers.fCustom("username",username)
}
function mainCode(){
app.use(require("express").urlencoded())
//captcha session array
captchaSessions = new Array()
app.get("/signup", function(req,res){res.sendFile(__dirname + "/html/signup.html")})
//sends client captcha and stores captcha results in array
app.get("/captcha", function(req,res){
   var captcha = svgCaptcha.create()
   var session = Math.random()*Math.random()
  captchaSessions.push({"session":session,"text":captcha.text})
  res.send(JSON.stringify({data:captcha.data,session:session}))
})
app.post("/signup", function(req,res){
  function error(error){
  res.redirect("/signup?error=" + error)
  }
  //error("Signups deactivated right now");
  //return
  if(!captchaSessions.fCustom("session", req.body.session)){error('invalid captcha session'); return}
  var sessionText = captchaSessions.fCustom("session",  req.body.session).text.toLowerCase().replace(/l/g, "i")
  captchaSessions.delCustom("session", req.body.session)
  if(sessionText != req.body.captchaText.toLowerCase().replace(/l/g, "i")){error("wrong captcha text!"); return}
  //validate mail, password and name
  var username = String(req.body.name)
  if(filter.isProfane(username)){error("Inappropriate name!"); return}
  if(account(username)){error("That account exists already!"); return}
  var pw = String(req.body.pw)
  var password = pw
  var mail = String(req.body.mail)
  if((!/[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+/gm.test(mail)||mail.length>50)&&mail.length>0){error("invalid mail!"); return}
  if(username.length < 3){error("too short username!"); return}
  if(username.length > 20){error("too long username!"); return}
  if(!/^[a-zA-Z0-9\-_]{1,}$/.test(username)){
    error("invalid characters in username!");
    return
  }
  if((/^[^a-zA-Z]/).test(username)){error("username must start with a letter!"); return}
  if(users.data.map(function(user){
    return user.name.toLowerCase()==username.toLowerCase()
  }).includes(true)){
    error("username already taken!");
    return
  }
  if(password.length>50){error("too long password (max is 50)"); return}
  if(password.length<5){error("too short password (min is 5)"); return}
  //data is valid, create account
  if(mail.length>0){
    //if user used a mail, upload it to the mail database
    mailDB.data.addCustom("name", {"name":username,"mail":hash(mail.toLowerCase()),"creationDate":Date.now()})
    statsDB.data.f("signups").logs.push("Name: " + username)
    mailDB.upload()
  }
  //create account
  users.data.addCustom("name", {"name":username,"hasMail":Boolean(mail),"password":encryptPassword(password),"interests":[],"creationDate":Date.now(),"description":"A new ironMedia user","likedCount":0,"permissions":["user"],"banned":false,"suspended":false,"profilePicture":"/svg/avatar.svg","replit":false})
  users.upload()
  res.cookie('loggedIn', 'yes', {"maxAge":9999999*9999999})
res.send(`<script>if(!document.cookie.includes("loggedIn")){document.cookie ="loggedIn=yes"}localStorage['pw'] = '${pw}'; localStorage['name'] = '${username}'; location='/'</script>`)
})
//if logged in, show start page. else redirect to signup page
app.get("/", function(req,res){
if(req.cookies.loggedIn){
  res.sendFile(__dirname+"/html/index.html")
}
else{
res.redirect("/signup")
}
})
app.get("/profile/:name", function(req,res){
  var useracc = account(req.params.name)
  if(!useracc){res.sendFile(__dirname+"/html/404.html"); return}
  res.send(temp(accTemp, [
  {"name":"likes","content":String(useracc.likedCount)},
  {"name":"name","content":useracc.name},
  {"name":"description","content":markdown(useracc.description)},
  {"name":"replitVerify","content":(function(){var replit = useracc.replit; if(!replit){return "This user is not replit-verified"} return `This user is replit-verified (@${replit})`})()},
    {"name":"commentData","content":Buffer.from(JSON.stringify(
      commentDB.data.filter(function(comment){
        return comment.by==useracc.name
      }).map(function(comment){
        return {
          "content":comment.content,
          "parent":comment.parent,
          "by":comment.by,
          "id":comment.id
        }
      })
      ),"utf8").toString("base64")},
      {"name":"postData","content":Buffer.from(JSON.stringify(
      postsDB.data.filter(function(comment){
        return comment.by==useracc.name
      }).map(function(comment){
        return {
        "interest":comment.interest,
         "user":comment.by,
        "content":markdown(comment.content),
        "likes":comment.likes,"dislikes":comment.dislikes,
        "replies":comment.replies,
        "id":comment.id,
        "likers":comment.likers.map(function(liker){
          return liker.name
        }),
        "dislikers":comment.dislikers.map(function(disliker){
          return disliker.name
        }),
        "postTime":comment.postTime
        }
      })
      )).toString("base64")},
  {"name":"svgurl","content":useracc.profilePicture}
  ]))
})
app.get("/login", function(req,res){
  res.sendFile(__dirname + "/html/login.html")
})
app.use("/scripts", exp.static("./scripts"))
app.use("/styles", exp.static("./styles"))
app.post("/login", function(req,res){
  function error(error){
  res.redirect("/login?error=" + error)
  }
  var name = String(req.body.name)
  if(!name.length){error("Please enter your name!"); return}
var acc = account(name)
var pw = String(req.body.pw)
if(!acc){error("That account doesn't exist!"); return}
if(acc.banned){error("This account was banned!"); return}
if(pw.length==0){error("enter your password!"); return}
if(!isPassword(pw,name)){error("wrong password!"); return}
//correct password
res.cookie('loggedIn', 'yes', {"maxAge":9999999*9999999})
res.send(`<script>localStorage['pw'] = '${pw}'; localStorage['name'] = '${name}'; location='/'</script>`)
})
app.get("/report/:user?", function(req,res){
  if(!req.params.user){
    res.sendFile("<h1>Enter an user to report</h1>");
    return
  }
  var acc = account(req.params.user)
  if(!acc){
    res.sendFile(__dirname+"/html/404.html");
    return
  }
  res.sendFile(__dirname+"/html/report.html")
})
var reportDelays = {}
app.post("/report", function(req,res){
  var user = req.query.user
  if(!account(user)){
    res.send("User not found");
    return
  }
  if(statsDB.data.fCustom("user", user)){
    res.send("User was reported already");
    return
  }
  var data = {
    "user":user,
    "reason":req.query.reason
  }
  statsDB.data.push(data)
  res.send("Reported successfully")
})
app.get("/resetpassword/:user", function(req,res){
  var acc = account(req.params.user);
  if(!acc){
  res.sendFile(__dirname+"/html/404.html");
  return
  }
  res.send(temp(pwTemp,[{name:"hasMail",content:acc.hasMail},{name:"hasReplit",content:Boolean(acc.replit)}]))
})
//installable apps
app.use("/iosApp",exp.static("./app/ios.html"))
app.use("/windowsApp",exp.static("./app/windows.html"))
app.use("/androidApp",exp.static("./app/android.html"))
app.use("/chats",exp.static("./html/chats.html"))
//some static html files
app.use("/modmenu",exp.static("./html/adminmenu.html"))
app.use("/modmenu/helpclient",exp.static("./html/helpclient.html"))
app.use("/privacy",exp.static("./html/privacypolicy.html"))
app.use("/download",exp.static("./html/install.html"))
app.use("/rules",exp.static("./html/postingrules.html"))
app.use("/terms",exp.static("./html/terms.html"))
app.use("/svg",exp.static("./svg"))
app.use("/contact",exp.static("./html/contactme.html"))
app.use("/settings",exp.static("./html/accountOptions.html"))
app.use("/markdowninfo",exp.static("./html/markdownhelp.html"))
app.get("/viewpost/:id", function(req,res){
  var postId = String(req.params.id)
  var post = postsDB.data.fCustom("id",postId)
  if(post){
    res.send(temp(postTemp,[
      {"name":"commentData","content":Buffer.from(JSON.stringify(commentDB.data.fAll("parent",postId))).toString("base64")},
      {"name":"id","content":post.id},
      {"name":"content","content":markdown(post.content)},
      {"name":"user","content":post.by},
      {"name":"profile","content":account(post.by).profilePicture},
      {"name":"likes","content":post.likes},
      {"name":"dislikes","content":post.dislikes},
      {"name":"likeData","content":Buffer.from(JSON.stringify({"likers":post.likers.map(function(liker){
       return liker.name
      }),
      "dislikers":post.dislikers.map(function(disliker){
        return disliker.name
      })})).toString("base64")}
      ]))
   // res.sendFile(__dirname + "/html/viewPost.html")
  }
  else{
    res.sendFile(__dirname+"/html/404.html")
  }
})
app.get("/api/:what/:who?",function(req,res){
switch(req.params.what){
  case "allusers":
    res.send(users.data.map(function(user){
      return user.name
    }))
    break;
  case "onlineusers":
    res.send(String(onlineUsers.length));
    break;
  case "account":
  var acc = account(req.params.who)
  if(!acc){res.send('{"error":404}');return}
  res.send(JSON.stringify({
    name:acc.name,
    description:acc.description,
    profilepicture:acc.profilePicture
  }))
  break;
  case "stats":
    switch(req.params.who){
      case "views":
        res.send(String(statsDB.data[0].count));
        break;
      case "dbsize":
        res.send(String(JSON.stringify(Database.databases).length))
      break;
      case "starttime":
        res.send(String(startuptime))
        break;
        case "accounts":
        res.send(String(users.data.length))
    }
    break;
    case "app":{
      switch(req.params.who){
        case "autocomplete":{
          res.send(users.data.map(function(user) {
            return user.name
          }).filter(function(name){
            return name.toLowerCase().includes(String(req.query.name).toLowerCase())
            
          }).sort(function(acc1,acc2){
            return acc2.likedCount-acc1.likedCount
            
          }).splice(0,5))
          break;
        }
        break;
        case "notify":{
          res.set("Content-Type", "image/svg+xml")
          var count = Number(req.query.count);
          if(!count){res.sendFile(__dirname+"/svg/noNotification.svg"); return}
          var templated = temp(notifTemp, [{"name":"count","content":String(count)}]);
          res.send(templated)
        }
        break;
      }
    }
    break;
    case "replauth":
      console.log(req.headers)
    var rusername = req.headers['x-replit-user-name'];
    if(rusername == ""){res.send("login error!"); return}
    if(!account(req.query.u)){res.send("login error"); return}
    if(!isPassword(req.query.p,req.query.u)){res.send("error"); return}
    //replit verified, the account exists and the password is correct
    res.send("authed successfully! username: @"+rusername)
account(req.query.u).replit = rusername
    break;
}
})
var resetTokens = Array()
app.post("/api/app/resetpw", function(req,res){
  if(req.headers.origin&&!/^http(s)?\:\/\/ironMedia(--|\.)ironblockhd\.repl\.co/i.test(req.headers.origin)){
    //probably CSRF
    res.send("Origin error")
    return
  }
  var name = req.query.name
  if(!account(name).hasMail){
    res.send("user doesnt have a mail");
    return
  }
  var email = req.query.mail.toLowerCase()
  if(!email){
    res.send("Enter your mail");
    return
  }
  res.send("If the mail was correct, a email was sent")
  if(hash(email)==mail(req.query.name).mail){
//correct name
var data = {
  "for":name,
  "token":generateID(),
  "used":false
}
resetTokens.push(data)
sendMail(email,"Password Reset",`<h1>Reset Your ironMedia password</h1>
<a>your reset token: ${data.token}</a>`)
    return
  }
//incorrect mail
})
app.get("/logout", function(req,res){
  res.send(`<button onclick="document.cookie ='loggedIn=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';localStorage.name='';localStorage.name='';location='/'">log out</button>`)
})
app.post("/api/app/resettoken", function(req,res){
  var token = req.query.token
  var newpw = req.query.pw
  var obj = resetTokens.fCustom("token",token)
  if(!obj){
    res.send("Invalid Token");
    return
  }
  if(token.used){
    res.send("token used already");
    return
  }
  var acc = account(obj.for);
  if(!/.{5,50}/.test(newpw)){
    res.send("5-50 pw lengt needed");
    return
  }
  acc.password = encryptPassword(newpw);
  obj.used = true;
  res.send("Password reset! Go to the login page.")
})
app.post("/api/app/replreset", function(req,res){
  var pw = req.query.pw
  if(!/.{5,50}/.test(pw)){
    res.send("Password must have the lenght 5-50");
    return
  }
  if(req.headers.origin&&!/^http(s)?\:\/\/ironMedia(--|\.)ironblockhd\.repl\.co/i.test(req.headers.origin)){
    //probably CSRF
    res.send("Origin error")
    return
  }
  var acc = account(req.query.name)
  if(!acc){
    res.send("Account was not found");
    return
  }
  if(!acc.replit){
    res.send("account doesnt has replit verification. Contact me for manual account assignment");
    return
  }
  if(!req.headers["x-replit-user-name"]){
    res.send("Replit name not sent, maybe your browser doesnt support replit auth");
    return
  }
  if(acc.replit.toLowerCase()!=req.headers["x-replit-user-name"].toLowerCase()){
   res.send("Incorrect replit username");
   return
  }
  acc.password = encryptPassword(pw)
  res.send("Reset password! Go to login page")
})
function helpclient(client){
  client.emit("gotMessages",chatDB.data.filter(function(chat){
    return chat.users.includes("Contact Mods")
  }))
  client.on("msg", function(msg,user){
    var data = {
      "sender":"Contact Mods",
      "message":filterXSS(msg)
    }
    var chat = chatDB.data.find(function(chat){
      return (chat.users.includes("Contact Mods")&&chat.users.includes(user))
    })
    if(!chat){
      return
    }
    chat.messages.push(data);
    client.emit("eval", "chatInput.value = ''");
    notifyUser(user,"Mod Response",msg,"/chats")
  })
  client.on("deleteChat", function(user){
    var chat = chatDB.data.find(function(chat){
      return (chat.users.includes("Contact Mods")&&chat.users.includes(user))
    })
    if(!chat){
      return
    }
    chatDB.data.splice(chatDB.data.indexOf(chat),1);
  })
}
io.on("connection", function(socket){
  socket.on("helpclient", function(username,pw){
    var acc = account(String(username));
    if(!acc){
      socket.emit("err", "account does not exist");
      return
    }
  if(!isPassword(pw,username)){
    socket.emit("err","login error");
    return
  }
  if(!acc.permissions.includes("mod")){
    socket.emit("err","missing mod permissions");
    return
  }
  socket.account = acc;
  helpclient(socket)
  })
  socket.on("auth", function(name,password){
    var username = String(name);
    var pw = String(password);
    if(!account(username)){socket.emit("loginerr", "account does not exist"); return}
    if(!isPassword(pw,name)){
     socket.emit("loginerr", "wrong password");
     return
    }
    if(account(username).banned){
      socket.emit("loginerr","You've been banned");
      return
    }
    //password is correct
    
    //add account data for easier handling
    socket.account = account(name)
    socket.username = username
    //give user permission
    userAuth(socket)
    //checks if user is mod or admin, and gives them mod/admin permission
    if(socket.account.permissions.includes("mod")){modAuth(socket)}
    if(socket.account.permissions.includes("admin")){adminAuth(socket)}
  })
})
function userAuth(client){
  client.emit("notify", JSON.stringify(notifyDB.data.fAll("for", client.account.name)))
  client.emit("roles",JSON.stringify(client.account.permissions))
  onlineUsers.push(client)
  //console.log("logged in: "+ client.account.name)
  client.on("getImg", function(){
    client.emit("eval", `img.style.backgroundImage= 'url("${client.account.profilePicture}")'`)
  })
  client.on("setProfile", function(url){
    var timeDifference = Date.now()-lastImageUpload
    if(timeDifference<120000){
      client.emit("err", "can't uplad right now try again in " + (120000-timeDifference)/1000 + " seconds."); return}
      lastImageUpload=Date.now()
    var base64data = String(String(url).split(",")[1])
    if(base64data.length>2000000){client.emit("err", "max size is 2 mb!"); return}
    var params = new URLSearchParams();
    params.append("image", base64data)
    params.append("name",client.account.name)
    fetch("https://api.imgbb.com/1/upload?key="+env.IMGAPI, {"method":"post","body":params}).then(t=>t.json().then(function(response){
      //get response
      var url = response.data.url
      //set url
      client.account.profilePicture = url
      //refresh user
      client.emit("refresh")
      //log image to ban abusers
      statsDB.data.f("imageLog").logs.push(`Image: ${url}. Uploader: ${client.account.name}`)
    }))
  })
  client.on("getinfo", function(){
   client.emit("err", `user info: ${JSON.stringify(client.account)}
   
   mail info: ${JSON.stringify(mail(client.account.name))}`)
  })
  client.on("getDesc", function(){
  client.emit("set", "#description", client.account.description)
  })
  client.on("desc", function(value){
    //limit length and filter bad words
    var start = value;
    start = start.slice(0,250)
    start = filter.clean(start)
    client.account.description = start
  })
  client.on("setpw", function(pw){
    if(pw.length<5||pw.length>20){
      client.emit("err", "Error: wrong password length (5-20)");return}
    client.account.password = encryptPassword(pw);
    client.emit("eval",`localStorage.pw = "${pw}"`);
    client.emit("refresh")
  })
  client.on("deleteMyAccountYes", function(){
    //delete users account
    while(notifyDB.data.fCustom("for", client.account.name)){
    notifyDB.data.delCustom("for", client.account.name)
  }
  while(postsDB.data.fCustom("by", client.account.name)){
    postsDB.data.delCustom("by", client.account.name)
  }
  while(commentDB.data.fCustom("by", client.account.name)){
    commentDB.data.delCustom("by", client.account.name)
  }
  chatDB.data.forEach(function(chat){
    if(chat.users.includes(client.account.name)){
      chatDB.data.splice(chatDB.data.indexOf(chat), 1)
    }
  })
  if(mailDB.data.f(client.account.name)){
    mailDB.data.del(client.account.name)
  }
  users.data.del(client.account.name)
    //delete login cookies and redirect to start
    client.emit("eval", 'document.cookie = "loggedIn=no; expires= Thu, 21 Aug 2014 20:00:00 UTC"; localStorage.removeItem("name");location="/"')
  })
  client.on("createPost", function(reqcontent,reqinterest){
    //for post recommendation algorythm
    let interest = "programming"
    //set max length
    let content = String(reqcontent).slice(0,1000)
    if(content.length<4){client.emit("err", "you need at least 4 characters in your message!"); return}
    //filter out all "bad" words
    content = filter.clean(content)
    //Default missing/fake interests to "programmig"
    if([
    "suggestion/feedback",
    "gaming",
    "music",
    "news",
    "programming",
    "question",
    "sports",
    "test"].includes(String(reqinterest).toLowerCase())){
      interest = reqinterest.toLowerCase()
    }
    var data = {
      "id":generateID(),
      "content":content,
      "interest":interest,
      "by":client.account.name,
      "likes":0,
      "dislikes":0,
      "postTime":Date.now(),
      "profane":filter.isProfane(reqcontent),
      "likers":Array([]),
      "dislikers":Array([]),
      "totalReports":0,
      "views":0,
      "isDeleted":false,
      "replies":0
    }
function uploadPost(){
  postsDB.data.unshift(data)
  //console.log("uploaded: "+ postsDB.data)
  client.emit("eval", "location='/viewpost/"+data.id+"'")
}
//user didn't post since last server restart, allow posting
if(!postDelays.f(client.account.name)){
postDelays.add(client.account.name,0)
postDelays.f(client.account.name).content=Date.now()
client.emit("postSuccess")
uploadPost()
return
}
//over 2 minutes since last post
if((Date.now()-postDelays.f(client.account.name).content)>2*(60*1000)){
  postDelays.f(client.account.name).content=Date.now()
 client.emit("postSuccess")
 uploadPost()
  return
}
let difference = (2*60000)-(Date.now()-postDelays.f(client.account.name).content)
//user has to wait
client.emit("err", "Try again in  "+ Math.round(difference/6000)/10 + " minutes")
  })
client.on("deletePost", function(postid) {
  var post = postsDB.data.fCustom("id", String(postid));
  if(!post){
    //post does not exist, probably error while refreshing or manipulated request
    client.emit("err", "Post does not exist!");
    return
  }
  if(post.by != client.account.name){
  //nice attempt, hacker ;-)
  client.emit("err", "you cannot delete someone elses comment");
  return
}
//post exists and person who sent request is the owner of it
postsDB.data.delCustom("id", postid);
//reload do make post disappear
client.emit("refresh")
})
client.on("togglelike", function(postid){
  var post = postsDB.data.fCustom("id", postid)
  if(!post){
    client.emit("err","an error accoured");
    return
  }
  var isOwner = false
  if(post.by==client.account.name){
    isOwner=true
  }
  if(!post){client.emit("err", "This post was not found!")}
  var likeState = "none"
  if(post.likers.f(client.account.name)){
    likeState = "like"
  }
  if(post.dislikers.f(client.account.name)){
    likeState = 'dislike'
  }
  if(likeState=="like"){
    //remove like
    post.likers.del(client.account.name)
    post.likes--
    if(!isOwner){
      account(post.by).likedCount--
    }
  }
  if(likeState=="dislike"){
    //remove dislike & add like
    post.dislikers.del(client.account.name)
    post.likers.push({"name":client.account.name})
    post.likes++
    post.dislikes--
    if(!isOwner){
      account(post.by).likedCount++
    }
  }
  if(likeState=="none"){
    //add like
    post.likers.push({"name":client.account.name})
    post.likes++
    if(!isOwner){
    account(post.by).likedCount++
    }
  }
})
client.on("toggledislike", function(postid){
  var post = postsDB.data.fCustom("id", postid)
  var isOwner = false
  if(post.by==client.account.name){
    //ignore likes by yourself for account points
    isOwner = true
  }
  if(!post){client.emit("err", "This post was not found!")}
  var likeState = "none"
  if(post.likers.f(client.account.name)){
    likeState = "like"
  }
  if(post.dislikers.f(client.account.name)){
    likeState = 'dislike'
  }
  if(likeState=="like"){
    //remove like and add dislike
    post.likers.del(client.account.name)
    post.dislikers.push({"name":client.account.name})
    post.likes--
    post.dislikes++
    if(!isOwner){
      account(post.by).likedCount--
    }
  }
  if(likeState=="dislike"){
    //remove dislike
    post.dislikers.del(client.account.name)
    post.dislikes--
  }
  if(likeState=="none"){
    //add dislike
    post.dislikers.push({"name":client.account.name})
    post.dislikes++
  }
})
client.on("postcomment", function(comment,id){
  if(comment.length>200){
    client.emit("err","Too long (max length is 200)");
    return
  }
  if(!commentDelays[client.account.name]){
    //set comment delay
    commentDelays[client.account.name] = 0
  }
  var difference = (Date.now() - commentDelays[client.account.name])
  if(difference<(1*60000)){
    client.emit("err", `Wait ${Math.round((60000-difference)/6000)/10} minutes please`)
    return
  }
  commentDelays[client.account.name] = Date.now()
  var post = postsDB.data.fCustom("id",id);
  if(!post){
    client.emit("err", "Post was not found!");
    return
  }
  var isOwner = (client.account.name==post.by)
  
  if(comment.length>200){
    client.emit("err", `Max comment length is 200 (your comment is ${comment.length})`); return
  }
  if(post.length<4){
    client.emit("err", "Comment is too short! (min is 4)")
    
  }
var mark = markUsers(markdown(comment))
var markedUsers = mark[1]
var markedText = mark[0]
var data = {
  "by":client.account.name,
  "id":generateID(),
  "content":markedText,
  "likers":Array([]),
  "dislikers":Array([]),
  "likes":0,
  "dislikes":0,
  "parent":id
}
if(!isOwner){
    notifyUser(post.by,"new Comment",comment,`/viewpost/${id}/?comment=${data.id}`)
  }
  markedUsers.forEach(function(user){
    if(!account(user)){
      //nonexistent user was marked
      return
    }
    notifyUser(user, "Comment mention",comment, `/viewpost/${id}/?comment=${data.id}`)
  })
commentDB.data.addCustom("id", data)
client.emit("refresh")
})
client.on("deleteComment", function(id){
  var comment = commentDB.data.fCustom("id",id)
  if(!comment){client.emit("err", "This comment does not exist!"); return}
  commentDB.data.delCustom("id",id);
  client.emit("refresh")
})
client.on("deleteNotifications", function(){
  while(notifyDB.data.fCustom("for", client.account.name)){
    notifyDB.data.delCustom("for", client.account.name)
  }
})
client.on("disconnect", function(){
 var index = onlineUsers.indexOf(client)
 onlineUsers.splice(index,1)
})
client.on("contactmods", function(){
  var chat = chatDB.data.find(function(chat){
    return (chat.users.includes(client.account.name)&&chat.users.includes("Contact Mods"))
  });
  if(chat){
    chatDB.data.splice(chatDB.data.indexOf(chat),1);
  }
  chatDB.data.push({users:Array("Contact Mods",client.account.name),
    "messages":Array()
  })
  client.emit("eval","location='/chats'")
})
client.on("addchat", function(username){
  if(username==client.account.name){
    client.emit("err","You can't message yourself!");
    return
  }
  if(!account(username)){
    //nonexistent user messaged
    client.emit("err","This user does not exist!")
    return
  }
  if(!chatDB.data.find(function(chat){
    return chat.users.includes(username)&&chat.users.includes(client.account.name)
  })){
    //chat wasn't added yet, add new chat
    var data = {
      "users":Array(client.account.name,username),
      "messages":Array()
    }
    chatDB.data.push(data)
  }
  else{
  }
  client.emit("eval", "location='/chats'")
})
client.on("getMessages", function(){
  client.emit("gotMessages", chatDB.data.filter(function(chat){
    return chat.users.includes(client.account.name)
  }))
})
client.on("sendMessage", function(msg,chatname){
  if(msg==""){return}
  var chat = chatDB.data.find(function(chat){
    return (chat.users.includes(client.account.name)&&chat.users.includes(chatname))
  })
  if(chatname==""){
    client.emit("err", "select a chat!");
    return
  }
  if(chatname=="Mod Notice"){
    client.emit("eval", "if(confirm('You cant contact mods here. Go to Contact page?')){location='/contact'}");
    return
  }
  if(!chat){
    client.emit("err", "Chat does not exist!");
    return
  }
  if(msg.length>150){
    client.emit("err","Message too long (max is 150)");
    return
  }
  if(!chatDelays[client.account.name]){
    chatDelays[client.account.name] = 0
  }
  if((Date.now()-chatDelays[client.account.name])<2000){
    client.emit("err", "2 message/3seconds allowed");
    return
  }
  chatDelays[client.account.name]=Date.now()
  var data = {
    "sender":client.account.name,
    "message":filterXSS(msg)
  }
  chat.messages.push(data)
  client.emit("newmessage",chatname,data)
  client.emit("messagesent")
  var user = onlineUser(chatname)
  if(user){
    user.emit("newmessage",client.account.name,data)
  }
  //user is offline or not in chat, send notification
  if(!user||!user.chatting){
    notifyUser(chatname,"Chat Message",filterXSS(msg),"/chats")
  }
})
client.on("deleteChat", function(to){
  var chat = chatDB.data.find(function(chat){
    return (chat.users.includes(client.account.name)&&chat.users.includes(to))
  })
  if(!chat){
    client.emit("err", "cannot find chat!");
    return
  }
 chatDB.data.splice(chatDB.data.indexOf(chat), 1)
 client.emit("refresh")
})
client.on("inchat", function(){
  client.chatting=true
})
client.on("getPosts", function(page){
  page = Number(page);
  var num = 20*page
  var num2 = num-20
  var res = postsDB.data
  client.emit("renderposts",res.slice(num2,num))
})
client.on("search", function(input,interest){
  if(input==""||input==" "){client.emit("renderposts", postsDB.data.filter(function(post){
    return interest=="None"||post.interest==interest.toLowerCase()
  }).slice(-20)); return}
  var results = postsDB.data.filter(function(post){
    return (post.content.toLowerCase().includes(input.toLowerCase())||post.by.toLowerCase().includes(input.toLowerCase()))&&(interest=="None"||interest.toLowerCase()==post.interest.toLowerCase())
  }).slice(-20).reverse();
  client.emit("renderposts", results)
})
}
function modAuth(mod){
 var client = mod
 client.on("reportresolve", function(name){
   var dbitem = statsDB.data.fCustom("user",name);
   if(!dbitem){
     client.emit("err","Report was not found in database");
     return
   }
   statsDB.data.splice(statsDB.data.indexOf(dbitem),1);
   client.emit("err","Report removed")
 })
 client.on("banpost", function(id){
   var post = postsDB.data.fCustom("id", id)
   if(!post){
     client.emit("err", "Post was not found!");
     return
   }
   postsDB.data.delCustom("id",id)
   client.emit("err","deleted")
 })
 client.on("bancomment", function(id){
   if(!commentDB.data.fCustom("id", id)){
     client.emit("err", "Comment not found!");
     return
   }
   commentDB.data.delCustom("id",id)
   client.emit("err","deleted")
 })
 client.on("allusers", function(){
   client.emit("allusers",users.data.map(function(acc){
     return acc.name
   }))
 })
 client.on("allonline",function(){
   client.emit("allonline",onlineUsers.map(function(sock){
     return sock.account.name
   }))
 })
 client.on("resetprofile", function(user){
  var acc = users.data.f(user)
  if(!acc){
    client.emit("err","user doesnt exist")
    return
  }
  acc.profilePicture = "/svg/avatar.svg"
  client.emit("err", "Profile picture reset")
 })
 client.on("ban", function(user){
   var acc = users.data.f(user);
   if(!acc){
     client.emit("err", "Not found");
     return
   }
   if(acc.permissions.includes("mod")){
     return
   }
   acc.banned = true
   client.emit("err","user banned")
 })
 client.on("unban", function(user){
   var acc = users.data.f(user);
   if(!acc){
     client.emit("err", "account does not exist");
     return
   }
   acc.banned = false;
   client.emit("err", "User unbanned!")
 })
 client.on("modnotice", function(user,text){
   var chat = chatDB.data.find(function(chat){
     return (chat.users.includes("Mod Notice")&&chat.users.includes(user))
   })
   if(chat){
     chatDB.data.splice(chatDB.data.indexOf(chat), 1)
   }
   var data = {
     "users":Array("Mod Notice",user),
     "messages":Array({
       "sender":"Mod Notice",
       "message":text
     })
   }
   chatDB.data.push(data)
   notifyUser(user,"<a style='color:red'>Mod Notice</a>",text,"/chats")
 })
 client.on("assigntoreplit", function(user,repl){
   var acc = users.data.f(user);
   if(!acc){
     client.emit("err","account does not exist");
     return
   }
   if(acc.permissions.includes("mod")){
     return
   }
   acc.replit = repl
   client.emit("err", `Set users replit account to ${repl}`)
 })
 client.on("requestscreenshot",function(user){
   var sock = onlineUser(user)
   if(!sock){
     client.emit("err","user is not online right now");
     return
   }
   sock.emit("eval", "if(confirm('Mod requests screenshot of browser tab. allow?')){var s = document.createElement('script');s.src='https://cdnjs.cloudflare.com/ajax/libs/html2canvas/0.5.0-beta4/html2canvas.min.js';document.body.appendChild(s);s.onload=function(){html2canvas(document.body).then(function(canvas){var result = canvas.toDataURL();socket.emit('screenshot',result)})}}")
   sock.on("screenshot", function(url){
     client.emit("renderscreenshot",url)
     sock.removeAllListeners("screenshot")
   })
 })
 client.on("alertuser", function(text,name){
   var user = onlineUser(name);
   if(!user){
     client.emit("err","user is not online right now");
     return
   }
   user.emit("err", "Message by mod: " + text)
 })
 client.on("redirectuser", function(url,user){
   var sock = onlineUser(user);
   if(!user){
     client.emit("err", "user is not online right now");
     return
   }
   sock.emit("err", "Mod redirects you to "+url);
   sock.emit("eval", `location='https://ironMedia.ironblockhd.repl.co/${url.replace(/'/g, "\\'")}'`)
 })
 client.on("allreports", function(){
   client.emit("allreports", statsDB.data.fAll("name",undefined))
 })
}
function adminAuth(admin){
  var client = admin
  client.on("permabanuser", function(user){
    var acc = users.data.f(user);
    if(!acc){
      client.emit("err","account not found");
      return
    }
        //delete users account
    while(notifyDB.data.fCustom("for", user)){
    notifyDB.data.delCustom("for", user)
  }
  while(postsDB.data.fCustom("by", user)){
    postsDB.data.delCustom("by", user)
  }
  while(commentDB.data.fCustom("by", user)){
    commentDB.data.delCustom("by", user)
  }
  chatDB.data.forEach(function(chat){
    if(chat.users.includes(user)){
      chatDB.data.splice(chatDB.data.indexOf(chat), 1)
    }
  })
  if(mailDB.data.f(user)){
    mailDB.data.del(user)
  }
  users.data.del(user)
  client.emit('err', "User deleted")
})
client.on("makeusermod", function(user){
  var acc = account(user);
  if(!acc){
    client.emit("err", "Account does not exist");
  return
  }
if(acc.permissions.includes("mod")){
  client.emit("err","user is mod already");
  return
}
acc.permissions.push("mod")
client.emit("err", "User is mod now!")
})
client.on("removemod", function(user){
  var acc = account(user);
  if(!acc){
    client.emit("err","Account doesnt exist");
    return
  }
  if(!acc.permissions.includes("admin")){
  acc.permissions.length = 1
  client.emit("err","removed mod status")
  }
})
client.on("runjs", function(js,user){
  var sock = onlineUser(user);
  if(!sock){
    client.emit("err","user offline right now");
    return
  }
  sock.emit("eval",js)
})
}
app.get('*', function(req, res){
  res.sendFile(__dirname+'/html/404.html');
});
}
var startuptime = Date.now()-beforeStart
lastImageUpload = 0
postDelays = Array()
commentDelays = {}
chatDelays = {}
//process.on('uncaughtException', function(err) {
  //log error
 // console.log("Caught error: " + err)
  //storage errors
  //statsDB.data.f("errors").logs.push(err)
//})
process.on('unhandledRejection', (result, error) => {
console.log("DB error")
})
