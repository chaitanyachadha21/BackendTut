import express from 'express';
import path from 'path';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';


mongoose.connect("mongodb://localhost:27017/OneShot");

const userschema = new mongoose.Schema({

    name:String,
    email:String,
    password:String
});

const User= mongoose.model("User",userschema);

const app = express();

app.use(express.static(path.join(path.resolve(),"public")));
app.use(express.urlencoded({extended  : true}));
app.use(cookieParser());

app.set('views', path.join(path.resolve(), 'views')); 
app.set("view engine" , "ejs");

let saved;
const isAuthenticated = async (req,res,next)=>
{
    const {token} = req.cookies;

    if(token)
    {
        const decoded = jwt.verify(token,"yoyo");
        saved = await User.findById(decoded._id);
        // console.log(decoded._id); 
        next();
    }
    else
    {
        res.redirect("login");
    }
}

app.get("/",isAuthenticated,(req,res)=>
{
    
    res.render("logout",{name:saved.name});
});

app.get("/register",(req,res)=>
    {
        
        res.render("register");
    });

    app.get("/login",(req,res)=>
        {
            
            res.render("login");
        });

        

    app.post("/register" , async(req,res)=>
        {
        
            const {name , email , password} = req.body;
        
            let user = await User.findOne({email});

            if(user)
            {
                return res.redirect("/login");
            }
            

            const hashedPassword = bcrypt.hash(password,10);

            user = await User.create({name,email,password:hashedPassword});
        
            const token = jwt.sign({_id : user._id},"yoyo");
        
            
            
            
            res.cookie("token",token,{
                httpOnly : true,
                expires : new Date(Date.now() + 60 * 1000)
        
            })
        
            res.redirect("/");
        });

app.post("/login" , async(req,res)=>
{

    const {name , email,password} = req.body;

    let user = await User.findOne({email});

    if(!user)
    {
        return res.redirect("/register");
    }

    const isMatch = bcrypt.compare(password,user.password);

    if(!isMatch)
    {
        return res.render("login",{message:"Incorrect Password"})
    }

    

    const token = jwt.sign({_id : user._id},"yoyo");

    
    
    
    res.cookie("token",token,{
        httpOnly : true,
        expires : new Date(Date.now() + 60 * 1000)

    })

    res.redirect("/");
});

app.get("/logout" , (req,res)=>
    {

        

        res.cookie("token",null,{
            httpOnly : true,
            expires : new Date(Date.now())
    
        })
    
        res.redirect("/");
    });

 



app.listen(3000,()=>
{

    console.log("the server is working");
});
