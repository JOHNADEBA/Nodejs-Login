const express = require('express')
const app = express()
const { pool } = require('./dbConfig')
const bcrypt = require('bcrypt')
const session = require('express-session')
const flash = require('express-flash')
const passport = require('passport')

const initializePassport = require('./passportConfig')

initializePassport(passport);


const PORT = process.env.PORT || 8000

app.set('view engine', 'ejs')
app.use(express.urlencoded({extended: false}))

app.use(session({
    secret: 'secret',

    resave: false,

    saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())

app.use(flash())

app.get('/', (req, res)=>{
    res.render('index');
})

app.get('/register', checkAuthenticated, (req, res)=>{
    res.render('register')
})

app.get('/login', checkAuthenticated, (req, res)=>{
    res.render('login')
})

app.get('/logout', (req, res)=>{
    req.logOut();
    req.flash('sucess', 'You are sucessfully logged out')
    res.redirect('/login')
})

app.get('/home', checkNotAuthenticated, (req, res)=>{
    res.render('home', { user: req.user.name })
})

app.post('/register', async(req, res)=>{
    const { name, email, password, password2 } = req.body
    console.log({name, email, password, password2})

    let errors = [];
    if( !name || !email || !password || !password2 ){
        errors.push({message: 'Kindly enter all fields'})
    };
    if(password != password2){
        errors.push({message: "Password don't match"})
    };
    if(password.length < 6 ){
        errors.push({message: "Password must be more than 5 characters"})
    };
    if(errors.length > 0){
        res.render('register', {errors})
    }
    else{
        let hashPassword = await bcrypt.hash(password, 10)
        console.log(hashPassword)

        pool.query(
            `SELECT * FROM users
            WHERE email = $1`,
            [email],
            (err, results) =>{
                if (err){
                    throw err;
                }
                console.log(results.rows)

                if(results.rows.length > 0 ){
                    errors.push({message: 'Email already exist'})
                    res.render('register', {errors})
                }
                else{
                    pool.query(
                        `INSERT INTO users(name, email, password)
                        VALUES ($1, $2, $3)
                        RETURNING id, password`,
                        [name, email, hashPassword],
                        (err, results) =>{
                            if (err){
                                throw err;
                            }
                            console.log(results.rows)
                        req.flash('sucess', 'Registration successful, Please Log In')
                        res.redirect('/login')
                        }
                    )
                }
            }
        )
    }
})

app.post('/login', passport.authenticate('local',{
    successRedirect: '/home',
    failureRedirect: 'login',
    failureFlash: true
}))

function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect('/home')
    }
    next()
}

function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next()
    }
   res.redirect('/login')
}


app.listen(PORT, ()=>console.log(PORT))
