const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

module.exports = {
  register: async (req, res) => {
    try {
      const { email, username, password, passwordVerify } = req.body; //1. get all fields from body

      // validation

      if (!email || !password || !passwordVerify || !username)
        return res.status(400).json({
          success: 0,
          message: "Please enter all required fields.",
        }); //2a. if some field doesnt exist, send 400 bad request

      if (password.length < 6)
        return res.status(400).json({
          success: 0,
          message: "Please enter a password of at least 6 characters.",
        }); //2b. if passwordlength < 6, send 400 bad request

      if (password !== passwordVerify)
        return res.status(400).json({
          success: 0,
          message: "Please enter the same password twice.",
        }); //2c. if password != passwordVerify, send 400 bad request

      const existingEmail = await User.findOne({ email });
      if (existingEmail)
        return res.status(400).json({
          success: 0,
          message: "An account with this email already exists.",
        }); //2d. if existingEmail, send 400 bad request

      const existingUser = await User.findOne({ username });
      if (existingUser)
        return res.status(400).json({
          success: 0,
          message: "An account with this username already exists.",
        }); //2e. if existingUser, send 400 bad request

      //3. Hash the password
      // Salt is a random string which is generated in order for the password to be hashed

      const salt = await bcrypt.genSalt(); //generate salt (random string)
      const passwordHash = await bcrypt.hash(password, salt); //hash the password

      // Save the user

      const newUser = new User({
        email,
        passwordHash,
        username,
      }); //4. create a document 
      const savedUser = await newUser.save(); //5. save to the database

      // Log the user in
      //6. sign the token

      const token = jwt.sign(
        {
          user: savedUser._id,
        },
        process.env.JWT_SECRET
      );

      //7. send the token in a HTTP only cookie (We use cookies to store the JWT so the client doesn’t have to manually send it with every request)

      res
        .cookie("token", token, {
          httpOnly: true,
        }) //makes it inaccessible to JavaScript in the browser (for security, to help prevent XSS attacks).
        .json({ success: 1, message: "User created" });
    } catch (err) {
      console.error(err);
      res.status(500).send(); 
    }
  },

  login: async (req, res) => {
    try {
      const { password, username } = req.body; //1. get all fields from body

      if (!username || !password)
        return res
          .status(400)
          .json({ success: 0, message: "Please enter all required fields." });
           //2a. if some field doesnt exist, send 400 bad request

      // check if the user exists

      const existingUser = await User.findOne({ username });

      // if not return 401

      if (!existingUser)
        return res
          .status(401)
          .json({ success: 0, message: "Wrong username or password" });

       //2b. if !existingUser, send 401 bad request (wrong username)

      //3. Else, compare the given password with the stored hashed password
      const passwordCorrect = await bcrypt.compare(
        password,
        existingUser.passwordHash
      ); 

      //4. if !passwordCorrect, send 401 bad request (wrong password)

      if (!passwordCorrect)
        return res
          .status(401)
          .json({ success: 0, message: "Wrong username or password" });

      const token = jwt.sign(
        {
          user: existingUser._id,
        },
        process.env.JWT_SECRET
      );  //5. sign the token

      res
        .cookie("token", token, {
          httpOnly: true,
        })
        .json({ success: 1, message: "Logged In Successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).send();
    } //6. send the token in a HTTP only cookie 
  },

  logout: (req, res) => {
    res
      .cookie("token", "", {
        httpOnly: true,
        expires: new Date(0),
      })
      .json({
        success: 1,
        message: "Logged Out",
      });
  },

  isLoggedIn: (req, res) => {
    try {
      const token = req.cookies.token;
      

      if (!token) return res.send(false);
      jwt.verify(token, process.env.JWT_SECRET);

      res.send(true);
    } catch (err) {
      res.send(false);
    }
  },

  getUserData: async (req, res) => {
    const user = await User.findById(req.user);

    // if not return 401
    if (!user)
      return res.status(401).json({ success: 0, message: "Unknown user" });

    return res.status(200).json({
      success: 1,
      data: {
        _id: user._id,
        username: user.username,
        email: user.email,
        description: user.description,
        color: user.color,
        numberOfQuestions: user.numberOfQuestions,
        numberOfAnswers: user.numberOfAnswers,
        numberOfLikes: user.numberOfLikes,
      },
    });
  },

  getUserDataById: async (req, res) => {
    const id = req.params.id;
    const user = await User.findById(id);

    // if not return 401
    if (!user)
      return res.status(401).json({ success: 0, message: "Unknown user" });

    return res.status(200).json({
      success: 1,
      data: {
        _id: user._id,
        username: user.username,
        email: user.email,
        description: user.description,
        color: user.color,
        numberOfQuestions: user.numberOfQuestions,
        numberOfAnswers: user.numberOfAnswers,
        numberOfLikes: user.numberOfLikes,
      },
    });
  },

  deleteUser: async (req, res) => {
    const user = await User.findByIdAndDelete(req.user);
    // if not return 401
    if (!user)
      return res.status(401).json({ success: 0, message: "Unknown user" });
    // logout
    return res
      .cookie("token", "", {
        httpOnly: true,
        expires: new Date(0),
      })
      .status(200)
      .json({
        success: 1,
        message: "User deleted successfully",
      });
  },

  updateUser: async (req, res) => {
    try {
      const user = await User.findById(req.user);
      let {
        email,
        username,
        description,
        color,
        oldPassword,
        password,
        passwordVerify,
      } = req.body;

      // validation
      if (!email) email = user.email;
      if (!username) username = user.username;
      if (!color) color = user.color;
      if (!description) description = user.description;
      if (!oldPassword) {
        return res.status(400).json({
          success: 0,
          message: "Please enter your password.",
        });
      }

      // Compare the given password with the stored hashed password
      const passwordCorrect = await bcrypt.compare(
        oldPassword,
        user.passwordHash
      );

      if (!passwordCorrect) {
        return res.status(400).json({ success: 0, message: "Wrong Password" });
      }

      // if the user wants to change his email we check if there is another account
      // with that email
      if (email !== user.email) {
        const existingEmail = await User.findOne({ email });
        if (existingEmail)
          return res.status(400).json({
            success: 0,
            message: "An account with this email already exists.",
          });
      }

      // if the user wants to change his username we check if there is another account
      // with that username
      if (username !== user.username) {
        const existingUser = await User.findOne({ username });
        if (existingUser)
          return res.status(400).json({
            success: 0,
            message: "An account with this username already exists.",
          });
      }

      if (password && !passwordVerify) {
        return res.status(400).json({
          success: 0,
          message: "Please enter the password verification",
        });
      }

      if (passwordVerify && !password) {
        return res.status(400).json({
          success: 0,
          message:
            "You've entered the password verification but not the password",
        });
      }

      if (password && passwordVerify) {
        // new password
        if (password.length < 6) {
          return res.status(400).json({
            success: 0,
            message: "Please enter a password of at least 6 characters.",
          });
        }

        if (password !== passwordVerify) {
          return res.status(400).json({
            success: 0,
            message: "Please enter the same password twice.",
          });
        }

        // Hash the password
        // Salt is a random string which is generated in order for the password to be hashed

        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password, salt);

        // find and update the user

        await User.findByIdAndUpdate(
          req.user,
          {
            email: email,
            passwordHash: passwordHash,
            username: username,
            color: color,
            description: description,
          },
          { useFindAndModify: false }
        );
      } else {
        // no new password
        await User.findByIdAndUpdate(
          req.user,
          {
            email: email,
            username: username,
            color: color,
            description: description,
          },
          { useFindAndModify: false }
        );
      }
      res.json({ success: 1, message: "User Updated Successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).send();
    }
  },
};
