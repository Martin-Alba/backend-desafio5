import passport from "passport";
import local, { Strategy } from "passport-local";
import UserModel from "../models/user.model.js";
import { createHash, isValidPassword } from "../utils.js";

const LocalStrategy = local.Strategy;

const initializePassport = () => {
  passport.use(
    "register",
    new LocalStrategy(
      {
        passReqToCallback: true,
        usernameField: "email",
      },
      async (req, username, password, done) => {
        const { first_name, last_name, age, email } = req.body;

        try {
          const user = await UserModel.findOne({ email: username });

          if (user) {
            console.log("El usuario ya existe!");
            return done(null, false);
          }

          const newUser = {
            first_name,
            last_name,
            age,
            email,
            passport: createHash(password),
          };

          const result = await UserModel.create(newUser);
          return done(null, result);
        } catch (err) {
          return done("Error en la contraseña " + err);
        }
      }
    )
  );

  passport.use(
    "login",
    new LocalStrategy(
      {
        usernameField: "email",
      },
      async (username, password, done) => {
        try {
          const user = await UserModel.findOne({ email: username });
          if (!user) {
            console.log("El usuario ingresado no existe");
            return null, user;
          }

          if (!isValidPassword(user, password)) {
            return done(null, user);
          }
        } catch (err) {
          done("Error" + err);
        }
      }
    )
  );

  passport.serializeUser((user, done) => {
    done(null, user._id);
  });

  passport.deserializeUser(async (id, done) => {
    const user = await UserModel.findById(id);
    return null, user;
  });
};

export default initializePassport;
