import { Router } from "express";
import passport from "passport";

const router = Router();

router.get("/register", async (req, res) => {
  res.render("sessions/register");
});

router.post(
  "/register",
  passport.authenticate("register", {
    failureRedirect: "/session/failureRegister",
  }),
  async (req, res) => {
    res.redirect("/api/session/login");
  }
);

router.get("/failureRegister", (req, res) => {
  res.send({ error: "failed!" });
});

router.get("/login", async (req, res) => {
  res.render("sessions/login");
});

router.post(
  "/login",
  passport.authenticate("login", { failureRedirect: "/session/failLogin" }),
  async (req, res) => {
    if (!req.user) {
      return res
        .status(400)
        .send({ status: "error", error: "Invalid credentials" });
    }
    req.session.user = {
      first_name: req.user.first_name,
      last_name: req.user.last_name,
      email: req.user.email,
      age: req.user.age,
    };
    res.redirect("/api/products");
  }
);

router.get("/failLogin", async (req, res) => {
  res.send({ error: "Fail in login" });
});

router.get("/logout", async (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      res.status(500).render("errors/base", { error: err });
    } else {
      res.redirect("/api/session/login");
    }
  });
});


export default router