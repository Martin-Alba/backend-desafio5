import { Router } from "express";
import cartModel from "../models/carts.model.js";
import productModel from "../models/product.model.js";
import mongoose from "mongoose";

const router = Router();
const { ObjectId } = mongoose.Types;

// Ver carts
router.get("/", async (req, res) => {
  try {
    const carts = await cartModel
      .find()
      .populate("products.productId")
      .lean()
      .exec();

    res.render("carts", { carts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ err: "Ocurrió un error al obtener los carritos" });
  }
});

// Crear cart
router.post("/", async (req, res) => {
  try {
    const newCart = await cartModel.create({});
    res.json({ newCart });
  } catch (err) {
    console.error(err);
    res.status(500).json({ err: "Ocurrio un error al crear el carrito" });
  }
});

// Agregar producto al carrito
router.post("/add-to-cart", async (req, res) => {
  const { productId } = req.body;

  try {
    let cart = await cartModel.findOne();

    if (!cart) {
      cart = await cartModel.create({ products: [] });
    }

    const existingProductIndex = cart.products.findIndex(
      (item) => item.productId && item.productId.toString() === productId
    );

    if (existingProductIndex !== -1) {
      // Si el producto ya está en el carrito, incrementar la cantidad
      cart.products[existingProductIndex].quantity++;
    } else {
      // Si el producto no está en el carrito, agregarlo con cantidad 1
      cart.products.push({ productId, quantity: 1 });
    }

    await cart.save();
    res.redirect("/api/products");
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ error: "Ocurrió un error al agregar el producto al carrito" });
  }
});

router.post("/remove-from-cart", async (req, res) => {
  const { productId } = req.body;

  try {
    const cart = await cartModel.findOne();

    if (!cart) {
      throw new Error("El carrito no existe");
    }

    // Filtrar el producto que se desea eliminar del carrito
    cart.products = cart.products.filter(
      (item) => item.productId.toString() !== productId
    );

    await cart.save();
    res.redirect("/api/products");
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ error: "Ocurrió un error al eliminar el producto del carrito" });
  }
});

router.post("/update-quantity", async (req, res) => {
  const { cartId, productId, quantity } = req.body;

  try {
    const cart = await cartModel.findById(cartId);

    if (!cart) {
      throw new Error("El carrito no existe");
    }

    const productIndex = cart.products.findIndex(
      (item) => item.productId.toString() === productId
    );

    if (productIndex !== -1) {
      // Actualizar la cantidad del producto en el carrito
      cart.products[productIndex].quantity = quantity;
      await cart.save();
    }

    res.redirect("/api/carts"); // Redirigir a la página de carritos después de la actualización
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ocurrió un error al actualizar la cantidad del producto" });
  }
});

export default router;