import mongoose from "mongoose";
import productModel from "../models/product.model.js";

mongoose.connect("mongodb://localhost:27017", { dbName: "Pre-Entrega" });

const db = mongoose.connection;
db.on("error", console.error.bind(console, "Error de conexion a la DB"));
db.once("open", () => {
  console.log("DB connected!");
});

const productManager = {
  async createProduct(productData) {
    const {
      title,
      description,
      price,
      status,
      code,
      stock,
      category,
      thumbnail,
    } = productData;

    const codeExists = await productModel.exists({ code });

    if (codeExists) {
      throw new Error("El codigo del producto ya existe");
    }

    const product = new productModel({
      title,
      description,
      price,
      status,
      code,
      stock,
      category,
      thumbnail,
    });

    await product.save();
    return product;
  },

  async getProducts() {
    const products = await productModel.find();
    return products;
  },

  async updateProduct(productId, newData) {
    const product = await productModel.findByIdAndUpdate(productId, newData, {
      new: true,
    });
    return product;
  },

  async deleteProduct(productId) {
    const product = await productModel.findByIdAndDelete(productId);
    return product;
  },
};

export default productManager;