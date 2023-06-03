import { Router } from "express";
import productModel from "../models/product.model.js";
import productManager from "../manager/products.manager.js";

const router = Router();

router.get("/", async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const sort = req.query.sort === "desc" ? -1 : 1;
  const query = req.query.query || "";

  const filter = query
    ? {
        $or: [
          { title: { $regex: query, $options: "i" } },
          { category: { $regex: query, $options: "i" } },
        ],
      }
    : {};

  const options = {
    page,
    limit,
    sort: { price: sort },
    lean: true,
  };

  try {
    const products = await productModel.paginate(filter, options);

    const prevPage = page > 1 ? page - 1 : null;
    const nextPage = page < products.totalPages ? page + 1 : null;

    const data = {
      products,
      query,
      limit,
      sort,
      prevPage,
      nextPage,
    };

    Object.assign(data, req.query);

    res.status(201).render("products", data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ err: "Ocurrió un error al obtener los productos" });
  }
});

router.get("/create", async (req, res) => {
  res.render("create");
});

router.post("/", async (req, res) => {
  try {
    const product = await productManager.createProduct(req.body);
    res.redirect("/api/products");
  } catch (err) {
    console.error(err);
    res.status(500).json({ err: "Ocurrió un error al ingresar el producto" });
  }
});


export default router;