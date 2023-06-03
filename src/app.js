import express from "express";
import mongoose from "mongoose";
import exphbs from "express-handlebars";
import bodyParser from "body-parser";
import path from "path";
import { fileURLToPath } from "url";
import productModel from "./models/product.model.js";
import productsRouter from "./routers/products.router.js";
import cartsRouter from "./routers/carts.router.js";
import sessionRouter from "./routers/session.router.js"

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const hbs = exphbs.create();
app.engine("handlebars", hbs.engine);
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "handlebars");
app.use(bodyParser.urlencoded({ extended: true }));

app.use("/api/products", productsRouter);
app.use("/api/carts", cartsRouter);
app.use("/api/session", sessionRouter)

// crear productos en DB
/* const main = async () => {
  await mongoose.connect("mongodb://localhost:27017", {
    dbName: "Desafio-5",
  });
  console.log("DB connected!");

  const products = await productModel.insertMany([
    {
      title: "Torta",
      description:
        "Torta rellena con dulce de leche y crema, bañana en chocolate.",
      price: 4999,
      status: true,
      code: "t0rt4ch0c0l4t3",
      stock: 10,
      category: "Dulces",
      thumbnail: [
        "https://images.pexels.com/photos/2067436/pexels-photo-2067436.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=1",
      ],
    },
    {
      title: "Bombas",
      description:
        "1 kg. de Bombas rellenas de dulce de leche bañadas en chocolate blanco/negro.",
      price: 3999,
      status: true,
      code: "b0mb45",
      stock: 15,
      category: "Dulces",
      thumbnail: [
        "https://instagram.frcu2-1.fna.fbcdn.net/v/t51.2885-15/125561619_157112369430010_5403147590968627900_n.jpg?stp=dst-jpg_e35_s640x640_sh0.08&_nc_ht=instagram.frcu2-1.fna.fbcdn.net&_nc_cat=110&_nc_ohc=7TF0NEbO-pgAX_5tjwz&edm=AP_V10EBAAAA&ccb=7-5&oh=00_AfAxpxD3z3-CXNv7JnV_SQOG1-0V-s_7fwiSN4awI_Aw_Q&oe=642771D5&_nc_sid=4f375e",
      ],
    },
    {
      title: "Tarta",
      description: "Tarta de frutilla y crema.",
      price: 2999,
      status: true,
      code: "t4rt4d3frut1ll4",
      stock: 5,
      category: "Dulces",
      thumbnail: [
        "https://images.pexels.com/photos/4686817/pexels-photo-4686817.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=1",
      ],
    },
    {
      title: "Tarteletas Dulces",
      description:
        "Tarteletas dulces de crema moka, bariloche, crema, y dulce de leche. Se vende por kg.",
      price: 2499,
      status: true,
      code: "t4rt3l3t4dulc3",
      stock: 13,
      category: "Dulces",
      thumbnail: [
        "https://img.freepik.com/fotos-premium/mini-tartaletas-dulces-hechas-ingredientes-frescos_681987-6676.jpg?w=2000",
      ],
    },
    {
      title: "Tarteletas Saladas",
      description:
        "Tarteletas saladas de atun, palmito y roquefort. Se vende por kg.",
      price: 2799,
      status: true,
      code: "t4rt3l3t4s4l4d4",
      stock: 11,
      category: "Salados",
      thumbnail: [
        "https://badun.nestle.es/imgserver/v1/80/1290x742/d01e5837e5c9-tartaletas-rellenas-de-atun.jpg",
      ],
    },
    {
      title: "Arrollado Dulce",
      description:
        "Arrollado Dulce relleno de dulce de leche y crema, bañado en crema moka, bariloche, dulce de leche o crema.",
      price: 3199,
      status: true,
      code: "4rr0ll4d0dulc3",
      stock: 3,
      category: "Dulces",
      thumbnail: [
        "https://www.recetas-argentinas.com/base/stock/Recipe/134-image/134-image_web.jpg",
      ],
    },
    {
      title: "Arrollado Salado",
      description: "Arrollado Salado de jamon y queso, Roquefort o Atun.",
      price: 3249,
      status: true,
      code: "4rr0ll4d0s4l4d0",
      stock: 2,
      category: "Salados",
      thumbnail: ["https://mediacenter.bonduelle.com/cdn/202001/ESGP016_.jpg"],
    },
    {
      title: "Tallarines",
      description: "Tallarines de huevo",
      price: 149,
      status: true,
      code: "t4ll4r1n3s",
      stock: 10,
      category: "Pastas",
      thumbnail: [
        "https://imag.bonviveur.com/tallarines-al-huevo-una-vez-cocidos.jpg",
      ],
    },
    {
      title: "Ñoquis",
      description: "Ñoquis de queso o papa",
      price: 299,
      status: true,
      code: "n0qu1s",
      stock: 6,
      category: "Pastas",
      thumbnail: [
        "https://www.clarin.com/img/2018/06/19/HJS8-kvW7_1256x620__2.jpg#1588085373911",
      ],
    },
    {
      title: "Sorrentinos",
      description:
        "Sorrentinos rellenos de pollo, carne y verdura o jamon y queso.",
      price: 359,
      status: true,
      code: "s0rr3nt1n0s",
      stock: 8,
      category: "Pastas",
      thumbnail: [
        "https://cuk-it.com/wp-content/uploads/2022/05/thumb03c-840x473.jpg",
      ],
    },
  ]);
};
main() */

mongoose.connect("mongodb://localhost:27017", { dbName: "Desafio-5" });
app.listen(8080, () => console.log("Server Up!"));
