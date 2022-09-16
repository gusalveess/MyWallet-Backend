import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import { v4 as uuid } from "uuid";
import joi from "joi";
import dayjs from "dayjs";

// CONFIGURAÇÕES
const server = express();
server.use(cors());
server.use(express.json());
dotenv.config();

const mongoClient = new MongoClient(process.env.MONGO_URI);
let db;
mongoClient.connect(() => {
  db = mongoClient.db("myWallet");
});

//SCHEMAS

const signUpSchema = joi.object({
  name: joi.required(),
  email: joi.required(),
  password: joi.required(),
  passwordConfirm: joi.required(),
});

const ValueSchema = joi.object({
  description: joi.string().required(),
  value: joi.number().required(),
  type: joi.string().required(),
});

const signInSchema = joi.object({
  email: joi.required(),
  senha: joi.required(),
});

// ROTAS
server.post("/users", async (req, res) => {
  const { name, email, password, passwordConfirm } = req.body;

  const validation = signUpSchema.validate(req.body, { abortEarly: false });

  if (validation.error) {
    return res
      .status(422)
      .send(validation.error.details.map((error) => error.message));
  }

  try {
    const isRegistered = await db.collection("users").findOne({ email: email });
    const passwordHash = bcrypt.hashSync(password, 10);

    if (isRegistered) {
      return res.sendStatus(409);
    }

    if (password != passwordConfirm) {
      return res.sendStatus(401);
    }

    if (!name || !email || !password || !passwordConfirm) {
      return res.send(401);
    }

    await db.collection("users").insertOne({
      name: name,
      email: email,
      password: passwordHash,
      passwordConfirm: passwordHash,
    });

    res.sendStatus(201);
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

server.get("/users", async (req, res) => {
  try {
    const participants = await db.collection("users").find().toArray();

    res.status(200).send(participants);
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

server.post("/sign-in", async (req, res) => {
  const { email, senha } = req.body;

  const user = await db.collection("users").findOne({ email });

  const validation = signInSchema.validate(req.body, { abortEarly: false });

  if (validation.error) {
    return res
      .status(422)
      .send(validation.error.details.map((error) => error.message));
  }

  if (user && bcrypt.compareSync(senha, user.password)) {
    const token = uuid();

    await db.collection("sessions").deleteMany({ userId: user._id });

    await db.collection("sessions").insertOne({
      userId: user._id,
      token,
    });

    const send = {
      name: user.name,
      token: token,
    };

    const sessions = await db.collection("sessions").find().toArray();
    console.log(sessions);
    res.send(send);
  } else {
    res.sendStatus(401);
  }
});

server.post("/data", async (req, res) => {
  const { value, description, type } = req.body;
  const { authorization } = req.headers;
  const token = authorization?.replace("Bearer ", "");

  const validation = ValueSchema.validate(req.body, { abortEarly: false });

  if (validation.error) {
    return res
      .status(422)
      .send(validation.error.details.map((error) => error.message));
  }

  try {
    if (!token) return res.sendStatus(401);

    const session = await db.collection("sessions").findOne({ token });

    if (!session) {
      return res.sendStatus(401);
    }

    if (!description || !value) {
      return res.send(401);
    }

    await db.collection("database").insertOne({
      Day: dayjs().format("DD/MM"),
      Description: description,
      Value: value,
      Type: type,
      User: session.userId,
    });

    res.sendStatus(201);
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

server.get("/data", async (req, res) => {
  const { authorization } = req.headers;
  const token = authorization?.replace("Bearer ", "");

  try {
    if (!token) return res.sendStatus(401);

    const session = await db.collection("sessions").findOne({ token });

    if (!session) {
      return res.sendStatus(401);
    }

    const database = await db
      .collection("database")
      .find({ User: session.userId })
      .toArray();

    res.status(200).send(database);
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

server.delete("/data/:id", async (req, res) => {
  const { id } = req.params;

  try {
    await db.collection("database").deleteOne({ _id: new ObjectId(id) });

    res.sendStatus(200);
  } catch (error) {
    res.status(500).send(error);
  }
});

// CONEXÃO DA PORTA
server.listen(process.env.PORT, () => {
  console.log("Server running on port " + process.env.PORT);
});
