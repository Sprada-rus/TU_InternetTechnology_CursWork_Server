import express from "express";
import * as dotenv from "dotenv";
import cors from "cors";
import {env} from "node:process";
import authRouter from "./api/Authorization/authorizationRouter.js";
import userRouter from "./api/User/userRouter.js";
import {CorsOptions} from "cors";

dotenv.config();
const server = express();
const port = env.SERVER_PORT ?? 8000;

const allowRegExp = /^(http:\/\/localhost:8080)|(http:\/\/curswork\.isapronov\.website)$/;

const corsOptions: CorsOptions = {
    origin: (origin, callback) => {
        if (origin && allowRegExp.exec(origin) !== null) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: "GET,PATCH,POST,DELETE,OPTIONS",
    preflightContinue: false,
    optionsSuccessStatus: 204
}

server.use(cors(corsOptions));

server.use(express.json());
server.use('/api/authorization', authRouter);
server.use('/api/user', userRouter);

server.get('/', (_, response) => {
    response.send(`Hello, who there?`)
});

server.options('*', (_, res) => {
    return res.status(201);
})

server.listen(port, () => {
    console.log(`Server work on ${port} port`);
})