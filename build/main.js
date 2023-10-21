var _a;
import express from "express";
import * as dotenv from "dotenv";
import cors from "cors";
import { env } from "node:process";
import authRouter from "./api/Authorization/authorizationRouter.js";
import userRouter from "./api/User/userRouter.js";
dotenv.config();
const server = express();
const port = (_a = env.SERVER_PORT) !== null && _a !== void 0 ? _a : 8000;
const allowRegExp = /^(http:\/\/localhost:8080)|(https:\/\/curswork\.isapronov\.info)$/;
const corsOptions = {
    origin: (origin, callback) => {
        if (origin && allowRegExp.exec(origin) !== null) {
            callback(null, true);
        }
        else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: "GET,PATCH,POST,DELETE,OPTIONS",
    preflightContinue: false,
    optionsSuccessStatus: 204
};
server.use(cors(corsOptions));
server.use(express.json());
server.use('/api/authorization', authRouter);
server.use('/api/user', userRouter);
server.get('/', (_, response) => {
    response.send(`Hello, who there?`);
});
server.options('*', (_, res) => {
    return res.status(201);
});
server.listen(port, () => {
    console.log(`Server work on ${port} port`);
});
//# sourceMappingURL=main.js.map