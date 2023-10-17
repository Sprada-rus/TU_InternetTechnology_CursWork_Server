import * as express from "express"
import * as dotenv from "dotenv";
import * as cors from "cors";
import {env} from "node:process";
import authRouter from "./api/Authorization/authorizationRouter";
import userRouter from "./api/User/userRouter";

dotenv.config();
const server = express();
const port = env.SERVER_PORT ?? 8000;

const allowRegExp = /^(http:\/\/localhost:8080)|(https:\/\/curswork\.isapronov\.info)$/;

const corsOptions = {
    origin: (origin, callback) => {
        if (allowRegExp.exec(origin) !== null) {
            callback(null, true);
        } else {
            callback('Not allowed by CORS');
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

server.get('/', (request, response) => {
    response.send(`Hello, who there?`)
});

server.options('*', (req, res) => {
    return res.status(201);
})

server.listen(port, () => {
    console.log(`Server work on ${port} port`);
})