import * as express from "express"
import * as dotenv from "dotenv";
import {env} from "node:process";

dotenv.config();
const server = express();
const port = env.SERVER_PORT ?? 8080;

server.get('/', (request, response) => {
    console.log(request.headers);
    response.send(`Hello, who there?`)
})

server.listen(port, () => {
    console.log(`Server work on ${port} port`);
})