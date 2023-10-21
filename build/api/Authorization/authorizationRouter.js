import { Router } from "express";
import PostgresConnector from "../../connector/PostgresConnector.js";
import { env } from "node:process";
import jwt from 'jsonwebtoken';
const authRouter = Router();
authRouter.use((req, res, next) => {
    console.log('auth router log', req.header('Fingerprint'));
    if (!req.header('Fingerprint')) {
        res.status(400);
        res.json({ reason: 'fingerprint is empty' });
        return;
    }
    next();
});
authRouter.post('/token', async (req, res) => {
    const { login, password } = req.body;
    const fingerprint = req.header('fingerprint');
    console.log('check login and password', login, password);
    if (!fingerprint) {
        return res.status(400).send('fingerprint not found');
    }
    try {
        if (!login) {
            res.status(403);
            return res.json('login is empty');
        }
        if (!password) {
            res.status(403);
            return res.json('password is empty');
        }
        const result = await checkPassword(login, password);
        if (!result) {
            res.status(403);
            return res.json('login or password incorrect');
        }
        if (!env.SECRET_KEY) {
            return res.status(500).send('server error');
        }
        const token = jwt.sign({ login: login, fingerprint: fingerprint }, env.SECRET_KEY, {
            algorithm: 'HS256',
            expiresIn: '8h'
        });
        const userId = await getUserId(login);
        await insertNewToken(token, userId, fingerprint);
        res.json({ token: token });
    }
    catch (e) {
        console.error(e);
        res.status(500).json({ reason: 'Error on server' });
    }
});
const insertNewToken = async (token, userId, fingerprint) => {
    var _a;
    console.log('start insert new token', userId, token, fingerprint);
    const db = new PostgresConnector();
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return;
    }
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        if (!db.sql) {
            return Promise.reject('connector empty');
        }
        await db.sql `insert into public.sessions_users(user_id, token, fingerprint) values (${userId}, ${token}, ${fingerprint})`;
    }
    catch (e) {
        console.error(e);
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
};
const getUserId = async (username) => {
    var _a;
    const db = new PostgresConnector();
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        throw new Error('user not found');
    }
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        if (!db.sql) {
            return Promise.reject('connector empty');
        }
        return (await db.sql `select user_id from public.users where user_login=${username}`.execute())[0]['user_id'];
    }
    catch (e) {
        console.error(e);
        return Promise.reject('error');
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
};
const checkPassword = async (username, password) => {
    var _a;
    const db = new PostgresConnector();
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return false;
    }
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        if (!db.sql) {
            return false;
        }
        const checkResult = (await db.sql `select 
		user_password = crypt(${password}, 'md5') as result 
		from public.users 
		where user_login = ${username}`.execute())[0]['result'];
        return !!checkResult;
    }
    catch (e) {
        console.error(e);
        return false;
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
};
authRouter.get('/check-token', async (req, res) => {
    var _a;
    const db = new PostgresConnector();
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return res.status(500).send('not found user');
    }
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        db.tokenIsValid(req.query['token']);
        return res.status(200).json({ status: 'ok' });
    }
    catch (e) {
        console.error(e);
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
});
export default authRouter;
//# sourceMappingURL=authorizationRouter.js.map