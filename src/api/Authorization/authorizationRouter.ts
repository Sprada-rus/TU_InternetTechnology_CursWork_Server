import {Router} from "express";
import PostgresConnector from "../../connector/PostgresConnector";
import {env} from "node:process";
import * as jwt from 'jsonwebtoken';

const authRouter = Router();

authRouter.use((req, res, next) => {
	console.log('auth router log', req.header('Fingerprint'));

	if (!req.header('Fingerprint')) {
		res.status(400);
		res.json({reason: 'fingerprint is empty'});
		return;
	}

	next();
});

authRouter.post('/token',async (req, res) => {
	const { login, password } = req.body;
	const fingerprint = req.header('fingerprint');
	console.log('check login and password', login, password);

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

		const token = jwt.sign({login: login, fingerprint: fingerprint}, env.SECRET_KEY, {
			algorithm: 'HS256',
			expiresIn: '8h'
		});

		const userId = await getUserId(login);
		await insertNewToken(token, userId, fingerprint);

		res.json({token: token});
	} catch (e) {
		console.error(e);
		res.status(500).json({reason: 'Error on server'});
	}

});

const insertNewToken = async (token: string, userId: number, fingerprint: string) => {
	console.log('start insert new token', userId, token, fingerprint);
	const db = new PostgresConnector();

	try {
		db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
		await db.sql`insert into public.sessions_users(user_id, token, fingerprint) values (${userId}, ${token}, ${fingerprint})`;
	} catch (e) {
		console.error(e);
	} finally {
		db.sql.end();
	}
}

const getUserId = async (username: string): Promise<number> => {
	const db = new PostgresConnector();

	try {
		db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
		const userId = (await db.sql`select user_id from public.users where user_login=${username}`.execute())[0]['user_id'] as number;

		return userId;
	} catch (e) {
		console.error(e);
	} finally {
		db.sql.end();
	}
}

const checkPassword = async (username: string, password: string): Promise<boolean> => {
	const db = new PostgresConnector();

	try {
		db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
		const checkResult = (await db.sql`select 
		user_password = crypt(${password}, 'md5') as result 
		from public.users 
		where user_login = ${username}`.execute())[0]['result'];

		return true;
	} catch (e) {
		console.error(e);
		return false;
	} finally {
		await db.sql.end();
	}
}

authRouter.get('/check-token', async (req, res) => {
	const db = new PostgresConnector();

	try {
		db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
		db.tokenIsValid(req.query['token'] as string);
		return res.status(200).json({status: 'ok'});
	} catch (e) {
		console.error(e);
	} finally {
		db.sql.end();
	}
})

export default authRouter;