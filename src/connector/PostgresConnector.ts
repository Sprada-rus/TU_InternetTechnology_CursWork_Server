import {env} from "node:process";
import postgres from "postgres";
import * as jwt from 'jsonwebtoken';

export default class PostgresConnector {
	_host?: string;
	_port?: number;
	_database?: string;
	_username: string;
	_password: string;
	_queries?: postgres.Sql<{}>;

	constructor() {
		this._host = env.DB_HOST;
		this._port = env.DB_PORT ? parseInt(env.DB_PORT) : undefined;
		this._database = env.DB_NAME;
		this._queries = undefined
		this._username = '';
		this._password = '';
	}

	public initUser(login: string, password: string) {
		this._queries = postgres({
			host: this._host,
			port: this._port,
			database: this._database,
			username: login,
			password: password,
		});
	}

	public tokenIsValid(token: string) {
		if (!this._queries) {
			throw new Error('user is not initialized');
		}

		try {
			if (env.SECRET_KEY){
				return jwt.verify(token, env.SECRET_KEY);
			} else {
				return false;
			}

		} catch (e) {
			return false;
		}
	}

	get sql() {
		return this._queries;
	}
}