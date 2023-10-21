import { Router } from "express";
import PostgresConnector from "../../connector/PostgresConnector.js";
import { env } from "node:process";
import User from "./User.js";
import jwt from "jsonwebtoken";
const userRouter = Router();
userRouter.use(async (req, res, next) => {
    var _a, _b;
    const token = (_a = req.header('Authorization')) === null || _a === void 0 ? void 0 : _a.replace('Bearer ', '');
    const reqFingerprint = req.header('Fingerprint');
    if (!token) {
        return res.status(401).send();
    }
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return res.status(500).send('not found user');
    }
    if (!env.SECRET_KEY) {
        return res.status(500).send('secret key not found');
    }
    const db = new PostgresConnector();
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        const checkResult = jwt.verify(token, env.SECRET_KEY, { complete: true });
        console.log('check token', checkResult);
        const fingerprint = typeof checkResult.payload !== 'string' ? checkResult.payload['fingerprint'] : '';
        if (!fingerprint || (fingerprint !== reqFingerprint))
            return res.status(403).send();
        const user = new User(token, fingerprint, db);
        await user.initUser();
        console.log('Check user', user.isInvalid);
        if (user.isInvalid) {
            return res.status(401).send();
        }
        req.app.set('user', user);
        next();
    }
    catch (e) {
        console.error(e);
        return res.status(401).send();
    }
    finally {
        await ((_b = db.sql) === null || _b === void 0 ? void 0 : _b.end());
    }
});
userRouter.get('/lists', async (req, res) => {
    var _a;
    const db = new PostgresConnector();
    const user = req.app.get('user');
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return res.status(500).send('not found user');
    }
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        if (!db.sql) {
            return res.status(500).send('server error');
        }
        const sqlResponse = await db.sql `select obj_type_name as name, ot.obj_type_code as to from obj_types ot
		join role_permission_obj_type rpot on ot.obj_type_id = rpot.obj_type_id
		join user_roles ur on rpot.role_id = ur.role_id
		join users u on ur.user_id = u.user_id
		where u.user_login = ${user.userLogin} and permision_type = 'visible'
		group by obj_type_code, obj_type_name;`.execute();
        console.log(sqlResponse);
        res.status(200).json(sqlResponse !== null && sqlResponse !== void 0 ? sqlResponse : []);
    }
    catch (e) {
        console.error(e);
        res.status(500);
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
});
userRouter.get('/list-attrs', async (req, res) => {
    var _a;
    const { code } = req.query;
    const user = req.app.get('user');
    if (!code) {
        res.status(400).json({ reason: 'code is empty' });
        return res.send();
    }
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return res.status(500).send('not found user');
    }
    const db = new PostgresConnector();
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        if (!db.sql) {
            return res.status(500).send('server error');
        }
        const [sqlResponse] = await db.sql `select obj_type_code, obj_type_name, ot.obj_type_id 
		from public.obj_types ot
			join public.role_permission_obj_type rpot on ot.obj_type_id = rpot.obj_type_id
			join public.user_roles ur on rpot.role_id = ur.role_id
		where permision_type = 'visible' and user_id = ${user.userId} and obj_type_code = ${code}
		group by obj_type_code, obj_type_name, ot.obj_type_id;`.execute();
        console.log('check sqlResponse obj type', sqlResponse);
        if (!sqlResponse || !sqlResponse['obj_type_id']) {
            return res.status(404).json({ result: 'Not found' });
        }
        const objTypeData = sqlResponse;
        console.log('check obj type data', objTypeData);
        const getAttrs = await db.sql `select attr_code, attr_name, order_num from public.obj_attrs a
		join public.obj_attr_oreders ao on a.attr_id = ao.attr_id
		join public.role_permission_obj_type_attrs rpota on a.attr_id = rpota.attr_id
		where obj_type_id = ${objTypeData['obj_type_id']} and rpota.role_id = ${user.roleId} and rpota.permision_type = 'visible_in_grid'
		order by ao.order_num;`;
        console.log('check attrs', getAttrs);
        const attrs = {
            obj_id: {
                name: 'ID',
                order: 0
            }
        };
        for (const row of getAttrs) {
            attrs[row['attr_code']] = {
                name: row['attr_name'],
                order: row['order_num']
            };
        }
        res.status(200).json(attrs);
    }
    catch (e) {
        console.error(e);
        res.status(500).json();
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
});
userRouter.get('/list-data', async (req, res) => {
    var _a;
    const { code } = req.query;
    const user = req.app.get('user');
    if (!code) {
        res.status(400).json({ reason: 'code is empty' });
        return res.send();
    }
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return res.status(500).send('not found user');
    }
    const db = new PostgresConnector();
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        if (!db.sql) {
            return res.status(500).send('server error');
        }
        const [checkResult] = await db.sql `select obj_type_id from public.obj_types where obj_type_code = ${code}`.execute();
        if (!checkResult) {
            return res.status(404).json({ reason: 'type not found' });
        }
        const viewName = 'public.v_' + code;
        const getAttrs = await db.sql `select attr_code from public.obj_attrs a
		join public.obj_attr_oreders ao on a.attr_id = ao.attr_id
		join public.role_permission_obj_type_attrs rpota on a.attr_id = rpota.attr_id
		where a.obj_type_id = ${checkResult['obj_type_id']} and rpota.role_id = ${user.roleId} and rpota.permision_type = 'visible_in_grid'
		order by ao.order_num;`.values();
        if (getAttrs.length === 0) {
            return res.status(200).json([]);
        }
        const attrsList = ['obj_id'];
        for (const [attr] of getAttrs) {
            attrsList.push(attr);
        }
        console.log('check attrList', attrsList);
        const objectData = await db.sql `select 
		${db.sql(attrsList)} from ${db.sql(viewName)}`.execute();
        console.log('check object data', objectData);
        res.status(200).json(objectData);
    }
    catch (e) {
        console.error(e);
        res.status(500).json({ reason: 'server error' });
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
});
userRouter.get('/object-attrs', async (req, res) => {
    var _a;
    const { code } = req.query;
    const user = req.app.get('user');
    if (!code) {
        res.status(400).json('invalid queries');
    }
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return res.status(500).send('not found user');
    }
    const db = new PostgresConnector();
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        if (!db.sql) {
            return res.status(500).send('server error');
        }
        console.log(user.roleId, code);
        if (!user.roleId) {
            res.status(500).json();
        }
        const getAttrs = await db.sql `select attr_code from public.obj_attrs a
		join public.obj_attr_oreders ao on a.attr_id = ao.attr_id
		join public.role_permission_obj_type_attrs rpota on a.attr_id = rpota.attr_id
		join public.obj_types ot on a.obj_type_id = ot.obj_type_id
		where ot.obj_type_code = ${code} and rpota.role_id = ${user.roleId} and permision_type in ('visible')
		order by ao.order_num;`.values();
        console.log('check result getAttrs', getAttrs);
        const attrsList = getAttrs.map(([attrCode]) => attrCode);
        console.log('check result attrsList', attrsList);
        const getPropsAttrs = await db.sql `select
		attr_code as name,
		order_num as "order",
		attr_name as label,
		case
		   when attr_type = 'link' then 'select'
		   else 'text'
		end as type,
		true as required,
		not(f_attr_is_editable(attr.attr_id, ${user.roleId})) as disabled,
		source
		from public.obj_attrs attr
		join public.obj_attr_oreders oao on attr.attr_id = oao.attr_id
		join public.obj_types ot on attr.obj_type_id = ot.obj_type_id
		where obj_type_code = ${code} and attr_code in ${db.sql(attrsList)};`.execute();
        console.log('check result getPropsAttrs', getPropsAttrs);
        res.status(200).json(getPropsAttrs);
    }
    catch (e) {
        console.error(e);
        res.status(500).json({ reason: 'server error', errorMessage: e });
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
});
userRouter.get('/object-data', async (req, res) => {
    var _a;
    const { code, objId } = req.query;
    const user = req.app.get('user');
    if (!code || !objId) {
        res.status(400).json({ reason: 'queries is not valid' });
    }
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return res.status(500).send('not found user');
    }
    const db = new PostgresConnector();
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        if (!db.sql) {
            return res.status(500).send('server error');
        }
        const [checkResult] = await db.sql `select obj_type_id from public.obj_types where obj_type_code = ${code}`.execute();
        if (!db.sql) {
            return res.status(500).send('server error');
        }
        if (!checkResult) {
            return res.status(404).json({ reason: 'type not found' });
        }
        if (!user.roleId) {
            return res.status(404).json({ reason: 'user not found' });
        }
        const viewName = 'public.v_' + code;
        const getAttrs = await db.sql `select attr_code from public.obj_attrs a
		join public.obj_attr_oreders ao on a.attr_id = ao.attr_id
		join public.role_permission_obj_type_attrs rpota on a.attr_id = rpota.attr_id
		where a.obj_type_id = ${checkResult['obj_type_id']} and rpota.role_id = ${user.roleId} and rpota.permision_type = 'visible'
		order by ao.order_num;`.values();
        if (getAttrs.length === 0) {
            res.status(200).json([]);
        }
        const attrsList = getAttrs.map(([attr]) => attr);
        console.log('check attrList', attrsList);
        const [objectData] = await db.sql `select 
		${db.sql(attrsList)} from ${db.sql(viewName)} where obj_id = ${objId}`.execute();
        console.log('check object data', objectData);
        res.status(200).json(objectData);
    }
    catch (e) {
        console.error(e);
        res.status(500).json({ reason: 'server error', errorMessage: e });
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
});
userRouter.get('/get-options', async (req, res) => {
    var _a;
    const { code } = req.query;
    if (!code) {
        return res.status(400).json({ reason: 'queries is not valid' });
    }
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return res.status(500).send('not found user');
    }
    const db = new PostgresConnector();
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        if (!db.sql) {
            return res.status(500).send('server error');
        }
        const options = await db.sql `select
			case attr_type
				when 'string' then value_str
				when 'date' then to_char(value_date, 'DD.MM.YYYY')
				else value_num::text
			end as label, oav.obj_id as value
		from public.obj_attr_values oav
		join public.obj_attrs oa on oav.attr_id = oa.attr_id
		join public.obj_types ot on oa.obj_type_id = ot.obj_type_id and oa.attr_code = ot.attr_for_caption
		where ot.obj_type_code = ${code}`.execute();
        console.log('check options', options);
        res.status(200).json(options);
    }
    catch (e) {
        console.error(e);
        res.status(500).json({ reason: 'server error', errorMessage: e });
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
});
userRouter.post('/save', async (req, res) => {
    var _a;
    const { code, objId } = req.query;
    const fieldsData = req.body;
    console.log('fieldsData', fieldsData);
    if (!code) {
        return res.status(400).json({ reason: 'invalid query' });
    }
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return res.status(500).send('not found user');
    }
    const db = new PostgresConnector();
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        let currentObjId = objId;
        if (!db.sql) {
            return res.status(500).send('server error');
        }
        if (!currentObjId) {
            const [rowWithId] = await db.sql `select public.create_new_object(${code}) as obj_id`.execute();
            currentObjId = rowWithId['obj_id'];
        }
        const requests = [];
        for (const [attr, value] of Object.entries(fieldsData)) {
            requests.push(db.sql `select public.set_value_2(${currentObjId}, ${code}, ${attr}, ${value})`);
        }
        await Promise.all(requests);
        res.status(200).json({ status: 'ok' });
    }
    catch (e) {
        console.error(e);
        res.status(500).json(e);
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
});
userRouter.get('/actions', async (req, res) => {
    var _a;
    const { code } = req.query;
    const user = req.app.get('user');
    if (!code) {
        return res.status(400).json({ reason: 'invalid query' });
    }
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return res.status(500).send('not found user');
    }
    const db = new PostgresConnector();
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        if (!db.sql) {
            return res.status(500).send('server error');
        }
        if (!user.roleId) {
            return res.status(500).send('user has not role id');
        }
        const sqlRes = await db.sql `select permision_type from role_permission_obj_type rp
		join obj_types ot on rp.obj_type_id = ot.obj_type_id
		where obj_type_code = ${code} and role_id = ${user.roleId} and permision_type not in ('open', 'visible');`.values();
        const labels = {
            edit: 'Изменить',
            delete: 'Удалить',
            create: 'Новая запись'
        };
        const actions = sqlRes.map(([action]) => {
            return ({ name: action, label: labels[action] });
        });
        res.status(200).json(actions);
    }
    catch (e) {
        console.error(e);
        res.status(500).json({ reason: 'server error' });
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
});
userRouter.delete('/delete', async (req, res) => {
    var _a;
    const { code, id } = req.query;
    if (!code || !id) {
        return res.status(400).json({ reason: 'invalid queries' });
    }
    if (!env.DB_USER_NAME || !env.DB_USER_PASSWORD) {
        return res.status(500).send('not found user');
    }
    const db = new PostgresConnector();
    try {
        db.initUser(env.DB_USER_NAME, env.DB_USER_PASSWORD);
        if (!db.sql) {
            return res.status(500).send('server error');
        }
        const [resultGroup] = await db.sql `select obj_type_group from public.obj_types where obj_type_code = ${code}`.execute();
        if (!resultGroup) {
            res.status(404).json({ reason: "not fount group" });
        }
        let table = '';
        switch (resultGroup['obj_type_group']) {
            case 'people':
                table = 'public.all_people_objects';
                break;
            case 'guide':
                table = 'public.guide_entry';
                break;
            default:
                res.status(404).json('unknown group');
        }
        if (table) {
            await db.sql `update ${db.sql(table)} set deleted = true where obj_id = ${id}`;
        }
        res.status(200).json({ result: 'object is deleted' });
    }
    catch (e) {
        console.error(e);
        res.status(500).json({ reason: 'server error' });
    }
    finally {
        await ((_a = db.sql) === null || _a === void 0 ? void 0 : _a.end());
    }
});
export default userRouter;
//# sourceMappingURL=userRouter.js.map