export default class User {
    constructor(token, fingerprint, dbConnector) {
        this.isInvalid = false;
        this.db = dbConnector;
        this.token = token;
        this.fingerprint = fingerprint;
    }
    async initUser() {
        if (this.db.sql) {
            const result = await this.db.sql `select
 			u.user_id, su.token, su.fingerprint, user_login, 
 			is_admin, apo.obj_type_id, ot.obj_type_code, ur.role_id 
 		from sessions_users su
		join users u on u.user_id = su.user_id
		join user_roles ur on u.user_id = ur.user_id
		left join all_people_objects apo on u.obj_id = apo.obj_id
		left join obj_types ot on apo.obj_type_id = ot.obj_type_id
		where token = ${this.token} and su.fingerprint = ${this.fingerprint};`.execute();
            if (result.length > 1) {
                this.isInvalid = true;
                return Promise.reject('invalid length response');
            }
            if (result.length === 0) {
                this.isInvalid = true;
                return Promise.reject('user not found');
            }
            const userData = result[0];
            this.userLogin = userData['user_login'];
            this.userId = parseInt(userData['user_id']);
            this.isAdmin = Boolean(userData['is_admin']);
            this.objTypeCode = userData['obj_type_code'];
            this.objTypeId = userData['obj_type_id'];
            this.roleId = userData['role_id'];
        }
    }
}
//# sourceMappingURL=User.js.map