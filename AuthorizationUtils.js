const _ = require('lodash');

let modules;
let authorizationMap;
let defaultModule;
let clientAuth;

function initBuild(moduleList) {
    modules = moduleList;
    let map = {};
    for(let m of modules) {
        let authMap = {};
        let t = {id: m._id, name: m.name, host: m.host, icon: m.icon, cover: m.cover, authMap};
        for(let auth of _.flatten(m.authorizations)) {
            auth.authValue = Math.pow(2, auth.value);
            authMap[auth.id] = auth;
        }
        map[t.id] = t;
    }
    authorizationMap = map;
}

function authValue(module, authList) {
    let map = authorizationMap[module].authMap;
    let value = 0;
    for(let a of authList) {
        value |= map[a].authValue;
    }
    return value;
}

function buildRole(role) {
    let result = {};
    _.each(role.authorizations, function (v, k) {
        result[k] |= authValue(k, v);
    });
    return result;
}

function merge(authMapList) {
    let result = {};
    _.each(authMapList, function (authMap) {
        _.each(authMap, function (v, k) {
            if(!result[k]) {
                result[k] = 0;
            }
            result[k] |= v;
        });
    });
    return result;
}

function buildRoles(roleList) {
    return merge(_.map(roleList, role => buildRole(role)));
}

function check(module, authMap, auth) {
    let authValue = authMap[module];
    if(!authValue) {
        return false;
    }
    try {
        return (authValue & authorizationMap[module]['authMap'][auth].authValue) > 0;
    }catch(e) {
        return false;
    }
}

function checkAuthList(module, authMap, authList) {
    if(!authList) {
        return false;
    }
    if(typeof(authList) === 'string') {
        authList = [authList];
    }
    return _.every(authList, auth => check(module, authMap, auth));
}

function setDefaultModule(module) {
    defaultModule = module;
}

function setClient(auth) {
    clientAuth = auth;
}

function checkClient(authList, module) {
    module = module || defaultModule;
    if(!module) {
        throw '没有指定module，也没有默认的module';
    }
    if(!clientAuth) {
        throw '客户端没有权限设置';
    }
    return checkAuthList(module, clientAuth, authList);
}

function checkKoaDefaultModule(ctx) {
    let module = defaultModule;
    if(!module) {
        throw '没有指定module，也没有默认的module';
    }

    let account = ctx.session && ctx.session.account;
    if(!account) {
        return false;
    }

    return account.authorizations &&
        (account.authorizations.accountAuth[module] != null);
}

function checkKoaSession(ctx, authList, module) {
    module = module || defaultModule;
    if(!module) {
        throw '没有指定module，也没有默认的module';
    }

    let account = ctx.session && ctx.session.account;
    if(!account) {
        return false;
    }

    return checkAuthList(module, account.authorizations.accountAuth, authList);
}

function buildAccountAuth(tenancyRoleList, accountRole) {
    let tenancyAuthMap = {};
    _.each(_.groupBy(tenancyRoleList, r => r.tenancy), function (v, k) {
        tenancyAuthMap[k] = buildRoles(v);
    });
    accountRole = accountRole || {};
    let accountAuth = merge([buildRole(accountRole), ..._.map(tenancyAuthMap, v => v)]);
    return {
        accountAuth,
        tenancyAuthMap
    }
}

function listHasAuthTenancies(tenancyAuthMap, module, auth) {
    let results = [];
    _.each(tenancyAuthMap, (v, k) => {
        if(check(module, v, auth)) {
            results.push(k);
        }
    });
    return results;
}

function listHasAuthModules(authMap = clientAuth) {
    if(!authMap) {
        return null;
    }
    return _.map(_.filter(modules, m => {
        return authMap[m._id] != null;
    }), m => ({
        id: m._id, name: m.name, host: m.host, icon: m.icon, cover: m.cover
    }));
}

function getModules() {
    return modules;
}

module.exports = {
    initBuild,
    authValue,
    buildRole,
    buildRoles,
    buildAccountAuth,
    merge,
    check,
    checkAuthList,
    checkKoaSession,
    checkKoaDefaultModule,
    checkClient,
    setDefaultModule,
    setClient,
    listHasAuthTenancies,
    listHasAuthModules,
    getModules
};