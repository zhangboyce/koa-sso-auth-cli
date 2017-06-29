'use strict';

let rp = require('request-promise');

let default_api_server;

function * getUserInfo(token, api_server = default_api_server) {
    return yield getCommonTokenData(token, '/api/getUserInfo', api_server);
}

function * getModules(api_server = default_api_server) {
    let json = yield getJson(api_server + '/api/getModules');
    if (!json.status) {
        console.error('Get ATO modules fail.', json);
        return null;
    }
    return json.result;
}

function * getMPList(token, api_server = default_api_server) {
    return yield getCommonTokenData(token, '/api/getMPList', api_server);
}

function * getMpAccessToken(token, mpId, api_server = default_api_server) {
    return yield getCommonTokenData(token, '/api/getMpAccessToken/' + mpId, api_server);
}

function * getCommonTokenData(token, url, api_server) {
    let json = yield getJson(api_server + url + '?token=' + token);
    if (!json.status) {
        console.warn('Get ' + url + ' failed, because ' + json.message);
        return null;
    } else {
        return json.result;
    }
}

function * getJson(url) {
    let result = yield rp(url);
    return JSON.parse(result);
}

function setDefaultAPIServer(server) {
    default_api_server = server;
}

module.exports = {
    getUserInfo,
    getModules,
    getMPList,
    getMpAccessToken,
    setDefaultAPIServer
};
