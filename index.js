'use strict';

let koa_session = require('koa-session');
let rp = require('request-promise');
let router = require('koa-router')();

let AuthorizationUtils = require('./AuthorizationUtils');

function SSOMiddleware(opts, app){

    if (!opts || !opts.sso_server || !opts.sso_client) {
        throw new Error('the opts is illegal.');
    }
    if (!app || typeof app.use !== 'function') {
        throw new Error('the app is illegal.');
    }

    app.keys = app.keys || ['koa-sso-auth-cli-2016','keys'];
    if (!app.context.sessionKey) app.use(koa_session(app));

    let sso_server = opts['sso_server'];
    let sso_api_server = opts['sso_api_server'] || sso_server ;
    let sso_client = opts['sso_client'];
    rp(sso_api_server + '/api/getModules').then(body => {
        let moduleJson = JSON.parse(body);
        if (!moduleJson.status) {
            console.error('Get ATO modules fail.' + jsonAccount.message);
            throw 'Get ATO modules fail.';
        } else {
            AuthorizationUtils.initBuild(moduleJson.result);
            console.log('Auth is runing.');
        }
    });

    let auth_callback_url = sso_client + '/api/getToken';
    auth_callback_url = encodeURIComponent(auth_callback_url);

    router.get('/api/getToken', getToken(sso_server, sso_api_server, auth_callback_url));
    app.use(router.routes()).use(router.allowedMethods());

    return auth(sso_server, sso_api_server , auth_callback_url);
};

function auth(sso_server, sso_api_server , auth_callback_url) {
    return function *(next) {
        let token = this.session.token;
        let redirectUrl = sso_server + '?auth_callback='+ auth_callback_url;

        if (token) {
            let token_check_url = sso_api_server + '/api/token/check?token=' + token;
            let jsonStr = yield rp(token_check_url);
            let json = JSON.parse(jsonStr);
            if (json.status) {
                yield next;
                return;
            }
            console.log('Check token result: ' + jsonStr + ', redirect to ' + redirectUrl);
        }else {
            console.log('No token, redirect to ' + redirectUrl);
        }

        if (!this.headers['x-requested-with'] ||
            this.headers['x-requested-with'].toLowerCase() !== 'xmlhttprequest') {

            this.session.currentUrl = this.req.url + (this.req.search || '') ;
            this.redirect(redirectUrl);
        }
    }
}

function getToken(sso_server, sso_api_server,  auth_callback_url) {
    return function *() {
        let code = this.query.code;
        console.log('Get token by code: ' + code);

        if (code) {
            let code_check_url = sso_api_server + '/api/code/check?code=' + code;
            let jsonStr = yield rp(code_check_url);
            let json = JSON.parse(jsonStr);

            if (json.status) {
                let redirectUrl = this.session.currentUrl || '/';
                this.session.token = json.result;

                let jsonAccountStr = yield rp(sso_api_server + '/api/getUserInfo?token=' + json.result);
                let jsonAccount = JSON.parse(jsonAccountStr);
                if (!jsonAccount.status) {
                    console.warn('Get the account failed, because ' + jsonAccount.message);
                } else {
                    this.session.account = jsonAccount.result;
                }

                this.redirect(redirectUrl);
                console.log('Get the token: ' + json.result + ', and redirect to ' + redirectUrl);
            } else {
                let redirectUrl = sso_server + '?auth_callback='+ auth_callback_url;
                this.redirect(redirectUrl);

                console.warn('Get the token result:  ' + jsonStr + ', and redirect to ' + redirectUrl);
            }

        } else {
            this.body = { status: false, message: 'Not found code.' };
        }
    }
}


module.exports = {SSOMiddleware, AuthorizationUtils};