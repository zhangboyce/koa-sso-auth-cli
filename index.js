'use strict';

let koa_session = require('koa-session');
let rp = require('request-promise');
let router = require('koa-router')();

module.exports = function(opts, app){

    if (!opts || !opts.sso_server || !opts.sso_client) {
        throw new Error('the opts is illegal.');
    }
    if (!app || typeof app.use !== 'function') {
        throw new Error('the app is illegal.');
    }

    app.keys = app.keys || ['koa-sso-auth-cli-2016','keys'];
    if (!app.context.sessionKey) app.use(koa_session(app));

    let sso_server = opts['sso_server'];
    let sso_client = opts['sso_client'];

    let auth_callback_url = sso_client + '/api/getToken';
    auth_callback_url = encodeURIComponent(auth_callback_url);

    router.get('/api/getToken', getToken(sso_server, auth_callback_url));
    app.use(router.routes()).use(router.allowedMethods());

    return auth(sso_server, auth_callback_url);
};

function auth(sso_server, auth_callback_url) {
    return function *(next) {
        let token = this.session.token;
        let redirectUrl = sso_server + '?auth_callback='+ auth_callback_url;

        if (token) {
            let token_check_url = sso_server + '/api/token/check?token=' + token;
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

function getToken(sso_server, auth_callback_url) {
    return function *() {
        let code = this.query.code;
        console.log('Get token by code: ' + code);

        if (code) {
            let code_check_url = sso_server + '/api/code/check?code=' + code;
            let jsonStr = yield rp(code_check_url);
            let json = JSON.parse(jsonStr);

            if (json.status) {
                let redirectUrl = this.session.currentUrl || '/';
                this.session.token = json.result;

                let jsonAccountStr = yield rp(sso_server + '/api/getUserInfo?token=' + json.result);
                let jsonAccount = JSON.parse(jsonAccountStr);
                if (!jsonAccount.status) {
                    console.warn('Get the account failed, because ' + jsonAccount.message);
                } else {
                    this.session.account = JSON.parse(jsonAccount.result);
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