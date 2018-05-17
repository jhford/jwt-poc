'use strict';
let request = require('request-promise-native').defaults({
  resolveWithFullResponse: true,
  simple: false,
});
let assume = require('assume');
let uuid = require('uuid').v4;

let {app, hostname, protocol, port} = require('./index');

describe('object service authorization', () => {

  let server;
  let objectName = 'testing-object-1';
  let objectUrl = `${protocol}//${hostname}:${port}/objects/${objectName}`;
  let object;

  let getCreds;

  before(done => {
    server = app.listen(port, done);
    getCreds = async function (op, nm) {
      let res = await request.get(`${protocol}//${hostname}:${port}/sign-object-url/operation/${op}/name/${nm}`);
      return JSON.parse(res.body);
    }
  });

  beforeEach(() => {
    object = uuid();
  });

  after(done => {
    server.close(done);
    getCreds = undefined;
  });

  it('should be able to generate signed urls', async () => {
    let response = await request.get(`${protocol}//${hostname}:${port}/sign-object-url/operation/get/name/a`);
    assume(response).has.property('statusCode', 200);
    assume(response).has.property('body');
  });

  it('should fail with an invalid operation', async () => {
    let response = await request.get(`${protocol}//${hostname}:${port}/sign-object-url/operation/junk/name/a`);
    assume(response).has.property('statusCode', 400);
  });

  describe('operations should work', () => {
    it('should be able to operate on an object with signed url', async () => {
      async function makeReq(op, method, reqStatus, body) {
        let {signedUrl} = await getCreds(op, objectName);
        let response = await request[method](signedUrl, {body});
        assume(response).has.property('statusCode', reqStatus);
        if (reqStatus === 200) {
          assume(response).has.property('body', object);
        }
      }
      await makeReq('get', 'get', 404);
      await makeReq('create', 'put', 204, object);
      await makeReq('get', 'get', 404);
      await makeReq('create', 'patch', 204);
      await makeReq('get', 'get', 200);
      await makeReq('delete', 'delete', 204);
      await makeReq('get', 'get', 404);
    });

    it('should be able to operate on an object with authorization header', async () => {
      async function makeReq(op, method, reqStatus, body) {
        let {token, url} = await getCreds(op, objectName);
        let response = await request[method](url, {headers: {Authorization: token}, body});
        assume(response).has.property('statusCode', reqStatus);
        if (reqStatus === 200) {
          assume(response).has.property('body', object);
        }
      }
      await makeReq('get', 'get', 404);
      await makeReq('create', 'put', 204, object);
      await makeReq('get', 'get', 404);
      await makeReq('create', 'patch', 204);
      await makeReq('get', 'get', 200);
      await makeReq('delete', 'delete', 204);
      await makeReq('get', 'get', 404);
     });
  });

  describe('authentication errors', () => {
    it('should fail when no token is present', async () => {
      let {url} = await getCreds('create', objectName);
      let response = await request.put(url);
      assume(response).has.property('statusCode', 403);
    });
    
    it('should fail when conflicting tokens are present', async () => {
      let {signedUrl} = await getCreds('create', objectName);
      let {token} = await getCreds('create', 'notright1');
      let response = await request.put(signedUrl, {headers: {Authorization: token}});
      assume(response).has.property('statusCode', 403);
    });

    it('should fail when the wrong operation is attempted', async () => {
      let {signedUrl} = await getCreds('create', objectName);
      let response = await request.get(signedUrl);
      assume(response).has.property('statusCode', 403);
    });
  });
});
