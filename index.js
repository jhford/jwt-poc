'use strict';

const jwt = require('jsonwebtoken');
const normalizeUrl = require('normalize-url');
const urllib = require('url');

const SECRET = 'Spree';

const API_ENDPOINT = 'https://objects.taskcluster.net/objects/';

// Sign a URL with a signature valid for 5 minutes
function signOperation(operation, name) {
  let signedUrl = new URL(API_ENDPOINT + name);

  let token = jwt.sign({
    resourceType: 'object',
    operation,
    name, // consuer using 'sub' instead?
  }, SECRET, {
    expiresIn: '5m',
    // TEST A nbf (notBefore) VALUE!!!
    algorithm: 'HS256',
    issuer: signedUrl.origin,
    // consider using aud to add IP blocks?  doubt it's a good idea, but if we
    // were doing IP lookup, we could do something like sign the URL such that
    // a URL requested in us-west-2 is only valid in us-west-2 IP blocks.
    // Since we're using IP blocks large enough that we don't own all of them
    // it's probably not worthwhile
  });

  console.log('Your Token is: ' + token);

  // Clear out other token values since we want to have only one.
  signedUrl.searchParams.delete('token');
  signedUrl.searchParams.append('token', token);

  let method;
  switch(operation) {
    case 'initiate':
      method = 'PUT';
      break;
    case 'delete':
      method = 'DELETE';
      break;
    case 'complete':
      method = 'PATCH';
      break;
    case 'retreive':
      method = 'GET';
      break;
    default:
      throw new Error('Unsupported Operation: ' + operation + ' on ' + name);
  }

  return {url: signedUrl, method};
}

// Verify this signed URL
function verifySignedUrl({method, signedUrl}) {
  let url = new URL(signedUrl);

  // We're going to get the Token from the URL and then remove it
  // for comparison later
  let token = url.searchParams.get('token');
  if (Array.isArray(token)) {
    throw new Error('Signed URL incorrectly has multiple signing tokens');
  }
  url.searchParams.delete('token');
  if (!token) {
    throw new Error('Token not found: ' + signedUrl.searchParams);
  }

  let decoded = jwt.verify(token, SECRET, {
    issuer: new URL(API_ENDPOINT).origin,
  });

  let requiredMethod;
  switch(decoded.operation) {
    case 'initiate':
      requiredMethod = 'PUT';
      break;
    case 'delete':
      requiredMethod = 'DELETE';
      break;
    case 'complete':
      requiredMethod = 'PATCH';
      break;
    case 'retreive':
      requiredMethod = 'GET';
      break;
    default:
      throw new Error('Unsupported Operation: ' + operation + ' on ' + name);
  }

  if (method !== requiredMethod) {
    throw new Error(`URL was signed for ${requiredMethod} but got ${method}`);
  }

  console.log(`Authorized to ${decoded.operation} the ${decoded.resourceType} ${decoded.name}`);
}

let {url: signedUrl, method} = signOperation('initiate', 'testing-object-1');
console.log(`Signed URL for ${method} of ${signedUrl}`);


verifySignedUrl({signedUrl, method});
