'use strict';

const jwt = require('jsonwebtoken');
const SECRET = 'Spree';


const express = require('express');
const bodyParser = require('body-parser');

const app = express();

let protocol = 'http:'
let hostname = 'localhost'
let port = process.env.PORT || 3000;

function mapMethodToOperation(method) {
  switch(method.toLowerCase()) {
    case 'patch':
    case 'put':
      return 'create';
    case 'delete':
      return 'delete';
    case 'get':
      return 'get';
    default:
      throw new Error('unsupported method: ' + method);
  }
}

const objectsApi = express.Router();

objectsApi.use(bodyParser.raw({type: () => true}));

objectsApi.use((req, res, next) => {
  // We support setting the token in the Authorization header or
  // as the 'token=' query parameter
  let token;
  if (req.headers.authorization && req.query.token) {
    if (req.headers.authorization !== req.query.token) {
      return res.status(403).end('conflicting authorization tokens');  
    }
  }

  if (req.headers.authorization) {
    token = req.headers.authorization;
  } else if (req.query.token) {
    token = req.query.token;
  }

  if (!token) {
    return res.status(403).end('no authorization token found');
  }

  let decoded;
  try {
    decoded = jwt.verify(token, SECRET, {
      issuer: new URL(`${protocol}//${hostname}:${port}`).origin,
      algorithms: ["HS256"],  // We probably want to allow stronger but not weaker 
    });
  } catch (err) {
    console.error(err);
    return res.status(403).end(err.message);
  }

  let attemptedOperation = mapMethodToOperation(req.method);
  if (decoded.operation !== attemptedOperation) {
    return res.status(403).end(`this token is for ${decoded.operation}, but used for ${attemptedOperation}`);
  }

  next();
});

let objects = new Map();

objectsApi.get('/:name', (req, res) => {
  if (objects.has(req.params.name)) {
    let {present, value} = objects.get(req.params.name);
    if (present) {
      return res.status(200).end(objects.get(req.params.name).value);
    } else {
      // In production we would use the same message as it being not there
      return res.status(404).end('object found but not complete');
    }
  } else {
    return res.status(404).end('object not found');
  }
});

objectsApi.put('/:name', (req, res) => {
  objects.set(req.params.name, {
    value: req.body,
    present: false,
  });
  return res.status(204).end();
});

objectsApi.patch('/:name', (req, res) => {
  objects.get(req.params.name).present = true;
  return res.status(204).end();
});

objectsApi.delete('/:name', (req, res) => {
  objects.delete(req.params.name);
  return res.status(204).end();
});

app.use('/objects', objectsApi);



// This is something which would be happening in the Queue, possibly through a
// library.
app.get('/sign-object-url/operation/:operation/name/:name', (req,res) => {
  // XXX: Obviously we would never consider doing this endpoint
  // in real life.  This is just to easily get signed urls
  
  let url = new URL(`http://${hostname}:${port}/objects/${req.params.name}`);

  if (!['create', 'delete', 'get'].includes(req.params.operation)) {
    return res.status(400).end('unsupported operation');
  }

  let token = jwt.sign({
    resourceType: 'object', // Maybe could also be a cache
    operation: req.params.operation,
    name: req.params.name,
  }, SECRET, {
    expiresIn: '5m',
    notBefore: '0ms',
    algorithm: 'HS256',
    issuer: url.origin,
  });

  // Let's get the Token and String for doing Header based authorization
  let response = {token, url: url.toString()};

  // But we hold off on mutating the url until we've already
  // serialised a copy of the unsigned url
  url.searchParams.set('token', token);

  response.signedUrl = url.toString();

  res.status(200).end(JSON.stringify(response));
});

module.exports = {app, hostname, protocol, port};

if (!module.parent) {
  app.listen(port, () => console.log('listening on :' + port));
}
