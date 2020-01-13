/**
 * SignApp v0.0.1
*/
const express = require('express');
const bodyParser = require('body-parser')
const axios = require('axios');

const utils = require('./utilities.js');
const credentials = require('./credentials.json');

process.on('unhandledRejection', (reason, p) => {
	console.log(reason.stack);
});

const data = { users: {}, contracts: {} };

const addUser = (email) => {
  if (typeof data.users[email] !== 'undefined') return false; // email exists
  const keyPair = utils.createKeyPair();
  data.users[email] = {
    email,
    privKey: keyPair.privateKey,
    pubKey: keyPair.publicKey,
  };
  utils.sendEmail(email,`Thank you for setting up an account on the JSE Sign App<br><br>Your private key  is:<br>${data.users[email].privKey}`);
  return { email, pubKey: keyPair.publicKey };
};

const addContract = (filename,hash,email) => {
  if (typeof data.users[email] === 'undefined') return false;
  data.contracts[hash] = {
    filename,
    hash,
    owner: email,
    signatures: [],
    blockHash: false,
    uploadedTS: new Date().getTime(),
    finalisedTS: false,
    blockID: false,
  }
  console.log('New Contract: '+hash);
  return data.contracts[hash];
};

const getContract = (ref) => {
  if (data.contracts[ref] === undefined) return false; // contract not found
  return data.contracts[ref];
};

const signContract = (ref,email,signature,callback) => {
  if (typeof data.users[email] === 'undefined') return false; // email not found
  if (data.contracts[ref] === undefined) return false; // contract not found
  console.log(data.contracts[ref].hash,data.users[email].pubKey,signature);
  utils.verifyHash(data.contracts[ref].hash,data.users[email].pubKey,signature,
    () => {
      const signed = {
        email,
        pubKey: data.users[email].pubKey,
        signature,
        timestamp: new Date().getTime(),
      }
      data.contracts[ref].signatures.push(signed);
      callback({ success:true });
    },
    () => { callback({ success:false }); }
  );
  return false;
};

const finaliseContract = (ref,callback) => {
  if (data.contracts[ref] === undefined) return false; // contract not found
  if (data.contracts[ref].blockHash !== undefined) {
    delete data.contracts[ref].blockHash; // prevent data change because of previous stamp;
    delete data.contracts[ref].finalisedTS;
  }
  data.contracts[ref].blockHash = utils.sha256(JSON.stringify(data.contracts[ref]));
  const url = `https://api.jsecoin.com/enterprise/sethash/${credentials.apiKey}/${data.contracts[ref].blockHash}/`;
  axios.get(url).then((response) => {
    const result = response.data;
    data.contracts[ref].blockID = result.blockID;    
    data.contracts[ref].finalisedTS = new Date().getTime();
    callback({ success:true,  contract:data.contracts[ref] });
  });
  return false
};

const startServer = () => {
  const app = express();
  app.use(function(req, res, next) {
    if (req.method === 'OPTIONS') {
      const headers = {};
      headers["Access-Control-Allow-Origin"] = "*";
      headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS";
      headers["Access-Control-Allow-Credentials"] = false;
      headers["Access-Control-Allow-Headers"] = "cache-control, Origin, X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept, Authorization";
      res.writeHead(200, headers);
      res.end();
    } else {
      res.header("Access-Control-Allow-Origin", "*");
      res.header("Access-Control-Allow-Headers", "cache-control, Origin, X-Requested-With, Content-Type, Accept, Authorization");
      next();
    }
  });
  app.use(bodyParser.json());
  app.get('/', (req, res) => {
    res.send('Sign App v0.0.1');
  });
  app.post('/newuser/', (req, res) => {
    const email = utils.cleanString(String(req.body.email)).toLowerCase();
    const newUser = addUser(email);
    res.send(JSON.stringify(newUser));
  });
  app.post('/newcontract/', (req, res) => {
    const filename = utils.cleanString(String(req.body.filename));
    const hash = utils.cleanString(String(req.body.hash)).toLowerCase();
    const email = utils.cleanString(String(req.body.email)).toLowerCase();
    const newContract = addContract(filename,hash,email);
    res.send(JSON.stringify(newContract));
  });
  app.post('/getcontract/', (req, res) => {
    const ref = utils.cleanString(String(req.body.ref)).toLowerCase();
    console.log('ref.'+ref);
    const contract = getContract(ref);
    res.send(JSON.stringify(contract));
  });
  app.post('/signcontract/', (req, res) => {
    const ref = utils.cleanString(String(req.body.ref)).toLowerCase();
    const email = utils.cleanString(String(req.body.email)).toLowerCase();
    const signature = utils.cleanString(String(req.body.signature));
    signContract(ref,email,signature,(returnObject) => {
      res.send(JSON.stringify(returnObject));
    });
  });
  app.post('/finalisecontract/', (req, res) => {
    const ref = utils.cleanString(String(req.body.ref)).toLowerCase();
    finaliseContract(ref,(returnObject) => {
      res.send(JSON.stringify(returnObject));
    });
  });
  app.listen(300, () => console.log('SignApp running on port 300!'));
}

startServer();