const sr = require('secure-random');
const crypto = require('crypto');
const eccrypto = require("eccrypto");

/**
 * @method <h2>cleanString</h2>
 * @description User input sanitization, uses this regex /[^ .$*+?\\\-_:/,@a-zA-Z0-9\s]/
 * @param {string} stringRaw string to be cleaned
 * @returns {string} cleaned string
 */
function cleanString(stringRaw) {
	let stringClean = stringRaw;
	stringClean = String(stringClean);
	stringClean = stringClean.split(/[^ .$*+?\\\-_:/&=,{}@a-zA-Z0-9\s]/).join('');
	stringClean = stringClean.substr(0, 255);
	return stringClean;
}

/**
 * @method <h2>sha256</h2>
 * @description Standard SHA256 function, returns a Sha256 hash of the provided data string
 * @param {string} data data to be hashed
 * @returns {string} returns a SHA256 hash
 */
function sha256(data) {
	return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * @method <h2>buf2hex</h2>
 * @description Converts a buffer to a hexadecimal string
 * @param {array} buffer Array Buffer
 * @returns {string} returns a hex string
 */
function buf2hex(buffer) { // buffer is an ArrayBuffer
	return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

/**
 * @method <h2>hex2buf</h2>
 * @description Converts a hexadecimal string to an array buffer
 * @param {string} hex hex string
 * @returns {array} returns an array buffer
 */
function hex2buf(hex) {
	const array = new Uint8Array(hex.length / 2);
	let k = 0;
	for (let i=0; i<hex.length; i+=2) {
		array[k] = parseInt(hex[i] + hex[i+1], 16);
		k+=1;
	}
	const buffer = Buffer.from(array.buffer);
	return buffer;
}

/**
 * @method <h2>createKeyPair</h2>
 * @description Creates a new private and public key
 * @returns {object} returns an object including object.privateKey and object.publicKey
 */
function createKeyPair() {
	const privateKey = sr.randomBuffer(32);
	const privateKeyString = buf2hex(privateKey);
	const publicKey = eccrypto.getPublic(privateKey);
	const publicKeyString = buf2hex(publicKey);
	const keyPair = {};
	keyPair.privateKey = privateKeyString;
	keyPair.publicKey = publicKeyString;
	return keyPair;
}

/**
 * @method <h2>signHash</h2>
 * @description More basic function just for signing, will probably work with any hex string
 * @param {string} hash A hash of the data
 * @param {string} privateKeyHex private key to sign data with
 * @param {function} callback callback with the signature string
 */
function signHash(hash, privateKeyHex ,callback) {
	const shaBuffer = hex2buf(hash);
	const privateKey = hex2buf(privateKeyHex);
	eccrypto.sign(privateKey, shaBuffer).then(function(signatureArrayBuffer) {
		const signatureString = buf2hex(signatureArrayBuffer);
		callback(signatureString);
	});
}

/**
 * @method <h2>verifyHash</h2>
 * @description Verify a signed hash using public key and signature
 * @param {string} hash hexFormat sha256 hash of the data
 * @param {string} publicKeyHex public key that signed the data
 * @param {string} signatureHex signature attached to the signed hash
 * @param {function} successCallback blank callback if valid
 * @param {function} failCallback blank callback if not valid
 */
function verifyHash(hash, publicKeyHex, signatureHex, successCallback, failCallback) {
	const shaBuffer = hex2buf(hash);
	const publicKey = hex2buf(publicKeyHex);
	const signature = hex2buf(signatureHex);
	eccrypto.verify(publicKey, shaBuffer, signature).then(function() {
		successCallback();
	}).catch(function(err) {
		console.log('Unable to Verify Data. verifyHash() Error: 104. '+err);
		failCallback();
	});
}

function sendEmail(email,messageHTML) {
  // use sendgrid to send email
  console.log(messageHTML);
}

module.exports = {
 cleanString,sha256,createKeyPair,signHash,verifyHash,sendEmail,
};
