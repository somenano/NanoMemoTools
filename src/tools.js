/**
 * NanoMemoTools.tools module
 * @module NanoMemoTools/tools
 */

// Thanks to https://github.com/dvdbng/nano-lib for a code in the signing portions of this module

const NanoCurrency = require('nanocurrency');
const ed2curve = require('../lib/ed2curve-blake2b/ed2curve-blake2b');
const nacl = require('tweetnacl-blake2b');
const blake2b = require('blakejs/blake2b');

const MAGIC_STRING = 'Nano Signed Message:\n';

/**
 * Encodes Uint8Array as hex string
 * @private
 * @param {Uint8Array} uint8arr array iterable to encode as string 
 * @returns {string} encoded string
 */
function hexEncode (uint8arr) {
    return Array.from(uint8arr).map(function(x) {
      return ('0' + x.toString(16)).substr(-2)
    }).join('');
}

/**
 * Decodes hex string as Uint8Array
 * @private
 * @param {string} hexString string to decode as Uint8Array 
 * @returns {string} encoded array
 */
function hexDecode (hexString) {
    if ((hexString.length % 2) !== 0) throw new Error('can only decode whole bytes');
    if (/[^0-9a-f]/ig.test(hexString)) throw new Error('invalid hex string');
    const out = new Uint8Array(hexString.length / 2);
    for (var i = 0, len = out.length; i < len; i++) {
      out[i] = parseInt(hexString.substr(i * 2, 2), 16);
    }
    return out;
}

/**
 * Hashes given string into string of hex 32 long
 * @private
 * @param {string} msg string to hash 
 * @returns {string} 32-long hex string
 */
function msgHash (msg) {
    return blake2b.blake2b(MAGIC_STRING + msg, null, 32);
}

/**
 * Hashes given string into string of hex 24 long
 * @private
 * @param {string} nonce string to hash 
 * @returns {string} 24-long hex string
 */
function nonceHash (nonce) {
    return blake2b.blake2b(MAGIC_STRING + nonce, null, 24);
}

/**
* This function calculates and returns a 128-hex string signature for given string buffer
* @public
* @param {string} buffer value to sign
* @param {string} private_key 64-hex string private key
* @param {number} [version=undefined] version of signature algorithm - not yet implemented
* @returns {string} 128-hex string signature
*/
const sign = function(buffer, private_key, version=undefined) {
    const key = nacl.sign.keyPair.fromSeed(hexDecode(private_key)).secretKey;
    return hexEncode(nacl.sign.detached(msgHash(buffer), key));
}

/**
 * This function verifies a given signature is true for given buffer and key
 * @public
 * @param {string} buffer string on which the signature is mapped
 * @param {string} public_key 64-hex string public key of keypair that signed the buffer
 * @param {string} signature 128-hex string signature of public_key on buffer
 * @param {number} version version of signature algorithm - not yet implemented
 * @returns {boolean} true for verified, false otherwise
 */
const verify = function(buffer, public_key, signature, version=undefined) {
    return nacl.sign.detached.verify(msgHash(buffer), hexDecode(signature), hexDecode(public_key));
}

/**
 * This function encrypts a message
 * @public
 * @param {string} message message to encrypt
 * @param {string} nonce unique nonce to increase entropy
 * @param {string} decrypting_public_key 64-hex encrypting public key
 * @param {string} signing_private_key 64-hex signing private key
 * @param {number} version version of encryption algorithm - not yet implemented
 * @returns {string} string representing encrypted message
 */
const encryptMessage = function(message, nonce, decrypting_public_key, signing_private_key, version=undefined) {
    // Convert from signing keys (Ed25519 ) to encryption keys (Curve25519)
    
    const signKey = nacl.sign.keyPair.fromSeed(hexDecode(signing_private_key));
    const dh_decrypting_public_key = Buffer.from(ed2curve.convertPublicKey(hexDecode(decrypting_public_key))).toString('hex');
    const dh_signing_private_key = Buffer.from(ed2curve.convertSecretKey(signKey.secretKey)).toString('hex');
    
    return hexEncode(nacl.box(Buffer.from(message), nonceHash(nonce), hexDecode(dh_decrypting_public_key), hexDecode(dh_signing_private_key)));
}

/**
 * This function decrypts a message
 * @public
 * @param {string} cipher_text encrypted message to decrypt
 * @param {string} nonce unique nonce to increase entropy
 * @param {string} signing_public_key 64-hex signing public key
 * @param {string} decrypting_private_key 64-hex decrypting private key
 * @param {number} version version of encryption algorithm - not yet implemented
 * @returns {string} string representing unencrypted message
 */
const decryptMessage = function(cipher_text, nonce, signing_public_key, decrypting_private_key, version=undefined) {
    // Convert from signing keys (Ed25519 ) to encryption keys (Curve25519)
    
    const signKey = nacl.sign.keyPair.fromSeed(hexDecode(decrypting_private_key));
    const dh_signing_public_key = Buffer.from(ed2curve.convertPublicKey(hexDecode(signing_public_key))).toString('hex');
    const dh_decrypting_private_key = Buffer.from(ed2curve.convertSecretKey(signKey.secretKey)).toString('hex');

    return Buffer.from(nacl.box.open(hexDecode(cipher_text), nonceHash(nonce), hexDecode(dh_signing_public_key), hexDecode(dh_decrypting_private_key))).toString('ascii');
}

/**
 * Derive a Nano Account's private key from a seed and index
 * @public
 * @param {string} seed 64-hex string representing a Nano seed
 * @param {number} index index value of account
 * @returns {string} 64-hex private key
 */
const getPrivateKey = function(seed, index) {
    return NanoCurrency.deriveSecretKey(seed, index);
}

/**
 * Derive a Nano Account's public key from a private key
 * @public
 * @param {string} private_key 64-hex string representing a private key
 * @returns {string} 64-hex public key
 */
const getPublicKeyFromPrivateKey = function(private_key) {
    return NanoCurrency.derivePublicKey(private_key);
}

/**
 * Derive a Nano Account's public key from a Nano address
 * @public
 * @param {string} address Nano address; nano_* or xrb_*
 * @returns {string} 64-hex public key
 */
const getPublicKeyFromAddress = function(address) {
    return NanoCurrency.derivePublicKey(address);
}

/**
 * Derive a Nano Account's address from a Nano public key
 * @public
 * @param {string} public_key 64-hex string representing a public key
 * @returns {string} Nano address: nano_*
 */
const getAddress = function(public_key) {
    return NanoCurrency.deriveAddress(public_key).replace('xrb_', 'nano_');
}

module.exports = {
    sign,
    verify,
    encryptMessage,
    decryptMessage,
    getPrivateKey,
    getPublicKeyFromAddress,
    getPublicKeyFromPrivateKey,
    getAddress
}