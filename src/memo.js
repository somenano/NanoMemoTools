/**
 * NanoMemoTools.memo module
 * @module NanoMemoTools/memo
 */

const version = require('./version');
const tools = require('./tools');
const node = require('./node');
const NanoCurrency = require('nanocurrency');

/**
* This function validates a given message
* @public
* @param {string} message message to validate
* @param {number} [maxlength=512] configurable maxlength of message
* @returns {boolean} true for validated message, false otherwise
*/
const validateMessage = function(message, maxlength=512) {
  try {
    message = message.toString('ascii');
    if (message.length > maxlength) return false;
    return true;
  } catch(e) {
    return false;
  }
}
module.exports.validateMessage = validateMessage;

/**
* This function validates a given signature
* @public
* @param {string} signature 128-hex string representing a signature
* @returns {boolean} true for validated signature, false otherwise
*/
const validateSignature = function(signature) {
  try {
      if (signature.length != 128) return false;
      return true;
  } catch(e) {
      return false;
  }
}
module.exports.validateSignature = validateSignature;

/**
* This function validates a given key (public or private)
* @public
* @param {string} key 64-hex string representing a key
* @returns {boolean} true for validated key, false otherwise
*/
const validateKey = function(key) {
  try {
      return NanoCurrency.checkKey(key);
  } catch(e) {
      return false;
  }
}
module.exports.validateKey = validateKey;

/**
* This function validates a given address
* @public
* @param {string} address Nano address
* @returns {boolean} true for validated address, false otherwise
*/
const validateAddress = function(address) {
  try {
      return NanoCurrency.checkAddress(address);
  } catch(e) {
      return false;
  }
}
module.exports.validateAddress = validateAddress;

/**
* This function validates a given hash
* @public
* @param {string} hash 64-hex string representing a Nano block hash
* @returns {boolean} true for validated hash, false otherwise
*/
const validateHash = function(hash) {
  try {
      return NanoCurrency.checkHash(hash);
  } catch(e) {
      return false;
  }
}
module.exports.validateHash = validateHash;

/**
 * This function validates one or more Memos against the Nano Network; No username/password required if connecting to DEFAULT_SERVER or public API
 * @param {array} memos Array of Memos to validate against the Nano Network
 * @param {string} [url=node.DEFAULT_SERVER] url of Nano Node RPC
 * @param {string} [username=undefined] username for Nano Node RPC authentication
 * @param {string} [password=password] password for Nano Node RPC authentication
 * @returns {object} { valid: [<array of hashes>], invalid: [<array of hashes>], not_found: [<array of hashes>] }; returns undefined on error
 */
 const nodeValidated = async function(memos, url=node.DEFAULT_SERVER, username=undefined, password=undefined) {

  let ret = {
    valid: [],
    invalid: [],
    not_found: []
  }

  let local_valid_memos = [];
  let local_invalid_memos = [];
  for (let memo of memos) {
    if (memo.valid_signature) local_valid_memos.push(memo);
    else local_invalid_memos.push(memo.hash);
  }

  // Return early if there are no valid memos to check
  // if (local_valid_memos.length == 0) return ret;

  // Query node
  const response = await node.blocks_info(memos.map(memo => memo.hash), url, username, password).catch(function(e) {
    console.error('In memo.nodeValidated, an error was caught running node.blocks_info');
    console.error(memos.map(memo => memo.hash));
    console.error(e);
    return undefined;
  });
  if (!response || (!response.blocks && !response.blocks_not_found)) {
    // Invalid response
    console.error('In memo.nodeValidate, no response was received from node.blocks_info');
    return undefined;
  }
  if (response.blocks == '') response.blocks = {};
  if (response.blocks_not_found == '') response.blocks_not_found = {};

  // Memo has already been validated with the signing_address
  // Don't compare addresses because nano_ or xrb_ prefixes may not match, so convert to public key
  //  and compare to be same
  for (let memo of memos) {

    if (response.blocks[memo.hash] !== undefined) {
      // Block exists exists on the Nano Network
      const block = response.blocks[memo.hash];
      const block_signing_public_key = tools.getPublicKeyFromAddress(block.block_account);
      if (memo.valid_signature && memo.signing_public_key.toUpperCase() == block_signing_public_key.toUpperCase()) {
        // Memo is valid and matches keys with the block
        ret.valid.push(memo.hash);
      } else {
        ret.invalid.push(memo.hash);
      }
    } else {
      ret.not_found.push(memo.hash);
    }
  }

  return ret;
}
module.exports.nodeValidated = nodeValidated;

/**
* This function converts a Memo into an EncryptedMemo Object
* @public
* @param {Memo} memo Memo Object to convert
* @param {string} signing_private_key 64-hex string representing a Nano Account's private key
* @param {string} decrypting_address Nano address whose will be able to decrypt the memo
* @param {number} [version_encrypt=undefined] version of encryption algorithm - Versioning not yet implemented
* @returns {EncryptedMemo} EncryptedMemo Object with the message encrypted
*/
module.exports.encrypt = function(memo, signing_private_key, decrypting_address, version_encrypt=undefined) {

  // Validate inputs
  if (!validateKey(signing_private_key)) {
    throw new TypeError('Invalid signing_private_key');
  }
  if (!validateAddress(decrypting_address)) {
    throw new TypeError('Invalid decrypting_address');
  }
  const decrypting_public_key = tools.getPublicKeyFromAddress(decrypting_address);

  // The hash is used as the nonce for encryption
  const encrypted_message = tools.encryptMessage(
    memo.message,
    memo.hash,
    decrypting_public_key,
    signing_private_key,
    version_encrypt
  );
  
  // Clear signature as message has changed
  const encrypted_memo = new EncryptedMemo(
    memo.hash,
    encrypted_message,
    memo.signing_address,
    decrypting_address,
    undefined,
    memo.version_sign,
    version_encrypt
  );
  
  return encrypted_memo;
}

/**
* This function converts an EncryptedMemo into a Memo Object
* @public
* @param {EncryptedMemo} encrypted_memo EncryptedMemo Object to convert
* @param {string} decrypting_private_key 64-hex string representing a Nano Account's private key
* @returns {Memo} Memo Object with the message as plaintext
*/
module.exports.decrypt = function(encrypted_memo, decrypting_private_key) {

  // The hash is used as the nonce for encryption
  const decrypted_message = tools.decryptMessage(
    encrypted_memo.message,
    encrypted_memo.hash,
    encrypted_memo.signing_public_key,
    decrypting_private_key,
    encrypted_memo.version_encrypt
  );

  // Clear signature as message has changed
  const decrypted_memo = new Memo(
    encrypted_memo.hash,
    decrypted_message,
    encrypted_memo.signing_address,
    undefined,
    encrypted_memo.version_sign
  );
  
  return decrypted_memo;
}

/** Class representing a Memo (with plaintext message) */
class Memo {

  /**
   * Creates a Memo
   * @param {string} hash 64-hex string representing a Nano block hash
   * @param {string} message message of memo
   * @param {string} signing_address Nano address that owns block with hash
   * @param {string} [signature=undefined] 128-hex string signature of memo
   * @param {number} [version_sign=version.sign] version of signing algorithm - Versioning not yet implemented
   */
  constructor (hash, message, signing_address, signature=undefined, version_sign=version.sign) {
    this.message = undefined;
    this.hash = undefined;
    this.signing_address = undefined;
    this.signature = undefined;
    this.version_sign = undefined;

    // Validate inputs
    if (validateHash(hash)) {
      this.hash = hash;
    } else {
      throw new TypeError('Invalid hash parameter');
    }

    if (validateMessage(message)) {
      this.message = message;
    } else {
      throw new TypeError('Invalid message parameter');
    }

    if (validateAddress(signing_address)) {
      this.signing_address = signing_address;
    } else {
      throw new TypeError('Invalid signing_address parameter');
    }

    if (signature) {  // Optional argument
      if (validateSignature(signature)) {
        this.signature = signature;
      } else {
        throw new TypeError('Invalid signature parameter');
      }
    }

    this.version_sign = version_sign;
  }

  /**
   * Getter for signing_public_key
   * @returns {string} value of signing public_key, derived from signing_address
   */
  get signing_public_key() {
    return tools.getPublicKeyFromAddress(this.signing_address);
  }

  /**
   * Getter for valid_signature
   * @returns {boolean} True if signature is valid, false otherwise
   */
  get valid_signature() {
    if (!this.signature) return false;

    // Signed buffer is concatenation of the message and the hash
    const buffer = this.message + this.hash;
    return tools.verify(buffer, this.signing_public_key, this.signature);
  }

  /**
   * Getter for is_encrypted
   * @returns {boolean} True if memo is encrypted, false otherwise
   */
  get is_encrypted() {
    return false;
  }

  /**
   * Calculates and signs the memo
   * @param {string} signing_private_key 64-hex private key of Nano Account that owns the memo
   * @param {number} [version_sign=undefined] version of signing algorithm - Versioning not yet implemented
   * @returns {string} 128-hex signature
   */
  sign(signing_private_key, version_sign=undefined) {

    // Update sign version
    if (version_sign !== undefined) this.version_sign = version_sign;

    // Validate inputs
    if (!validateKey(signing_private_key)) {
      throw new TypeError('Invalid signing_private_key parameter');
    }

    // Signed buffer is concatenation of the message and the hash
    const buffer = this.message + this.hash;
    this.signature = tools.sign(buffer, signing_private_key);
    return this.signature;
  }

}
module.exports.Memo = Memo;

/** Class representing an EncryptedMemo (with ciphertext message)
 * @extends Memo
*/
class EncryptedMemo extends Memo {

  /**
   * Creates an EncryptedMemo
   * @param {string} hash 64-hex string representing a Nano block hash
   * @param {string} encrypted_message encrypted message of memo
   * @param {string} signing_address Nano address that owns block with hash
   * @param {string} decrypting_address Nano address that will be able to decrypt and read the message
   * @param {string} [signature=undefined] 128-hex string signature of memo
   * @param {number} [version_sign=version.sign] version of signing algorithm - Versioning not yet implemented
   * @param {number} [version_encrypt=undefined] version of encryption algorithm - Versioning not yet implemented
   */
  constructor(hash, encrypted_message, signing_address, decrypting_address, signature=undefined, version_sign=version.sign, version_encrypt=undefined) {
    super(hash, encrypted_message, signing_address, signature, version_sign);
    this.decrypting_address = undefined;
    this.version_encrypt = undefined;

    if (validateAddress(decrypting_address)) {
      this.decrypting_address = decrypting_address;
    } else {
      throw new TypeError('Invalid decrypting_address parameter');
    }

    this.version_encrypt = version_encrypt;
  }

  /**
   * Getter for is_encrypted
   * @returns {boolean} True if memo is encrypted, false otherwise
   */
  get is_encrypted() {
    return true;
  }

}
module.exports.EncryptedMemo = EncryptedMemo;