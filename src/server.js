/**
 * NanoMemoTools.server module
 * @module NanoMemoTools/server
 */

const network = require('./network.js');
const node = require('./node');
const Memo = require('./memo.js');
let SERVER = 'https://nanomemo.cc';
let WSS = 'wss://nanomemo.cc';

/**
* This function gathers user data from the server
* @public
* @param {string} api_key user public api key
* @param {string} api_secret user private secret key
* @param {string} [endpoint=/api/user/] endpoint of POST request
* @returns {Promise} Promise object represents the user data as an object
*/
const getUserData = async function(api_key, api_secret, endpoint='/api/user') {
    
    const data = {
        api_key: api_key,
        api_secret: api_secret
    }
    return network.post(SERVER + endpoint, data);
}

/**
* This function gathers a memo's data from the server
* @public
* @param {string} hash 64-hex hash that represents a Nano Block
* @param {string} [endpoint=/api/memo/block/] endpoint of POST request
* @returns {Promise} Promise object represents the memo object 
*/
const getMemo = async function(hash, endpoint='/api/memo/block/') {
    if (!Memo.validateHash(hash)) {
        console.error('In NanoMemoTools.server.getMemo, hash failed validation');
        return undefined;
    }

    let response = await network.get(SERVER + endpoint + hash);
    if (response === undefined || response === null) {
        return {
            success: false,
            dtg: new Date(),
            error: 'No response returned'
        }
    }
    if (response.error !== undefined) return response;

    // Get corresponding block data
    const block = await node.block_info(response.data.hash).catch(function(e) {
        console.error('In NanoMemoTools.server.getMemo, error caught when running node.block_info for hash: '+ response.data.hash);
        console.error(e);
        return undefined;
    });
    if (block === undefined || block === null) {
        console.error('In NanoMemoTools.server.getMemo, no block data returned for hash: '+ response.data.hash);
        return undefined;
    }

    // Create Memo Object
    let memo = undefined;
    if (response.version_encrypt !== undefined) {
        // Yes, encrypted
        memo = new Memo.EncryptedMemo(response.data.hash, response.data.message, response.data.signing_address, response.data.decrypting_address, response.data.signature, response.data.version_sign, response.data.version_encrypt);
    } else {
        // No, not encrypted
        memo = new Memo.Memo(response.data.hash, response.data.message, response.data.signing_address, response.data.signature, response.data.version_sign);
    }

    // Validate signature locally
    if (!memo.valid_signature) {
        console.error('In NanoMemoTools.server.getMemo, memo signature validation failed');
        return undefined;
    }

    return memo;
}

/**
* This function saves a memo to the server
* @public
* @param {Memo.Memo} memo memo data to be saved to the server
* @param {string} api_key public api key
* @param {string} api_secret private api key
* @param {string} [endpoint=/api/memo/new/] endpoint of POST request
* @returns {Promise} Promise object represents the memo object 
*/
const saveMemo = async function(memo, api_key, api_secret, endpoint='/api/memo/new') {

    if (!memo.valid_signature) {
        console.error('Memo has an invalid signature');
        return {
            success: false,
            dtg: new Date(),
            error: 'Memo has an invalid signature'
        }
    }

    const response = await network.post(SERVER + endpoint, {
        api_key: api_key,
        api_secret: api_secret,
        message: memo.message,
        hash: memo.hash,
        signing_address: memo.signing_address,
        decrypting_address: memo.decrypting_address,
        signature: memo.signature,
        version_sign: memo.version_sign,
        version_encrypt: memo.version_encrypt
    });

    return response;
}

/**
 * This function subscribes to a NanoMemo websocket that will send a message for each new memo that is saved
 * @public
 * @param {function} onmessage function to call with newly received memo data
 * @returns {websocket} websocket object 
 */
const websocketSubscribe = async function(onmessage) {
    const websocket = network.websocket(
        WSS,
        function(ws) {
            // onopen
            console.log('Connected to websocket server: '+ WSS);
            const data = {
                "action": "subscribe"
            }
            ws.send(JSON.stringify(data));
        },
        function(ws, message) {
            // onmessage
            console.log('Websocket message received from: '+ WSS);
            let data = undefined;
            try {
                data = JSON.parse(message.data);
            } catch(e) {
                console.error('Error parsing data into Object: '+ message.data);
            }
            onmessage(data);
        },
        function(ws) {
            // onclose
            console.log('Closed connection to websocket server: '+ WSS);
        },
        function(ws, e) {
            // onerror
            console.error(e);
        }
    );

    return websocket;
}

/**
 * This function unsubscribes to a NanoMemo websocket that was receiving new memos
 * @public
 * @returns undefined
 */
const websocketUnsubscribe = async function() {
    if (websocket === undefined) return;
    const data = {
        "action": "unsubscribe"
    }
    websocket.send(JSON.stringify(data));
}

module.exports = {
    getUserData,
    getMemo,
    saveMemo,
    websocketSubscribe,
    websocketUnsubscribe
}