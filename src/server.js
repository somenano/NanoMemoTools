/**
 * NanoMemoTools.server module
 * @module NanoMemoTools/server
 */

const network = require('./network.js');
const Memo = require('./memo.js');
let SERVER = 'https://nanomemo.cc';
let WSS = 'wss://nanomemo.cc';

/**
* This function gathers user data from the server
* @public
* @param {string} [api_key=undefined] user public api key; if undefined uses IP rate limiting
* @param {string} [api_secret=undefined] user private secret key; if undefined uses IP rate limiting
* @param {string} [endpoint=/api/user/] endpoint of POST request
* @returns {Promise} Promise object represents the user data as an object
*/
const getUserData = async function(api_key=undefined, api_secret=undefined, endpoint='/api/user') {
    
    const data = {
        api_key: api_key,
        api_secret: api_secret
    }
    return network.post(SERVER + endpoint, data);
}

/**
* This function gathers a memo's data from the server
* @public
* @param {array} hashes array of 64-hex hash that represents a Nano Block
* @param {string} [server=SERVER] server to POST
* @param {string} [endpoint=/api/memo/blocks/] endpoint of POST request
* @returns {Promise} Promise object represents array of Memo objectsthe memo object 
*/
const getMemos = async function(hashes, server=SERVER, endpoint='/api/memo/blocks/') {

    let response = await network.post(server + endpoint, {
        hashes: hashes
    });
    if (response === undefined || response === null) {
        return {
            success: false,
            dtg: new Date(),
            error: 'No response returned'
        }
    }
    if (response.error !== undefined) return response;

    // Create Memo objects
    let memos = [];
    for (let memo_data of response.data) {
        let memo = undefined;
        if (memo_data.version_encrypt !== undefined) {
            // Yes, encrypted
            memo = new Memo.EncryptedMemo(
                memo_data.hash,
                memo_data.message,
                memo_data.signing_address,
                memo_data.decrypting_address,
                memo_data.signature,
                memo_data.version_sign,
                memo_data.version_encrypt
            );
        } else {
            // No, not encrypted
            memo = new Memo.Memo(
                memo_data.hash,
                memo_data.message,
                memo_data.signing_address,
                memo_data.signature,
                memo_data.version_sign
            );
        }

        // Validate signature locally
        if (!memo.valid_signature) {
            console.error('In NanoMemoTools.server.getMemos, memo signature validation failed for hash '+ memo.hash);
            continue;
        }

        memos.push(memo);
    }

    return memos;
}

/**
* This function saves a memo to the server
* @public
* @param {Memo.Memo} memo memo data to be saved to the server
* @param {string} api_key public api key
* @param {string} api_secret private api key
* @param {string} [server=SERVER] server to POST
* @param {string} [endpoint=/api/memo/new/] endpoint of POST request
* @returns {Promise} Promise object represents the memo object 
*/
const saveMemo = async function(memo, api_key, api_secret, server=SERVER, endpoint='/api/memo/new') {

    if (!memo.valid_signature) {
        console.error('Memo has an invalid signature');
        return {
            success: false,
            dtg: new Date(),
            error: 'Memo has an invalid signature'
        }
    }

    console.log(server + endpoint);

    const response = await network.post(server + endpoint, {
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
    getMemos,
    saveMemo,
    websocketSubscribe,
    websocketUnsubscribe,
}