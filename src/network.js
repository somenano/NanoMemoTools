/**
 * NanoMemoTools.network module
 * @module NanoMemoTools/network
 */

const axios = require('axios');
const ReconnectingWebSocket = require('reconnecting-websocket');
const WS = require('ws');

/**
* This function sends a network POST request
* @public
* @param {string} url target of POST request
* @param {Object} params data fields to include in POST request
* @returns {Promise} Promise object represents the data field of a POST request's response
*/
module.exports.post = async function(url, params, headers={}) {
    let response = await axios.post(url, params, headers);
    return response.data;
}

/**
* This function sends a network GET request
* @private
* @param {string} url target of POST request
* @returns {Promise} Promise object represents the data field of a POST request's response
*/
module.exports.get = async function(url) {
    let response = await axios.get(url);
    return response.data;
}

/**
* This function sets up a websocket
* @private
* @param {string} url address of websocket
* @param {function} onopen function called when websocket is opened successfully; handles one argument, the websocket object
* @param {function} onmessage function called when websocket receives a message; handles two arguments, 1. websocket object 2. message
* @param {function} onclose function called when websocket is closed; handles one argument, the websocket object
* @param {function} onerror function called when websocket encounters an error; handles two arguments, 1. websocket object 2. error
* @returns {object} websocket object
*/
module.exports.websocket = async function(url, onopen, onmessage, onclose, onerror) {
    let ws = new ReconnectingWebSocket(url, [], {
        // WebSocket: WS,
        connectionTimeout: 1000,
        maxRetries: Infinity,
        maxReconnectionDelay: 8000,
        minReconnectionDelay: 3000
    });

    ws.onmessage = msg => {
        onmessage(ws, msg);
    }
    ws.onopen = () => {
        onopen(ws);
    }
    ws.onclose = () => {
        onclose(ws);
    }
    ws.onerror = (e) => {
        onerror(ws, e);
    }

    return ws;
}