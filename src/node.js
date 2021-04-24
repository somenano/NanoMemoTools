/**
 * NanoMemoTools.node module
 * @module NanoMemoTools/node
 */

const network = require('./network');

/**
 * Default Nano Node Server
 */
const DEFAULT_SERVER = module.exports.DEFAULT_SERVER = 'https://node.somenano.com/proxy';

/**
 * This function returns a headers object to include in a network.post request
 * @private
 * @param {string} username username for auth
 * @param {string} password password for auth 
 * @returns {object} headers object to include in network.post
 */
const basicAuth = function(username, password) {
    let headers = {}
    if (username && password) {
        const auth_token = Buffer.from(username +':'+ password, 'utf8').toString('base64');
        headers = {
            headers: {
                'Authorization': 'Basic '+ auth_token
            }
        }
    }
    return headers;
}

/**
* This function requests information of a Nano Block from a given RPC server
* @public
* @param {string} hash hash identifier for requested Nano Block
* @param {string} [url=DEFAULT_SERVER] target RPC server to send the request
* @param {string} [username=undefined] username for Nano Node RPC authentication
* @param {string} [password=password] password for Nano Node RPC authentication
* @returns {Promise} Promise object represents the fields returned from an RPC block_info request
*/
const block_info = function(hash, url=DEFAULT_SERVER, username=undefined, password=undefined) {
    input = {
        action: 'block_info',
        json_block: true,
        hash: hash
    }

    return network.post(url, input, basicAuth(username, password));
}
module.exports.block_info = block_info;

/**
* This function requests information of one or more Nano Blocks from a given RPC server
* @public
* @param {array} hashes array of hash identifiers for requested Nano Blocks
* @param {string} [url=DEFAULT_SERVER] target RPC server to send the request
* @param {string} [username=undefined] username for Nano Node RPC authentication
* @param {string} [password=password] password for Nano Node RPC authentication
* @returns {Promise} Promise object represents the fields returned from an RPC block_info request
*/
const blocks_info = function(hashes, url=DEFAULT_SERVER, username=undefined, password=undefined) {
    input = {
        action: 'blocks_info',
        include_not_found: true,
        json_block: true,
        hashes: hashes
    }

    return network.post(url, input, basicAuth(username, password));
}
module.exports.blocks_info = blocks_info;