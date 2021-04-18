/**
 * NanoMemoTools.node module
 * @module NanoMemoTools/node
 */

const network = require('./network');

/**
 * This function returns a headers object to include in a network.post request
 * @private
 * @param {string} username username for auth
 * @param {string} password password for auth 
 * @returns 
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
* @param {string} [url=https://node.somenano.com/proxy] target RPC server to send the request
* @returns {Promise} Promise object represents the fields returned from an RPC block_info request
*/
const block_info = function(hash, url='https://node.somenano.com/proxy', username=undefined, password=undefined) {
    input = {
        action: 'block_info',
        json_block: true,
        hash: hash
    }

    return network.post(url, input, basicAuth(username, password));
}
module.exports.block_info = block_info;