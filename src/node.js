/**
 * NanoMemoTools.node module
 * @module NanoMemoTools/node
 */

const network = require('./network');

/**
* This function requests information of a Nano Block from a given RPC server
* @public
* @param {string} hash hash identifier for requested Nano Block
* @param {string} [url=https://node.somenano.com/proxy] target RPC server to send the request
* @returns {Promise} Promise object represents the fields returned from an RPC block_info request
*/
const block_info = function(hash, url='https://node.somenano.com/proxy') {
    input = {
        action: 'block_info',
        json_block: true,
        hash: hash
    }
    return network.post(url, input);
}
module.exports.block_info = block_info;