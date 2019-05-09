"use strict";

const randomBytes = require('randombytes')
const BigInteger = require('bigi')
const ecurve = require('ecurve')
const crypto = require('crypto')
const bs58 = require('bs58')
const secp256k1 = require('secp256k1')
const clone = require('clone')
const sha3= require('js-sha3')
const bs64 = require('base-64')
//testruby config 
var options = { pubKeyHashVersion: '007f5512', privateKeyVersion: '8028effe', checksumValue: 'c81bd898', compressed: false }



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//创建钱包
function createWalletAddress(walletPwd, walletName) {

 
    var privkey = randomPrivkey() 
    var privateAdd = toWIF(privkey) 
    var publicAdd = generateAddress(privkey)

    var walletData = {
        "publicAdd": publicAdd,
        "privateAdd": privateAdd,
        "walletPwd": walletPwd,
        "walletName": walletName,
        "gmtCreate": new Date().getTime()
    }

    return walletData;
} 
function randomPrivkey() { 
    var randombytes = randomBytes(32).toString('hex')
    var privateKey = new Buffer(randombytes, 'hex')
    return privateKey
}

String.prototype.getBytes = function () {
    var bytes = [];
    for (var i = 0; i < this.length; ++i) {
      bytes.push(this.charCodeAt(i));
    }
    return bytes;
  };


function stringToByte(str) {
    var bytes = new Array();
    var len, c;
    len = str.length;
    for(var i = 0; i < len; i++) {
        c = str.charCodeAt(i);
        if(c >= 0x010000 && c <= 0x10FFFF) {
            bytes.push(((c >> 18) & 0x07) | 0xF0);
            bytes.push(((c >> 12) & 0x3F) | 0x80);
            bytes.push(((c >> 6) & 0x3F) | 0x80);
            bytes.push((c & 0x3F) | 0x80);
        } else if(c >= 0x000800 && c <= 0x00FFFF) {
            bytes.push(((c >> 12) & 0x0F) | 0xE0);
            bytes.push(((c >> 6) & 0x3F) | 0x80);
            bytes.push((c & 0x3F) | 0x80);
        } else if(c >= 0x000080 && c <= 0x0007FF) {
            bytes.push(((c >> 6) & 0x1F) | 0xC0);
            bytes.push((c & 0x3F) | 0x80);
        } else {
            bytes.push(c & 0xFF);
        }
    }
    return bytes;


}


 function byteToString(arr) {
    if(typeof arr === 'string') {
        return arr;
    }
    var str = '',
        _arr = arr;
    for(var i = 0; i < _arr.length; i++) {
        var one = _arr[i].toString(2),
            v = one.match(/^1+?(?=0)/);
        if(v && one.length == 8) {
            var bytesLength = v[0].length;
            var store = _arr[i].toString(2).slice(7 - bytesLength);
            for(var st = 1; st < bytesLength; st++) {
                store += _arr[st + i].toString(2).slice(2);
            }
            str += String.fromCharCode(parseInt(store, 2));
            i += bytesLength - 1;
        } else {
            str += String.fromCharCode(_arr[i]);
        }
    }
    return str;
}

 
function generatePubKey(privkey) { 
    var ecparams = ecurve.getCurveByName('secp256k1')
    var curvePt = ecparams.G.multiply(BigInteger.fromBuffer(privkey))
    var x = curvePt.affineX.toBuffer(32)
    var y = curvePt.affineY.toBuffer(32)

    var publicKey = ''

    if (options.compressed) { 
        if (parseInt(y.toString('hex').substr(63, 1)) % 2 === 1) {
            publicKey = Buffer.concat([new Buffer([0x03]), x])
        } else {
            publicKey = Buffer.concat([new Buffer([0x02]), x])
        }
    } else {
        publicKey = Buffer.concat([new Buffer([0x04]), x, y])
    }

    return publicKey;
}
 
function generateAddress(privkey) {

    var publicKey = generatePubKey(privkey)

    console.log('publicKey:'+publicKey.toString('hex')) 
    var sha256 = crypto.createHash('sha256').update(publicKey).digest() 
    var pubkeyHash = crypto.createHash('rmd160').update(sha256).digest() 
    var rubypubkeyHash = '';
    for (var i = 0; i < 4; i++) {
        rubypubkeyHash = rubypubkeyHash + options.pubKeyHashVersion.substr(i * 2, 2) + pubkeyHash.toString('hex').substr(i * 10, 10)
    } 
    var sha1 = crypto.createHash('sha256').update(Buffer.from(rubypubkeyHash, 'hex')).digest()
    var sha2 = crypto.createHash('sha256').update(sha1).digest()
 
    var xorv = xor(hex_to_bin(options.checksumValue), hex_to_bin(sha2.toString('hex').substr(0, 8))) 
    const bytes = Buffer.from((rubypubkeyHash.toString('hex') + xorv), 'hex')
    const address = bs58.encode(bytes)

    return address;
}
 
function toWIF(privkey) {

    var privateKey = privkey 
    if (options.compressed) {

        privateKey = privateKey.toString('hex') + '01';
    } else {

        privateKey = privateKey.toString('hex');
    }
 
    var privateKeyVer = '';
    for (var i = 0; i < 5; i++) {
        privateKeyVer = privateKeyVer + options.privateKeyVersion.substr(i * 2, 2) + privateKey.toString('hex').substr(i * 16, 16)
    }
 
    var sha1 = crypto.createHash('sha256').update(Buffer.from(privateKeyVer, 'hex')).digest()
    var sha256 = crypto.createHash('sha256').update(sha1).digest()
 
    var l4bytes = sha256.toString('hex').substr(0, 8);
 

    var xorv = xor(hex_to_bin(options.checksumValue), hex_to_bin(l4bytes.toString('hex')))

 
    privateKeyVer = privateKeyVer + xorv.toString('hex')
 
    const bytes = Buffer.from((privateKeyVer.toString('hex')), 'hex')
    const formatPrivkey = bs58.encode(bytes) 

    return formatPrivkey

}



function fromWIF(wif) {

    var decodedWIF = new Buffer(bs58.decode(wif));

    var extractedChecksum = decodedWIF.slice(decodedWIF.length - Buffer.from(options.checksumValue, 'hex').length),
        extendedPrivateKey = decodedWIF.slice(0, decodedWIF.length - Buffer.from(options.checksumValue, 'hex').length),
        generatedChecksum = _generateChecksum(extendedPrivateKey, Buffer.from(options.checksumValue, 'hex').length),
        xorChecksum = xor(hex_to_bin(generatedChecksum.toString('hex')), hex_to_bin(options.checksumValue));

    if (compare(extractedChecksum, Buffer.from(xorChecksum, 'hex')) !== 0) {
        throw new Error('Extracted checksum and generated checksum do not match (' + extractedChecksum.toString('hex') + ', ' + xorChecksum.toString('hex') + ')');
    }

    var extractedData = _extractVersion(extendedPrivateKey, Buffer.from(options.privateKeyVersion, 'hex').length, 8);

    if (compare(extractedData['version'], Buffer.from(options.privateKeyVersion, 'hex')) !== 0) {
        throw new Error('Extracted private key does not match the given private key (' + extractedData['version'].toString('hex') + ', ' + options.privateKeyVersion.toString('hex') + ')');
    }

    var privateKey = extractedData['hash']

    if (privateKey.length !== 32) {
        if (privateKey.length === 33 && privateKey[32] === 1) { 
            privateKey = privateKey.slice(0, 32);
        } else {
            throw new Error('Private key length invalid ' + privateKey.length + ' bytes');
        }
    }

    return privateKey;
};



function _extractVersion(extendedHash, versionLength, nbSpacerBytes) {
    var versionParts = [],
        hashParts = [], index = 0, fromIndex, toIndex;

    for (; index < versionLength; index++) {
        versionParts.push(extendedHash.slice(index * nbSpacerBytes + index, index * nbSpacerBytes + index + 1));

        fromIndex = index * nbSpacerBytes + index + 1;
        toIndex = (index + 1) * nbSpacerBytes + index + 1;

        hashParts.push(extendedHash.slice(fromIndex, toIndex));
    }

    if ((index * nbSpacerBytes + index) < extendedHash.length) {
        hashParts.push(extendedHash.slice(index * nbSpacerBytes + index));
    }

    return {
        'version': Buffer.concat(versionParts),
        'hash': Buffer.concat(hashParts)
    };
};

function _generateChecksum(extendedHash, checksumLength) {
    return hash256(extendedHash).slice(0, checksumLength);
};




///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//签名交易，传入decoderawdeal和unspent
function signTx(privKey, decodedTransaction, unspent, signedCallBack) {
    var returnResult = "";
    for (var j = 0; j < decodedTransaction.vout.length; j++) {
        (function (index) { 
            decodedTransaction.vout[index].value = decodedTransaction.vout[index].value.toFixed(6) * 1e6;
        })(j);
    }
    // Sign the transaction
    var i = 0, signedTransaction = Promise.resolve(clone(decodedTransaction));

    for (; i < unspent.length; i++) {
        (function (index) {
            signedTransaction = signedTransaction.then(function (signedTransaction) {
                return sign(privKey, decodedTransaction, index, unspent[index].scriptPubKey.hex, false).then(function (currentIndexSignedTransaction) {
                    signedTransaction.vin[index].script = currentIndexSignedTransaction.vin[index].script
                    return signedTransaction
                });
            });
        })(i);
    }
    signedTransaction.then(function (signedTransaction) {

        var signedTransactionBuffer = _toBuffer(signedTransaction);
        returnResult = signedTransactionBuffer.toString('hex');
        signedCallBack(returnResult) 
    })

}



function sign(privKey, rawTransaction, index, getInputScript) {
    rawTransaction = clone(rawTransaction);
    index = index || 0;
    var self_privateKey = fromWIF(privKey)
console.log("self_privateKey:"+self_privateKey.toString('hex'))
    var self_pubkey = generatePubKey(self_privateKey)
    var scriptPromise;
    switch (typeof getInputScript) {
        case 'function':
            scriptPromise = getInputScript(rawTransaction.vin[index]['txid'], rawTransaction.vin[index]['vout']);
            break;
        case 'object':
            scriptPromise = getInputScript;
            break;
        case 'string':
            scriptPromise = Promise.resolve(getInputScript);
            break;
    }

    var self = this;

    return scriptPromise.then(function (script) {
        rawTransaction.vin[index].script = Buffer.isBuffer(script) ? script : Buffer.from(script, 'hex');

        var hashType = '0x01';  // SIGHASH_ALL

        var hashForSignature = hash256(Buffer.concat([_toBuffer(rawTransaction), uint32Buffer(hashType)]));

        var signature = secp256k1.sign(hashForSignature, self_privateKey).signature;
        var signatureDER = secp256k1.signatureExport(signature);

        var scriptSignature = Buffer.concat([signatureDER, uint8Buffer(hashType)]); // public key hash input 

        var scriptSig = Buffer.concat([pushDataIntBuffer(scriptSignature.length), scriptSignature, pushDataIntBuffer(self_pubkey.length), self_pubkey]);

        rawTransaction.vin[index].script = scriptSig;

        rawTransaction.toBuffer = function () {

            return _toBuffer(this);
        }

        return rawTransaction;
    });
};



function _toBuffer(decodedTransaction) {


    var chunks = [];

    chunks.push(uint32Buffer(decodedTransaction.version));
    chunks.push(varIntBuffer(decodedTransaction.vin.length));

    decodedTransaction.vin.forEach(function (txIn, index) {
        var hash = [].reverse.call(new Buffer(txIn.txid, 'hex'));
        chunks.push(hash);
        chunks.push(uint32Buffer(txIn.vout)); // index

        if (txIn.script != null) {
            chunks.push(varIntBuffer(txIn.script.length));
            chunks.push(txIn.script);
        } else {
            chunks.push(varIntBuffer(0));
        }

        chunks.push(uint32Buffer(txIn.sequence));
    });

    chunks.push(varIntBuffer(decodedTransaction.vout.length));
    decodedTransaction.vout.forEach(function (txOut) {
        chunks.push(uint64Buffer(txOut.value));

        var script = Buffer.from(txOut.scriptPubKey.hex, 'hex');

        chunks.push(varIntBuffer(script.length));
        chunks.push(script);
    });

    chunks.push(uint32Buffer(decodedTransaction.locktime));

    return Buffer.concat(chunks);
};


var pushDataIntBuffer = function (number) {
    var chunks = [];

    var pushDataSize = number < 76 ? 1
        : number < 0xff ? 2
            : number < 0xffff ? 3
                : 5;

    if (pushDataSize === 1) {
        chunks.push(uint8Buffer(number));
    } else if (pushDataSize === 2) {
        chunks.push(uint8Buffer(76));
        chunks.push(uint8Buffer(number));
    } else if (pushDataSize === 3) {
        chunks.push(uint8Buffer(77));
        chunks.push(uint16Buffer(number));
    } else {
        chunks.push(uint8Buffer(78));
        chunks.push(uint32Buffer(number));
    }

    return Buffer.concat(chunks);
};

var varIntBuffer = function (number) {
    var chunks = [];

    var size = number < 253 ? 1
        : number < 0x10000 ? 3
            : number < 0x100000000 ? 5
                : 9;

    // 8 bit
    if (size === 1) {
        chunks.push(uint8Buffer(number));

        // 16 bit
    } else if (size === 3) {
        chunks.push(uint8Buffer(253));
        chunks.push(uint16Buffer(number));

        // 32 bit
    } else if (size === 5) {
        chunks.push(uint8Buffer(254));
        chunks.push(uint32Buffer(number));

        // 64 bit
    } else {
        chunks.push(uint8Buffer(255));
        chunks.push(uint64Buffer(number));
    }

    return Buffer.concat(chunks);
};

var uint8Buffer = function (number) {
    var buffer = new Buffer(1);
    buffer.writeUInt8(number, 0);

    return buffer;
};

var uint16Buffer = function (number) {
    var buffer = new Buffer(2);
    buffer.writeUInt16LE(number, 0);

    return buffer;
};

var uint32Buffer = function (number) {
    var buffer = new Buffer(4);
    buffer.writeUInt32LE(number, 0);

    return buffer;
};

var uint64Buffer = function (number) {
    var buffer = new Buffer(8);
    buffer.writeInt32LE(number & -1, 0)
    buffer.writeUInt32LE(Math.floor(number / 0x100000000), 4)

    return buffer;
};

function compare(a, b) {
    if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
        throw new TypeError('Arguments must be Buffers')
    }

    if (a === b) return 0

    var x = a.length
    var y = b.length

    for (var i = 0, len = Math.min(x, y); i < len; ++i) {
        if (a[i] !== b[i]) {
            x = a[i]
            y = b[i]
            break
        }
    }

    if (x < y) return -1
    if (y < x) return 1
    return 0
}

function hash256(buffer) {

    var sha1 = crypto.createHash('sha256').update(buffer).digest()
    return crypto.createHash('sha256').update(sha1).digest()
}

function xor(a, b) {
    var length = Math.max(a.length, b.length)
    var buffer = Buffer.allocUnsafe(length)

    for (var i = 0; i < length; ++i) {
        buffer[i] = a.substr(i, 1) ^ b.substr(i, 1)
    }

    return bin_to_hex(Uint8ArrayToString(buffer))
}

function hex_to_bin(str) {
    const hex_array = [{ key: 0, val: '0000' }, { key: 1, val: '0001' }, { key: 2, val: '0010' }, { key: 3, val: '0011' }, { key: 4, val: '0100' }, { key: 5, val: '0101' }, { key: 6, val: '0110' }, { key: 7, val: '0111' },
    { key: 8, val: '1000' }, { key: 9, val: '1001' }, { key: 'a', val: '1010' }, { key: 'b', val: '1011' }, { key: 'c', val: '1100' }, { key: 'd', val: '1101' }, { key: 'e', val: '1110' }, { key: 'f', val: '1111' }]

    let value = ''
    for (let i = 0; i < str.length; i++) {
        for (let j = 0; j < hex_array.length; j++) {
            if (str.charAt(i) == hex_array[j].key) {
                value = value.concat(hex_array[j].val)
                break
            }
        }
    }
    return value
}

function bin_to_hex(str) {
    const hex_array = [{ key: 0, val: '0000' }, { key: 1, val: '0001' }, { key: 2, val: '0010' }, { key: 3, val: '0011' }, { key: 4, val: '0100' }, { key: 5, val: '0101' }, { key: 6, val: '0110' }, { key: 7, val: '0111' },
    { key: 8, val: '1000' }, { key: 9, val: '1001' }, { key: 'a', val: '1010' }, { key: 'b', val: '1011' }, { key: 'c', val: '1100' }, { key: 'd', val: '1101' }, { key: 'e', val: '1110' }, { key: 'f', val: '1111' }]
    let value = ''
    const list = []
    if (str.length % 4 !== 0) {
        const a = '0000'
        const b = a.substring(0, 4 - str.length % 4)
        str = b.concat(str)
    }
    while (str.length > 4) {
        list.push(str.substring(0, 4))
        str = str.substring(4)
    }
    list.push(str)
    for (let i = 0; i < list.length; i++) {
        for (let j = 0; j < hex_array.length; j++) {
            if (list[i] == hex_array[j].val) {
                value = value.concat(hex_array[j].key)
                break
            }
        }
    }
    return value
}

function Uint8ArrayToString(fileData) {
    var dataString = '';
    for (var i = 0; i < fileData.length; i++) {
        dataString += fileData[i]
    }

    return dataString
}


function hextoString(hex) {
    var arr = hex.split("")
    var out = ""
    for (var i = 0; i < arr.length / 2; i++) {
        var tmp = "0x" + arr[i * 2] + arr[i * 2 + 1]
        var charValue = String.fromCharCode(tmp);
        out += charValue
    }
    return out
}


export {
    signTx,
    createWalletAddress, fromWIF, toWIF, hextoString,generatePubKey,generateAddress,test

}