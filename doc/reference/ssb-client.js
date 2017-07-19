/**
 * Reference Implementation for a Secure Scuttlebutt Client
 *
 * This implementation is based on a 2-month analysis of the SSB Client source code 
 * located at https://github.com/ssbc/ssb-client and its many, nested dependencies.
 *
 * I have stripped away as many dependencies as possible, simplified the original logic, 
 * used more descriptive variable names and documented every step so that the underlying 
 * protocol can be understood. This should allow the protocol to be implemented in a 
 * different language, outside of the Node ecosphere.
 *
 * In particular, this implementation does two things ...
 * 1) It negotiates the secure handshake that is required to connect to a secure scuttlebutt server
 * 2) It pulls down the entire contents of a random history stream and displays it to the screen
 *
 * After you connect to a scuttlebutt server, it will send you a list of every history stream it knows about.
 * Each history stream is associated to one individual user (i.e. a public key), and it represents every post 
 * the user has published / synced to the server.
 *
 * e.g. {"name":["createHistoryStream"],"args":[{"id":"@MOU474MmgIOyNBqkT1xi8yOt3V3Ze1vTKg9wmWXGiBg=.ed25519","seq":13,"live":false,"keys":false}],"type":"source"}
 * The server has 12 posts from MOU474MmgIOyNBqkT1xi8yOt3V3Ze1vTKg9wmWXGiBg= (which is the user's Ed25519 public key signature in base64 encoding)
 * 
 * We parse this list and send back a response with the earliest sequence number we want, and the server will send 
 * us the contents of every post we are missing. For example, if we tell it we want seq 10, then the server will
 * send us posts 10 - 12. If we tell it we want seq 0 or 1, then the server will send us everything it has.
 *
 * The docs don't make this very clear, but createHistoryStream is the ONLY stream available to remote clients.
 * You are expected to store the post contents in a local database, and all other streams (i.e. feed, log and user streams) 
 * are merely different ways of querying this LOCAL data. They do not need to be implemented to participate in the network.
 *
 * TODO
 *
 * - A client also needs to be a server, and so I will eventually add support for handling client requests (it's mostly just reversing the logic)
 * - Add support for private messaging (i.e. encrypted posts) and blobs (i.e. file publishing and network search)
 * - Add support for publishing the different post types (i.e. about, contact / friends, vote, pub)
 *
 * Limitations
 *
 * To keep things simple, this implementation does NOT do any kind of error checking. It also does not do any 
 * kind of data storage / retrieval. How you implement and query the local database is up to you.
 *
 * Further Reading
 *
 * Designing a Secret Handshake: Authenticated Key Exchange as a Capability System
 * by Dominic Tarr on July 10, 2015
 *
 * https://dominictarr.github.io/secret-handshake-paper/shs.pdf
 *
 * This is the secure handshake protocol that SSB uses.
 *
 * Some historical discussion on the protocol, and its possible flaws, can be found at
 * https://lists.gnu.org/archive/html/gnunet-developers/2015-08/msg00016.html
 *
 * Also, the official implementation, as well as this one, does not follow the paper exactly.
 * See https://github.com/auditdrivencrypto/secret-handshake/issues/7 for details, as well as 
 * other suggested improvements.
 *
 */

// [---- Dependencies ----]

// A networking library that can create a TCP client / server
//
// NOTE: This library requires us to use a Buffer when writing to the socket,
//       and so this becomes an implicit dependency that is built into Node.
//       It may require a different implementation in other languages.
var net = require('net');

// Sodium - A cryptography library
// You can find bindings for other languages at
// https://download.libsodium.org/doc/bindings_for_other_languages/
//
// NOTE: The SUMO version is used because we require support for crypto_hash_sha256()
//       See https://github.com/jedisct1/libsodium.js/issues/54
//
//       SHA-256 is vulnerable to length extension attacks, and so it should eventually be
//       replaced with crypto_generichash(). This will let us use the standard library too.
var sodium = require('./libsodium-wrappers-sumo.js');

// [---- Globals ----]

// An invite code for a pub server. You can get a new one from http://ssb.exitsystemcall.com/invited
// See https://github.com/ssbc/scuttlebot/wiki/Pub-Servers for other alternatives
var invite = 'ssb.exitsystemcall.com:8008:@gSb2Dt4qtUSIt0jV1yrugKPiBriKPIUFfYB574vWhrM=.ed25519~H7CnTrQ2thtMwxUWsfWb1OL/qQ4gfNiI09pJbOAx9+4=';
var invitePieces = invite.split(':');

// e.g. ssb.exitsystemcall.com
var serverHost = invitePieces[0];

// e.g. 8008
var serverPort = invitePieces[1];

// e.g. The server's public key is gSb2Dt4qtUSIt0jV1yrugKPiBriKPIUFfYB574vWhrM=
// e.g. Your unique invite code is H7CnTrQ2thtMwxUWsfWb1OL/qQ4gfNiI09pJbOAx9+4=
// NOTE: I don't understand what the unique invite code is used for.
//       The server does not request or verify it in any way.
var serverKeys = invitePieces[2].split('~');

// A place to store all data received from the server
var serverData = new Uint8Array();
var serverDataArray = [];

// The timer that gets triggered when we are ready to parse the server data
var serverDataTimer = null;

// The TCP client
var client = new net.Socket();

// A place to store all the encryption keys and MACs used for communicating with the server
var clientKeychain = {
    // A hard-coded "key" that represents the capabilties the client / server supports
    // See https://github.com/ssbc/scuttlebot/blob/master/lib/ssb-cap.js and the SHS paper
    // If the protocol changes then this key will need to change too
    appKey: sodium.from_base64('1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s='),
    
    // The client's public / private keypair
    // In a real-world application this would be generated once and stored in a file
    client: sodium.crypto_sign_seed_keypair(sodium.randombytes_buf(32)),
    
    // The server's public key
    server: {
        publicKey: sodium.from_base64(serverKeys[0].replace('.ed25519', '').substr(1))
    },
    
    // The ephemeral (i.e. temporary) keys and MACs used for the secure handshake
    hShake: {
        client: {
            ephMac: null,
            ephKey: {}
        },
        server: {
            ephMac: null,
            ephKey: {}
        }
    },
    
    // The secret keys shared between the client and server
    shared: {
        secretForMessageHash: null,
        secretForSendingHash: null,
        secretForSending: null,
    },
    
    // The client's authentication response
    // i.e. The client's public key prefixed with a signature
    accept: null,
    
    // The keys used to encrypt / decrypt data after the secure handshake
    sesKey: {}
}

// Has the client verified the server's challenge
var verifyChallenge = false;

// Has the client verified the server's accept
var verifyAccept = false;

// Has the client parsed the history streams
var parsedServerData = false

// The random history stream we will be displaying
var randomStream = {}

// [---- Application ----]

console.log('\nConnecting to ' + serverHost + ':' + serverPort + ' ...\n');

// The client connect is wrapped inside a function so we can call it more than once
function connect() {
    // The client connects to the server in the invite code
    client.connect(serverPort, serverHost, function() {
        // The client creates a "challenge" for the server
        // i.e. The client wants to securely transmit a temporary public key to the server
        
        console.log('Create Challenge');
        
        // The client creates a new ephemeral (i.e. temporary) keypair
        clientKeychain.hShake.client.ephKey = sodium.crypto_box_seed_keypair(sodium.randombytes_buf(32));
        
        // The client creates a MAC of the message it will be sending to the server (i.e. the message is the public key)
        // It does this using the appKey, because this is a hard-coded value that both parties have access to
        // NOTE: This only works when they both speak the same version of the protocol
        clientKeychain.hShake.client.ephMac = sodium.crypto_auth(clientKeychain.hShake.client.ephKey.publicKey, clientKeychain.appKey);
        
        // The client prefixes the MAC to the public key and sends this to the server
        var ephKeyWithMac = concat(clientKeychain.hShake.client.ephMac, clientKeychain.hShake.client.ephKey.publicKey);
        client.write(new Buffer(ephKeyWithMac));
        
        // The server can verify the message (i.e. the public key) hasn't been altered in transit by following
        // the same steps the client does when verifyChallenge === false, see below ...
    });
}

// The client has received some data from the server
client.on('data', function(data) {
    if (verifyChallenge === false) {
        // The server has sent a "challenge" to the client, and we need to verify it
        
        console.log('Verify Challenge');
        
        // The first 32 bytes is always the MAC
        clientKeychain.hShake.server.ephMac = data.slice(0, 32);
        
        // The rest of the message is the temporary, public key
        clientKeychain.hShake.server.ephKey.publicKey = data.slice(32, data.length);
        
        // Sodium verifies the public key hasn't been altered in transit by generating another MAC using the received public key and the hard-coded appKey
        // It compares this MAC to the one received, and if they match, then nothing has been altered and the "challenge" has been verified
        var verify = sodium.crypto_auth_verify(clientKeychain.hShake.server.ephMac, clientKeychain.hShake.server.ephKey.publicKey, clientKeychain.appKey);
        if (verify === false) { client.destroy(); }
        
        // ---------------------------------------------
        
        // The client creates an "accept" for the server
        // i.e. The client and server both have temporary keys that can be used to exchange data with now,
        //      and so the client can now securely transmit its long term public key to the server
        
        console.log('Create Accept');
        
        // The client creates a shared secret using the client's temporary private key and the server's temporary public key
        // See https://download.libsodium.org/doc/advanced/scalar_multiplication.html
        var secretForMessage = sodium.crypto_scalarmult(clientKeychain.hShake.client.ephKey.privateKey, clientKeychain.hShake.server.ephKey.publicKey);
        
        // The client hashes the secret
        clientKeychain.shared.secretForMessageHash = sodium.crypto_hash_sha256(secretForMessage);
        
        // The client creates a message that proves ...
        // 1) we are using the same version of the protocol (clientKeychain.appKey)
        // 2) we have the server's public key (clientKeychain.server.publicKey)
        // 3) we have access to the ephemeral keys (clientKeychain.shared.secretForMessageHash)
        //
        // NOTE: It seems like 1) is unnecessary because providing 3) proves we already have access to 1)
        var message = concat(concat(clientKeychain.appKey, clientKeychain.server.publicKey), clientKeychain.shared.secretForMessageHash);
        
        // The message is not sent to the server. The client only uses it to generate a signature for the public key.
        // i.e. The server will use this signature to prove the public key came from this client
        var messageSignature = sodium.crypto_sign_detached(message, clientKeychain.client.privateKey);
        
        // The client prefixes the signature to it's public key
        clientKeychain.accept = concat(messageSignature, clientKeychain.client.publicKey);
        
        // The client creates ANOTHER shared secret, but using the server's public key this time, NOT the temporary one
        var secretForSending = sodium.crypto_scalarmult(clientKeychain.hShake.client.ephKey.privateKey, sodium.crypto_sign_ed25519_pk_to_curve25519(clientKeychain.server.publicKey));
        
        // The client creates a key using the appKey and both shared secrets
        // NOTE: This seems unecessary too. Isn't secretForSending good enough?
        clientKeychain.shared.secretForSending = concat(concat(clientKeychain.appKey, secretForMessage), secretForSending);
        clientKeychain.shared.secretForSendingHash = sodium.crypto_hash_sha256(clientKeychain.shared.secretForSending);
        
        // The "accept" message is encrypted and sent to the server
        var encryptedAccept = sodium.crypto_secretbox_easy(clientKeychain.accept, new Uint8Array(24).fill(0), clientKeychain.shared.secretForSendingHash);
        
        if (encryptedAccept) {
            client.write(new Buffer(encryptedAccept));
    	    
    	    verifyChallenge = true;
    	} else {
    	    client.destroy();
    	}
    } else if (verifyAccept === false) {
        // The server has sent an "accept" to the client, and we need to verify it
        
        console.log('Verify Accept');
        
        // The client creates the SAME shared secret that was generated by the server
        var secretForServer = sodium.crypto_scalarmult(sodium.crypto_sign_ed25519_sk_to_curve25519(clientKeychain.client.privateKey), clientKeychain.hShake.server.ephKey.publicKey);
        
        // The shared secret generated by the client is combined with the one generated by
        // the server to create the key the server used when encrypting the accept message
        // NOTE: See https://github.com/auditdrivencrypto/secret-handshake/issues/11 on why we hash twice
        //       This is a security precaution for the official implementation only
        var secretForSendingServer = sodium.crypto_hash_sha256(concat(clientKeychain.shared.secretForSending, secretForServer));
        
        // The "accept" message is an encrypted signature
        var messageSignatureServer = sodium.crypto_secretbox_open_easy(data, new Uint8Array(24).fill(0), secretForSendingServer);
        
        if (messageSignatureServer) {
            // The client re-creates the message that was generated by the server
            var messageServer = concat(concat(clientKeychain.appKey, clientKeychain.accept), clientKeychain.shared.secretForMessageHash);
            
            // The client verifies messageSignatureServer is a valid signature for the message
            var success = sodium.crypto_sign_verify_detached(messageSignatureServer, messageServer, clientKeychain.server.publicKey);
            
            if (success) {
                // We now have the keys to encrypt / decrypt data for our current session
                // NOTE: These keys will ONLY work for this session. This protects us, by giving us forward secrecy, if the long term keys are ever compromised.
                clientKeychain.sesKey.privateKey = sodium.crypto_hash_sha256(concat(sodium.crypto_hash_sha256(secretForSendingServer), clientKeychain.server.publicKey));
                clientKeychain.sesKey.publicKey  = sodium.crypto_hash_sha256(concat(sodium.crypto_hash_sha256(secretForSendingServer), clientKeychain.client.publicKey));
                
                verifyAccept = true;
                
                // The client has parsed the history streams and chosen a random one
                if (parsedServerData) {
                    // We tell the server to send us ALL posts by setting the sequence number to 0 or 1
                    randomStream.args[0].seq = 0;
                    
                    // A packet contains the following ...
                    // req = A unique number that increments every time you send a packet
                    // stream = Does this packet represent a stream or a message / request
                    // end = Should the server close the connection when it's done
                    // NOTE: This must be set to "false" when stream is set to "true",
                    //       otherwise the server will ignore me and disconnect. Why?
                    // value = A JSON object representing an API call
                    // e.g. {"name":["createHistoryStream"],"args":[{"id":"@MOU474MmgIOyNBqkT1xi8yOt3V3Ze1vTKg9wmWXGiBg=.ed25519","seq":0,"live":false,"keys":false}],"type":"source"}
                    packet = { req: 1, stream: true, end: false, value: randomStream }
                    
                    // NOTE: Another issue I noticed, is the packet must be sent BEFORE the server sends us its list of history streams
                    //       If I send it after receiving the list then the server ignores me and disconnects.
                    writePacket(packet);
                }
                
                console.log('');
            }
        } else {
            client.destroy();
        }
    } else {
        // The client appends the latest data
        serverData = concat(serverData, new Uint8Array(data));
        
        // The previous timer is cleared
        if (serverDataTimer) {
            clearTimeout(serverDataTimer)
        }
        
        // The client will parse the server data after 5 seconds of inactivity
        // HACK: This should be updated to look for the GOODBYE packet instead
        serverDataTimer = setTimeout(parseServerData, 5000);
        
        process.stdout.write('\rDownloading ' + Number(serverData.length / 1024).toFixed(2) + ' KB ...');
    }
});

// This function assumes all of the data has been downloaded
// It will not parse in real-time, as a stream is being sent
function parseServerData() {
    console.log('\nParsing Server Data ...\n')
    
    // We create a nonce (i.e. a one-time use number) from the temporary MAC
    nonce = new Uint8Array(clientKeychain.hShake.client.ephMac.slice(0, 24));
    
    var dataLength = 34
    var dataBuffer = null;
    var dataHeader = true;
    var dataMac    = null;
    
    for (var i = 0, b = 0; i < serverData.length; i++, b++) {
        if (b < dataLength) {
            continue;
        } else {
            dataBuffer = serverData.slice(i - dataLength, i);
            b = 0;
        }
        
        // A packet is always sent as two seperate chunks of data
        // See https://github.com/dominictarr/packet-stream-codec
        
        // 1st = The packet header, which is always 9 bytes long
        // e.g. { req: 1, stream: true, end: false, length: 151, type: 2 }
        // The above JSON gets encoded into a 9 byte buffer
        
        // 2nd = The packet body / API call
        // e.g. {"name":["createHistoryStream"],"args":[{"id":"@MOU474MmgIOyNBqkT1xi8yOt3V3Ze1vTKg9wmWXGiBg=.ed25519","seq":0,"live":false,"keys":false}],"type":"source"}
        
        // Each chunk of data is ALSO composed of a header and a body
        // The header is 18 bytes long and the body is an arbitrary length
        // The header stores the length of the body and a MAC, which is 
        // really just the first 16 bytes of the body
        if (dataHeader) {
            // The client decrypts the header
            var header = new Buffer(sodium.crypto_secretbox_open_easy(dataBuffer, nonce, clientKeychain.sesKey.publicKey))
            
            // The body length
            dataLength = header.readUInt16BE(0);
            
            // The body MAC
            // NOTE: The official implementation does a slice(2, 34),
            //       but I think this is incorrect since we only store 
            //       the first 16 bytes of the body here
            dataMac = header.slice(2, 18);
            
            dataHeader = false;
        } else {
            increment(nonce)
            
            // To keep this simple, we ignore all packet header chunks and only keep track of the JSON in the body
            if (dataLength != 9) {
                // The client decrypts the body
                var body = new Buffer(sodium.crypto_secretbox_open_easy(concat(dataMac, dataBuffer), nonce, clientKeychain.sesKey.publicKey));
                
                var bodyJSON = JSON.parse(body.toString('utf8'));
                
                // The client has not parsed the history streams yet
                if (parsedServerData === false) {
                    // The client stores the createHistoryStream object
                    serverDataArray.push(bodyJSON)
                } else {
                    // The client compares the author of the current history stream to the random one we requested
                    // If they match, then we display the JSON string to the screen
                    if (bodyJSON.author && bodyJSON.author == randomStream.args[0].id) {
                        // In a real-world application, you should verify the "previous" hash matches the previous 
                        // post and that the "signature" is valid. Otherwise, this could be a malicious SSB server.
                        console.log(JSON.stringify(bodyJSON))
                    }
                }
            }
            
            increment(nonce)
            
            dataLength = 34;
            dataMac = null;
            
            dataHeader = true;
        }
    }
    
    if (parsedServerData === false) {
        parsedServerData = true;
        
        // The client chooses a random stream
        var rand = Math.floor(Math.random() * serverDataArray.length);
        randomStream = serverDataArray[rand];
        
        // NOTE: Why is randomStream.args an array?
        console.log('Fetching Stream ' + randomStream.args[0].id + ' (' + (randomStream.args[0].seq - 1) + ' Posts)\n')
        
        // Reset some of the globals before we re-connect
        serverData = new Uint8Array();
        serverDataArray = [];
        
        verifyChallenge = false;
        verifyAccept = false;
        
        // The client re-connects and requests the random history stream
        // See client.on('data') > "The client has parsed the history streams and chosen a random one"
        connect();
    } else {
        client.destroy();
    }
}

// This function will create the packet header and body,
// encrypt them both and then send the data to the server
function writePacket(object) {
    var header = new Buffer(9);
    
    // The packet stream codec allows you to send a buffer (0), string (1) or JSON object (2)
    // See https://github.com/dominictarr/packet-stream-codec
    
    // We are only interested in sending a JSON object, and so this logic has been hard-coded
    var body = new Buffer(JSON.stringify(object.value));
    var bodyType = 2;
    
    // Bytes 1 = We store the stream / end / type flags
    header[0] = object.stream << 3 | object.end << 2 | bodyType;
    
    // Bytes 2 - 5 = We store the length of the body
    header.writeUInt32BE(body.length, 1);
    
    // Bytes 6 - 9 = We store the unique identifier
    header.writeInt32BE(object.req || 0, 5);
    
    // ---------------------------------------------
    
    // We create some nonces from the temporary MAC
    var nonceForEncryption = new Uint8Array(clientKeychain.hShake.server.ephMac.slice(0, 24));
    var nonceForHeader = new Uint8Array(clientKeychain.hShake.server.ephMac.slice(0, 24));
    
    increment(nonceForEncryption);
    
    // We encrypt the packet header
    var headerEncrypted = new Buffer(sodium.crypto_secretbox_easy(header, nonceForEncryption, clientKeychain.sesKey.privateKey));
    
    // The packet header is split into two parts
    // Part 1 = A "header" that is 18 bytes long
    // Part 2 = A "body" that is 9 bytes long
    
    // Part 1 / Bytes 1 = We store the length of the data
    var headerPart1 = new Buffer(18);
    headerPart1.writeUInt16BE(header.length, 0);
    
    // Part 1 / Bytes 3 - 18 = We store the first 16 bytes of headerEncrypted
    // NOTE: This seems unnecessarily complex. Why do we do this?
    headerEncrypted.copy(headerPart1, 2, 0, 16);
    
    // Part 1 is encrypted
    headerPart1Encrypted = new Buffer(sodium.crypto_secretbox_easy(headerPart1, nonceForHeader, clientKeychain.sesKey.privateKey));
    
    // Part 2 is the rest of headerEncrypted
    headerPart2Encrypted = headerEncrypted.slice(16, 16 + header.length);
    
    // NOTE: Why do we increment twice?
    increment(increment(nonceForHeader));
    increment(increment(nonceForEncryption));
    
    // We encrypt the packet body
    var bodyEncrypted = new Buffer(sodium.crypto_secretbox_easy(body, nonceForEncryption, clientKeychain.sesKey.privateKey));
    
    // The packet body is split into two parts
    // Part 1 = A "header" that is 18 bytes long
    // Part 2 = A "body" that is an arbitrary length
    
    // Part 1 / Bytes 1 = We store the length of the data
    var bodyPart1 = new Buffer(18);
    bodyPart1.writeUInt16BE(body.length, 0);
    
    // Part 1 / Bytes 3 - 18 = We store the first 16 bytes of bodyEncrypted
    // NOTE: This seems unnecessarily complex. Why do we do this?
    bodyEncrypted.copy(bodyPart1, 2, 0, 16);
    
    // Part 1 is encrypted
    bodyPart1Encrypted = new Buffer(sodium.crypto_secretbox_easy(bodyPart1, nonceForHeader, clientKeychain.sesKey.privateKey));
    
    // Part 2 is the rest of bodyEncrypted
    bodyPart2Encrypted = bodyEncrypted.slice(16, 16 + body.length);
    
    // We send everything to the server (in 4 parts)
    client.write(headerPart1Encrypted);
    client.write(headerPart2Encrypted);
    client.write(bodyPart1Encrypted);
    client.write(bodyPart2Encrypted);
}

// This function will append one Uint8Array to another
function concat(a, b) {
    var c = new Uint8Array(a.length + b.length);
    
    c.set(a, 0);
    c.set(b, a.length);
    
    return c;
}

// This function will increment a buffer in big endian
function increment(buffer) {
    for (var i = buffer.length - 1; i >= 0; i--) {
        if (buffer[i]++ !== 255) break;
    }
    
    return buffer;
}

// Run the application
connect();