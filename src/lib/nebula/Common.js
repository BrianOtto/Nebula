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
        if (buffer[i]++ !== 255) { break; }
    }
    
    return buffer;
}

function readUInt16BE(buffer, offset) {
    offset = offset >>> 0;
    return (buffer[offset] << 8) | buffer[offset + 1];
}

function readUInt32BE(buffer, offset) {
    offset = offset >>> 0;
    return (buffer[offset] * 0x1000000) + ((buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]);
}

function readInt32BE (buffer, offset) {
    offset = offset >>> 0;
    return (buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | (buffer[offset + 3]);
}

function writeUInt16BE(buffer, value, offset) {
    value  = +value;
    offset = offset >>> 0;
    
    buffer[offset] = (value >>> 8);
    buffer[offset + 1] = (value & 0xff);

    return offset + 2;
}

function writeUInt32BE(buffer, value, offset) {
    value  = +value;
    offset = offset >>> 0;
    
    buffer[offset] = (value >>> 24);
    buffer[offset + 1] = (value >>> 16);
    buffer[offset + 2] = (value >>> 8);
    buffer[offset + 3] = (value & 0xff);

    return offset + 4;
}

function writeInt32BE(buffer, value, offset) {
    value  = +value;
    offset = offset >>> 0;

    if (value < 0) value = 0xffffffff + value + 1;

    buffer[offset] = (value >>> 24);
    buffer[offset + 1] = (value >>> 16);
    buffer[offset + 2] = (value >>> 8);
    buffer[offset + 3] = (value & 0xff);

    return offset + 4;
}

// This function will convert a UTF8 string to a byte array
// It comes from https://github.com/feross/buffer
function utf8ToBytes(string, units) {
    units = units || Infinity;
    
    var codePoint;
    var length = string.length;
    var leadSurrogate = null;
    var bytes = [];

    for (var i = 0; i < length; ++i) {
        codePoint = string.charCodeAt(i);

        // is surrogate component
        if (codePoint > 0xD7FF && codePoint < 0xE000) {
            // last char was a lead
            if (!leadSurrogate) {
                // no lead yet
                if (codePoint > 0xDBFF) {
                    // unexpected trail
                    if ((units -= 3) > -1) {
                        bytes.push(0xEF, 0xBF, 0xBD);
                    }

                    continue;
                } else if (i + 1 === length) {
                    // unpaired lead
                    if ((units -= 3) > -1) {
                        bytes.push(0xEF, 0xBF, 0xBD);
                    }

                    continue;
                }

                // valid lead
                leadSurrogate = codePoint;

                continue;
            }

            // 2 leads in a row
            if (codePoint < 0xDC00) {
                if ((units -= 3) > -1) {
                    bytes.push(0xEF, 0xBF, 0xBD);
                }

                leadSurrogate = codePoint;
                continue;
            }

            // valid surrogate pair
            codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000;
        } else if (leadSurrogate) {
            // valid bmp char, but last char was a lead
            if ((units -= 3) > -1) {
                bytes.push(0xEF, 0xBF, 0xBD);
            }
        }

        leadSurrogate = null;

        // encode utf8
        if (codePoint < 0x80) {
            if ((units -= 1) < 0) { break; }
            bytes.push(codePoint)
        } else if (codePoint < 0x800) {
            if ((units -= 2) < 0) { break; }
            bytes.push(codePoint >> 0x6 | 0xC0, codePoint & 0x3F | 0x80);
        } else if (codePoint < 0x10000) {
            if ((units -= 3) < 0) { break; }
            bytes.push(codePoint >> 0xC | 0xE0, codePoint >> 0x6 & 0x3F | 0x80, codePoint & 0x3F | 0x80);
        } else if (codePoint < 0x110000) {
            if ((units -= 4) < 0) { break; }
            bytes.push(codePoint >> 0x12 | 0xF0, codePoint >> 0xC & 0x3F | 0x80, codePoint >> 0x6 & 0x3F | 0x80, codePoint & 0x3F | 0x80);
        }
    }

    return bytes;
}

exports.concat = concat;
exports.increment = increment;
exports.readUInt16BE = readUInt16BE;
exports.readUInt32BE = readUInt32BE;
exports.readInt32BE = readInt32BE;
exports.writeUInt16BE = writeUInt16BE;
exports.writeUInt32BE = writeUInt32BE;
exports.writeInt32BE = writeInt32BE;
exports.utf8ToBytes = utf8ToBytes;