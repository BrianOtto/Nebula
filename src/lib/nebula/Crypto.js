window = {
	crypto: {
		getRandomValues: function(buffer) {
			var bufferPos = buffer.length;
			var bufferMax = 256;
			
			if (buffer instanceof Uint16Array) {
				bufferMax = 65535;
			}

			if (buffer instanceof Uint32Array) {
				bufferMax = 4294967295;
			}

			while (bufferPos--) {
				// TODO: Math.random() is not a CSRN
				buffer[bufferPos] = Math.floor(Math.random() * bufferMax);
			}
			
			return buffer;
		}
	}
}

var sodium = require("../sodium-0.5.2/libsodium-wrappers-sumo.js");

exports.sodium = sodium;