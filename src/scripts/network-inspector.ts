import type { ScriptTemplate } from '../types.js';
import { getFridaRuntime } from './frida-runtime.js';

export const networkInspectorTemplate: ScriptTemplate = {
  name: 'network_inspector',
  description: 'Monitor network socket operations including connect, send, recv. Logs addresses, ports, and data sizes.',
  platforms: ['android', 'ios'],
  category: 'network',
  riskTier: 1,
  options: {
    log_data: { type: 'boolean', description: 'Log raw data (hex)', default: false },
    filter_host: { type: 'string', description: 'Filter by host pattern' },
  },
  generate: (options) => {
    const logData = options.log_data === true;
    return `
    (function() {
      ${getFridaRuntime()}

      // Hook connect
      hookNative(null, 'connect', {
        onEnter: function(args) {
          try {
            var sockaddr = args[1];
            if (sockaddr.isNull()) return;
            var family = Memory.readU16(sockaddr);
            if (family === 2) { // AF_INET
              var port = (Memory.readU8(sockaddr.add(2)) << 8) | Memory.readU8(sockaddr.add(3));
              var ip = Memory.readU8(sockaddr.add(4)) + '.' + Memory.readU8(sockaddr.add(5)) + '.' + Memory.readU8(sockaddr.add(6)) + '.' + Memory.readU8(sockaddr.add(7));
              this.info = { api: 'connect', ip: ip, port: port, family: 'IPv4' };
            } else if (family === 30) { // AF_INET6
              var port = (Memory.readU8(sockaddr.add(2)) << 8) | Memory.readU8(sockaddr.add(3));
              this.info = { api: 'connect', port: port, family: 'IPv6' };
            }
          } catch(e) {}
        },
        onLeave: function(retval) {
          if (this.info) {
            this.info.result = retval.toInt32() === 0 ? 'success' : 'error';
            send(this.info);
          }
        }
      });

      // Hook send
      hookNative(null, 'send', {
        onEnter: function(args) {
          this.fd = args[0].toInt32();
          this.size = args[2].toInt32();
          ${logData ? "this.data = args[1].readByteArray(Math.min(this.size, 256));" : ''}
        },
        onLeave: function(retval) {
          var info = { api: 'send', fd: this.fd, size: this.size, sent: retval.toInt32() };
          ${logData ? "if (this.data) info.data = Array.from(new Uint8Array(this.data)).map(function(b){return ('0'+b.toString(16)).slice(-2);}).join('').slice(0,512);" : ''}
          send(info);
        }
      });

      // Hook recv
      hookNative(null, 'recv', {
        onEnter: function(args) { this.fd = args[0].toInt32(); this.buf = args[1]; this.size = args[2].toInt32(); },
        onLeave: function(retval) {
          var received = retval.toInt32();
          if (received > 0) {
            var info = { api: 'recv', fd: this.fd, requested: this.size, received: received };
            ${logData ? "try { info.data = this.buf.readByteArray(Math.min(received, 256)); info.data = Array.from(new Uint8Array(info.data)).map(function(b){return ('0'+b.toString(16)).slice(-2);}).join('').slice(0,512); } catch(e) {}" : ''}
            send(info);
          }
        }
      });

      // DNS resolution — getaddrinfo
      hookNative(null, 'getaddrinfo', {
        onEnter: function(args) {
          try { this.hostname = args[0].readUtf8String(); } catch(e) { this.hostname = null; }
        },
        onLeave: function(retval) {
          if (this.hostname) send({ api: 'getaddrinfo', hostname: this.hostname, result: retval.toInt32() === 0 ? 'success' : 'error' });
        }
      });

      // UDP — sendto
      hookNative(null, 'sendto', {
        onEnter: function(args) {
          try { this.fd = args[0].toInt32(); this.size = args[2].toInt32(); } catch(e) {}
        },
        onLeave: function(retval) {
          if (this.fd !== undefined) send({ api: 'sendto', fd: this.fd, size: this.size, sent: retval.toInt32() });
        }
      });

      // UDP — recvfrom
      hookNative(null, 'recvfrom', {
        onEnter: function(args) {
          try { this.fd = args[0].toInt32(); this.size = args[2].toInt32(); } catch(e) {}
        },
        onLeave: function(retval) {
          if (this.fd !== undefined) send({ api: 'recvfrom', fd: this.fd, requested: this.size, received: retval.toInt32() });
        }
      });

      // TLS library name — shared by SSL_read and SSL_write hooks
      var sslLib = Process.platform === 'darwin' ? 'libboringssl.dylib' : 'libssl.so';

      // TLS plaintext — SSL_read
      hookNative(sslLib, 'SSL_read', {
        onEnter: function(args) { try { this.ssl = args[0]; this.size = args[2].toInt32(); } catch(e) {} },
        onLeave: function(retval) {
          var read = retval.toInt32();
          if (read > 0) send({ api: 'SSL_read', size: read });
        }
      });

      // TLS plaintext — SSL_write
      hookNative(sslLib, 'SSL_write', {
        onEnter: function(args) { try { this.size = args[2].toInt32(); } catch(e) {} },
        onLeave: function(retval) {
          if (retval.toInt32() > 0) send({ api: 'SSL_write', size: retval.toInt32() });
        }
      });

      reportSummary('network_inspector');
    })();
    `;
  },
};
