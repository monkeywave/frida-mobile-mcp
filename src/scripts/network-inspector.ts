import type { ScriptTemplate } from '../types.js';

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
      // Hook connect
      try {
        var connect = Module.findExportByName(null, 'connect');
        if (connect) {
          Interceptor.attach(connect, {
            onEnter: function(args) {
              var sockaddr = args[1];
              var family = Memory.readU16(sockaddr);
              if (family === 2) { // AF_INET
                var port = (Memory.readU8(sockaddr.add(2)) << 8) | Memory.readU8(sockaddr.add(3));
                var ip = Memory.readU8(sockaddr.add(4)) + '.' + Memory.readU8(sockaddr.add(5)) + '.' + Memory.readU8(sockaddr.add(6)) + '.' + Memory.readU8(sockaddr.add(7));
                this.info = { api: 'connect', ip: ip, port: port, family: 'IPv4' };
              } else if (family === 30) { // AF_INET6
                var port = (Memory.readU8(sockaddr.add(2)) << 8) | Memory.readU8(sockaddr.add(3));
                this.info = { api: 'connect', port: port, family: 'IPv6' };
              }
            },
            onLeave: function(retval) {
              if (this.info) {
                this.info.result = retval.toInt32() === 0 ? 'success' : 'error';
                send(this.info);
              }
            }
          });
          send({ status: 'hooked', api: 'connect' });
        }
      } catch(e) {}

      // Hook send
      try {
        var sendFunc = Module.findExportByName(null, 'send');
        if (sendFunc) {
          Interceptor.attach(sendFunc, {
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
          send({ status: 'hooked', api: 'send' });
        }
      } catch(e) {}

      // Hook recv
      try {
        var recvFunc = Module.findExportByName(null, 'recv');
        if (recvFunc) {
          Interceptor.attach(recvFunc, {
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
          send({ status: 'hooked', api: 'recv' });
        }
      } catch(e) {}
    })();
    `;
  },
};
