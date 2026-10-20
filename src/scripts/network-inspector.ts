import type { ScriptTemplate } from '../types.js';
import { buildTemplateBody } from './template-body.js';

const BODY = buildTemplateBody('network_inspector', `
  var o = templateOptions();
  var logData = o.log_data === true;
  var hostFilter = null;
  if (o.filter_host) {
    try { hostFilter = new RegExp(String(o.filter_host)); } catch (e) { send({ status: 'error', error: 'Invalid filter_host regex: ' + e.message }); }
  }

  function hostMatches(host) {
    return !hostFilter || hostFilter.test(String(host));
  }

  function toHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('').slice(0, 512);
  }

  // Hook connect
  hookNative(null, 'connect', {
    onEnter: function(args) {
      try {
        var sockaddr = args[1];
        if (sockaddr.isNull()) return;
        var family = sockaddr.readU16();
        if (family === 2) { // AF_INET
          var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
          var ip = sockaddr.add(4).readU8() + '.' + sockaddr.add(5).readU8() + '.' + sockaddr.add(6).readU8() + '.' + sockaddr.add(7).readU8();
          if (hostMatches(ip)) this.info = { api: 'connect', ip: ip, port: port, family: 'IPv4' };
        } else if (family === 30) { // AF_INET6
          var port6 = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
          this.info = { api: 'connect', port: port6, family: 'IPv6' };
        }
      } catch (e) {}
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
      if (logData) { try { this.data = args[1].readByteArray(Math.min(this.size, 256)); } catch (e) {} }
    },
    onLeave: function(retval) {
      var info = { api: 'send', fd: this.fd, size: this.size, sent: retval.toInt32() };
      if (logData && this.data) info.data = toHex(this.data);
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
        if (logData) { try { info.data = toHex(this.buf.readByteArray(Math.min(received, 256))); } catch (e) {} }
        send(info);
      }
    }
  });

  // DNS resolution — getaddrinfo
  hookNative(null, 'getaddrinfo', {
    onEnter: function(args) {
      try { this.hostname = args[0].readUtf8String(); } catch (e) { this.hostname = null; }
    },
    onLeave: function(retval) {
      if (this.hostname && hostMatches(this.hostname)) {
        send({ api: 'getaddrinfo', hostname: this.hostname, result: retval.toInt32() === 0 ? 'success' : 'error' });
      }
    }
  });

  // UDP — sendto
  hookNative(null, 'sendto', {
    onEnter: function(args) {
      try { this.fd = args[0].toInt32(); this.size = args[2].toInt32(); } catch (e) {}
    },
    onLeave: function(retval) {
      if (this.fd !== undefined) send({ api: 'sendto', fd: this.fd, size: this.size, sent: retval.toInt32() });
    }
  });

  // UDP — recvfrom
  hookNative(null, 'recvfrom', {
    onEnter: function(args) {
      try { this.fd = args[0].toInt32(); this.size = args[2].toInt32(); } catch (e) {}
    },
    onLeave: function(retval) {
      if (this.fd !== undefined) send({ api: 'recvfrom', fd: this.fd, requested: this.size, received: retval.toInt32() });
    }
  });

  // TLS library name — shared by SSL_read and SSL_write hooks
  var sslLib = Process.platform === 'darwin' ? 'libboringssl.dylib' : 'libssl.so';

  // TLS plaintext — SSL_read
  hookNative(sslLib, 'SSL_read', {
    onEnter: function(args) { try { this.ssl = args[0]; this.size = args[2].toInt32(); } catch (e) {} },
    onLeave: function(retval) {
      var read = retval.toInt32();
      if (read > 0) send({ api: 'SSL_read', size: read });
    }
  });

  // TLS plaintext — SSL_write
  hookNative(sslLib, 'SSL_write', {
    onEnter: function(args) { try { this.size = args[2].toInt32(); } catch (e) {} },
    onLeave: function(retval) {
      if (retval.toInt32() > 0) send({ api: 'SSL_write', size: retval.toInt32() });
    }
  });
`);

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
  generate: () => BODY,
};
