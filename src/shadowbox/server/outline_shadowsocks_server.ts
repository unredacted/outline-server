// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import * as child_process from 'child_process';
import * as jsyaml from 'js-yaml';
import * as mkdirp from 'mkdirp';
import * as path from 'path';

import * as file from '../infrastructure/file';
import * as logging from '../infrastructure/logging';
import {ShadowsocksAccessKey, ShadowsocksServer} from '../model/shadowsocks_server';

// Extended interface for access keys with WebSocket configuration
export interface ShadowsocksAccessKeyWithWebSocket extends ShadowsocksAccessKey {
  websocket?: {
    enabled: boolean;
    tcpPath?: string;
    udpPath?: string;
    domain?: string;
    tls?: boolean;
  };
}

// Configuration types for outline-ss-server
interface LegacyConfig {
  keys: ShadowsocksAccessKey[];
}

interface WebSocketListener {
  type: 'websocket-stream' | 'websocket-packet';
  web_server: string;
  path: string;
}

interface TcpUdpListener {
  type: 'tcp' | 'udp';
  address: string;
}

interface ServiceConfig {
  listeners: Array<WebSocketListener | TcpUdpListener>;
  keys: Array<{
    id: string;
    cipher: string;
    secret: string;
  }>;
}

interface WebSocketConfig {
  web?: {
    servers: Array<{
      id: string;
      listen: string[];
    }>;
  };
  services: ServiceConfig[];
}

type ServerConfig = LegacyConfig | WebSocketConfig;

// Runs outline-ss-server.
export class OutlineShadowsocksServer implements ShadowsocksServer {
  private ssProcess: child_process.ChildProcess;
  private ipCountryFilename?: string;
  private ipAsnFilename?: string;
  private isAsnMetricsEnabled = false;
  private isReplayProtectionEnabled = false;
  private webSocketConfig?: {
    enabled: boolean;
    webServerPort: number;
  };

  /**
   * @param binaryFilename The location for the outline-ss-server binary.
   * @param configFilename The location for the outline-ss-server config.
   * @param verbose Whether to run the server in verbose mode.
   * @param metricsLocation The location from where to serve the Prometheus data metrics.
   */
  constructor(
    private readonly binaryFilename: string,
    private readonly configFilename: string,
    private readonly verbose: boolean,
    private readonly metricsLocation: string
  ) {}

  /**
   * Configures the Shadowsocks Server with country data to annotate Prometheus data metrics.
   * @param ipCountryFilename The location of the ip-country.mmdb IP-to-country database file.
   */
  configureCountryMetrics(ipCountryFilename: string): OutlineShadowsocksServer {
    this.ipCountryFilename = ipCountryFilename;
    return this;
  }

  /**
   * Configures the Shadowsocks Server with ASN data to annotate Prometheus data metrics.
   * @param ipAsnFilename The location  of the ip-asn.mmdb IP-to-ASN database file.
   */
  configureAsnMetrics(ipAsnFilename: string): OutlineShadowsocksServer {
    this.ipAsnFilename = ipAsnFilename;
    return this;
  }

  enableReplayProtection(): OutlineShadowsocksServer {
    this.isReplayProtectionEnabled = true;
    return this;
  }

  /**
   * Configures WebSocket support for the Shadowsocks server.
   * @param webServerPort The port for the internal WebSocket server to listen on.
   */
  configureWebSocket(webServerPort: number): OutlineShadowsocksServer {
    this.webSocketConfig = {
      enabled: true,
      webServerPort,
    };
    return this;
  }

  // Promise is resolved after the outline-ss-config config is updated and the SIGHUP sent.
  // Keys may not be active yet.
  // TODO(fortuna): Make promise resolve when keys are ready.
  update(keys: ShadowsocksAccessKey[]): Promise<void> {
    return this.writeConfigFile(keys).then(() => {
      if (!this.ssProcess) {
        this.start();
        return Promise.resolve();
      } else {
        this.ssProcess.kill('SIGHUP');
      }
    });
  }

  private writeConfigFile(keys: ShadowsocksAccessKey[]): Promise<void> {
    return new Promise((resolve, reject) => {
      // Check if any key has WebSocket configuration
      const extendedKeys = keys as ShadowsocksAccessKeyWithWebSocket[];
      const hasWebSocketKeys = extendedKeys.some(key => key.websocket?.enabled);
      
      let config: ServerConfig;
      
      if (hasWebSocketKeys && this.webSocketConfig?.enabled) {
        // Use new format with WebSocket support
        config = this.generateWebSocketConfig(extendedKeys);
      } else {
        // Use legacy format for backward compatibility
        const keysJson = {keys: [] as ShadowsocksAccessKey[]};
        for (const key of keys) {
          if (!isAeadCipher(key.cipher)) {
            logging.error(
              `Cipher ${key.cipher} for access key ${key.id} is not supported: use an AEAD cipher instead.`
            );
            continue;
          }
          keysJson.keys.push(key);
        }
        config = keysJson;
      }

      mkdirp.sync(path.dirname(this.configFilename));

      try {
        file.atomicWriteFileSync(this.configFilename, jsyaml.safeDump(config, {sortKeys: true}));
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  }

  private generateWebSocketConfig(keys: ShadowsocksAccessKeyWithWebSocket[]): WebSocketConfig {
    // Group keys by their listener configuration
    const serviceGroups = new Map<string, ShadowsocksAccessKeyWithWebSocket[]>();
    
    // Process each key
    for (const key of keys) {
      if (!isAeadCipher(key.cipher)) {
        logging.error(
          `Cipher ${key.cipher} for access key ${key.id} is not supported: use an AEAD cipher instead.`
        );
        continue;
      }

      if (key.websocket?.enabled) {
        // Group WebSocket-enabled keys by their paths
        const groupKey = `ws:${key.websocket.tcpPath || '/tcp'}:${key.websocket.udpPath || '/udp'}`;
        if (!serviceGroups.has(groupKey)) {
          serviceGroups.set(groupKey, []);
        }
        serviceGroups.get(groupKey)!.push(key);
      } else {
        // Group traditional keys by port
        const groupKey = `port:${key.port}`;
        if (!serviceGroups.has(groupKey)) {
          serviceGroups.set(groupKey, []);
        }
        serviceGroups.get(groupKey)!.push(key);
      }
    }

    // Build the configuration
    const config: WebSocketConfig = {
      services: []
    };

    // Add web server configuration if any WebSocket keys exist
    if (Array.from(serviceGroups.keys()).some(k => k.startsWith('ws:'))) {
      config.web = {
        servers: [{
          id: 'outline-ws-server',
          listen: [`127.0.0.1:${this.webSocketConfig!.webServerPort}`]
        }]
      };
    }

    // Create services
    for (const [groupKey, groupKeys] of serviceGroups) {
      const service: ServiceConfig = {
        listeners: [],
        keys: groupKeys.map(k => ({
          id: k.id,
          cipher: k.cipher,
          secret: k.secret
        }))
      };

      if (groupKey.startsWith('ws:')) {
        // WebSocket listeners
        const [, tcpPath, udpPath] = groupKey.split(':');
        service.listeners.push({
          type: 'websocket-stream',
          web_server: 'outline-ws-server',
          path: tcpPath
        });
        service.listeners.push({
          type: 'websocket-packet',
          web_server: 'outline-ws-server',
          path: udpPath
        });
      } else if (groupKey.startsWith('port:')) {
        // Traditional TCP/UDP listeners
        const port = groupKey.split(':')[1];
        service.listeners.push({
          type: 'tcp',
          address: `[::]:${port}`
        });
        service.listeners.push({
          type: 'udp',
          address: `[::]:${port}`
        });
      }

      config.services.push(service);
    }

    return config;
  }

  /**
   * Generates dynamic access key YAML content for a specific access key with WebSocket support.
   * @param proxyParams The proxy parameters containing cipher and password
   * @param websocket The WebSocket configuration
   * @returns The YAML content as a string, or null if the key doesn't have WebSocket enabled
   */
  generateDynamicAccessKeyYaml(proxyParams: {encryptionMethod: string; password: string}, websocket?: {enabled: boolean; tcpPath?: string; udpPath?: string; domain?: string; tls?: boolean}): string | null {
    if (!websocket?.enabled || !websocket.domain) {
      return null;
    }

    const protocol = websocket.tls !== false ? 'wss' : 'ws';
    
    const config = {
      transport: {
        $type: 'tcpudp',
        tcp: {
          $type: 'shadowsocks',
          endpoint: {
            $type: 'websocket',
            url: `${protocol}://${websocket.domain}${websocket.tcpPath || '/tcp'}`
          },
          cipher: proxyParams.encryptionMethod,
          secret: proxyParams.password
        },
        udp: {
          $type: 'shadowsocks',
          endpoint: {
            $type: 'websocket',
            url: `${protocol}://${websocket.domain}${websocket.udpPath || '/udp'}`
          },
          cipher: proxyParams.encryptionMethod,
          secret: proxyParams.password
        }
      }
    };

    return jsyaml.safeDump(config, {sortKeys: true});
  }

  private start() {
    const commandArguments = ['-config', this.configFilename, '-metrics', this.metricsLocation];
    if (this.ipCountryFilename) {
      commandArguments.push('-ip_country_db', this.ipCountryFilename);
    }
    if (this.ipAsnFilename) {
      commandArguments.push('-ip_asn_db', this.ipAsnFilename);
    }
    if (this.verbose) {
      commandArguments.push('-verbose');
    }
    if (this.isReplayProtectionEnabled) {
      commandArguments.push('--replay_history=10000');
    }
    logging.info('======== Starting Outline Shadowsocks Service ========');
    logging.info(`${this.binaryFilename} ${commandArguments.map((a) => `"${a}"`).join(' ')}`);
    this.ssProcess = child_process.spawn(this.binaryFilename, commandArguments);
    this.ssProcess.on('error', (error) => {
      logging.error(`Error spawning outline-ss-server: ${error}`);
    });
    this.ssProcess.on('exit', (code, signal) => {
      logging.info(`outline-ss-server has exited with error. Code: ${code}, Signal: ${signal}`);
      logging.info('Restarting');
      this.start();
    });
    // This exposes the outline-ss-server output on the docker logs.
    // TODO(fortuna): Consider saving the output and expose it through the manager service.
    this.ssProcess.stdout.pipe(process.stdout);
    this.ssProcess.stderr.pipe(process.stderr);
  }
}

// List of AEAD ciphers can be found at https://shadowsocks.org/en/spec/AEAD-Ciphers.html
function isAeadCipher(cipherAlias: string) {
  cipherAlias = cipherAlias.toLowerCase();
  return cipherAlias.endsWith('gcm') || cipherAlias.endsWith('poly1305');
}
