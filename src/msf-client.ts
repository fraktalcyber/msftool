import * as https from "https";
import * as http from "http";
import msgpack from "msgpack5";

const mp = msgpack();

// Convert Buffer keys/values to strings recursively
function convertBuffers(obj: unknown): unknown {
  if (Buffer.isBuffer(obj)) {
    return obj.toString("utf8");
  }
  if (obj instanceof Map) {
    const result: Record<string, unknown> = {};
    for (const [key, value] of obj) {
      const keyStr = Buffer.isBuffer(key) ? key.toString("utf8") : String(key);
      result[keyStr] = convertBuffers(value);
    }
    return result;
  }
  if (Array.isArray(obj)) {
    return obj.map(convertBuffers);
  }
  if (obj && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = convertBuffers(value);
    }
    return result;
  }
  return obj;
}

export interface MsfConfig {
  host: string;
  port: number;
  ssl: boolean;
  username?: string;
  password?: string;
  token?: string;
}

export interface MsfSession {
  type: string;
  tunnel_local: string;
  tunnel_peer: string;
  via_exploit: string;
  via_payload: string;
  desc: string;
  info: string;
  workspace: string;
  session_host: string;
  session_port: number;
  target_host: string;
  username: string;
  uuid: string;
  exploit_uuid: string;
  routes: string[];
  arch: string;
  platform: string;
}

export interface MsfJob {
  jid: number;
  name: string;
  start_time: number;
  datastore: Record<string, unknown>;
}

export interface MsfConsole {
  id: string;
  prompt: string;
  busy: boolean;
}

export interface MsfModuleInfo {
  name: string;
  description: string;
  license: string;
  rank: string;
  authors: string[];
  references: Array<[string, string]>;
  targets?: Array<{ id: number; name: string }>;
  options: Record<string, unknown>;
}

export class MetasploitClient {
  private config: MsfConfig;
  private token: string | null = null;

  constructor(config: MsfConfig) {
    this.config = config;
    if (config.token) {
      this.token = config.token;
    }
  }

  private async call(method: string, ...args: unknown[]): Promise<unknown> {
    const params = this.token ? [method, this.token, ...args] : [method, ...args];
    const packed = mp.encode(params);

    return new Promise((resolve, reject) => {
      const options = {
        hostname: this.config.host,
        port: this.config.port,
        path: "/api/",
        method: "POST",
        headers: {
          "Content-Type": "binary/message-pack",
          "Content-Length": packed.length,
        },
        rejectUnauthorized: false, // Allow self-signed certs
      };

      const protocol = this.config.ssl ? https : http;
      const req = protocol.request(options, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          try {
            const buffer = Buffer.concat(chunks);
            const raw = mp.decode(buffer);
            const decoded = convertBuffers(raw);
            if (decoded && typeof decoded === "object" && "error" in decoded) {
              reject(new Error(`MSF Error: ${(decoded as { error: unknown }).error}`));
            } else {
              resolve(decoded);
            }
          } catch (err) {
            reject(err);
          }
        });
      });

      req.on("error", reject);
      req.write(packed);
      req.end();
    });
  }

  // Authentication
  async login(username?: string, password?: string): Promise<string> {
    const user = username || this.config.username;
    const pass = password || this.config.password;
    if (!user || !pass) {
      throw new Error("Username and password required for login");
    }
    const result = (await this.call("auth.login", user, pass)) as { token: string };
    this.token = result.token;
    return result.token;
  }

  async logout(): Promise<boolean> {
    const result = (await this.call("auth.logout", this.token)) as { result: string };
    this.token = null;
    return result.result === "success";
  }

  async tokenList(): Promise<string[]> {
    const result = (await this.call("auth.token_list")) as { tokens: string[] };
    return result.tokens;
  }

  // Core
  async version(): Promise<{ version: string; ruby: string; api: string }> {
    return (await this.call("core.version")) as { version: string; ruby: string; api: string };
  }

  async moduleStats(): Promise<Record<string, number>> {
    return (await this.call("core.module_stats")) as Record<string, number>;
  }

  async setGlobal(name: string, value: string): Promise<boolean> {
    const result = (await this.call("core.setg", name, value)) as { result: string };
    return result.result === "success";
  }

  async unsetGlobal(name: string): Promise<boolean> {
    const result = (await this.call("core.unsetg", name)) as { result: string };
    return result.result === "success";
  }

  async threadList(): Promise<Record<string, unknown>> {
    return (await this.call("core.thread_list")) as Record<string, unknown>;
  }

  async threadKill(id: number): Promise<boolean> {
    const result = (await this.call("core.thread_kill", id)) as { result: string };
    return result.result === "success";
  }

  // Modules
  async exploits(): Promise<string[]> {
    const result = (await this.call("module.exploits")) as { modules: string[] };
    return result.modules;
  }

  async auxiliary(): Promise<string[]> {
    const result = (await this.call("module.auxiliary")) as { modules: string[] };
    return result.modules;
  }

  async post(): Promise<string[]> {
    const result = (await this.call("module.post")) as { modules: string[] };
    return result.modules;
  }

  async payloads(): Promise<string[]> {
    const result = (await this.call("module.payloads")) as { modules: string[] };
    return result.modules;
  }

  async encoders(): Promise<string[]> {
    const result = (await this.call("module.encoders")) as { modules: string[] };
    return result.modules;
  }

  async nops(): Promise<string[]> {
    const result = (await this.call("module.nops")) as { modules: string[] };
    return result.modules;
  }

  async moduleInfo(type: string, name: string): Promise<MsfModuleInfo> {
    return (await this.call("module.info", type, name)) as MsfModuleInfo;
  }

  async moduleOptions(type: string, name: string): Promise<Record<string, unknown>> {
    return (await this.call("module.options", type, name)) as Record<string, unknown>;
  }

  async moduleSearch(query: string): Promise<Array<Record<string, unknown>>> {
    const result = (await this.call("module.search", query)) as Array<Record<string, unknown>>;
    return result;
  }

  async compatiblePayloads(moduleName: string): Promise<string[]> {
    const result = (await this.call("module.compatible_payloads", moduleName)) as { payloads: string[] };
    return result.payloads;
  }

  async moduleExecute(
    type: string,
    name: string,
    options: Record<string, unknown>
  ): Promise<{ job_id?: number; uuid?: string; payload?: string }> {
    return (await this.call("module.execute", type, name, options)) as {
      job_id?: number;
      uuid?: string;
      payload?: string;
    };
  }

  async moduleCheck(type: string, name: string, options: Record<string, unknown>): Promise<Record<string, unknown>> {
    return (await this.call("module.check", type, name, options)) as Record<string, unknown>;
  }

  async executableFormats(): Promise<string[]> {
    const result = (await this.call("module.executable_formats")) as string[];
    return result;
  }

  async transformFormats(): Promise<string[]> {
    const result = (await this.call("module.transform_formats")) as string[];
    return result;
  }

  async encodeFormats(): Promise<string[]> {
    const result = (await this.call("module.encode_formats")) as string[];
    return result;
  }

  async platformList(): Promise<string[]> {
    const result = (await this.call("module.platforms")) as string[];
    return result;
  }

  async archList(): Promise<string[]> {
    const result = (await this.call("module.architectures")) as string[];
    return result;
  }

  // Sessions
  async sessionList(): Promise<Record<string, MsfSession>> {
    return (await this.call("session.list")) as Record<string, MsfSession>;
  }

  async sessionStop(id: number): Promise<boolean> {
    const result = (await this.call("session.stop", id)) as { result: string };
    return result.result === "success";
  }

  async shellRead(id: number, pointer?: number): Promise<{ seq: number; data: string }> {
    if (pointer !== undefined) {
      return (await this.call("session.shell_read", id, pointer)) as { seq: number; data: string };
    }
    return (await this.call("session.shell_read", id)) as { seq: number; data: string };
  }

  async shellWrite(id: number, data: string): Promise<number> {
    const result = (await this.call("session.shell_write", id, data)) as { write_count: number };
    return result.write_count;
  }

  async meterpreterRead(id: number): Promise<string> {
    const result = (await this.call("session.meterpreter_read", id)) as { data: string };
    return result.data;
  }

  async meterpreterWrite(id: number, command: string): Promise<boolean> {
    const result = (await this.call("session.meterpreter_write", id, command)) as { result: string };
    return result.result === "success";
  }

  async meterpreterRunSingle(id: number, command: string): Promise<boolean> {
    const result = (await this.call("session.meterpreter_run_single", id, command)) as { result: string };
    return result.result === "success";
  }

  async compatibleSessionModules(id: number): Promise<string[]> {
    const result = (await this.call("session.compatible_modules", id)) as { modules: string[] };
    return result.modules;
  }

  async shellUpgrade(id: number, host: string, port: number): Promise<boolean> {
    const result = (await this.call("session.shell_upgrade", id, host, port)) as { result: string };
    return result.result === "success";
  }

  // Jobs
  async jobList(): Promise<Record<string, string>> {
    return (await this.call("job.list")) as Record<string, string>;
  }

  async jobInfo(id: number): Promise<MsfJob> {
    return (await this.call("job.info", id)) as MsfJob;
  }

  async jobStop(id: number): Promise<boolean> {
    const result = (await this.call("job.stop", id)) as { result: string };
    return result.result === "success";
  }

  // Console
  async consoleCreate(): Promise<MsfConsole> {
    return (await this.call("console.create")) as MsfConsole;
  }

  async consoleDestroy(id: string): Promise<boolean> {
    const result = (await this.call("console.destroy", id)) as { result: string };
    return result.result === "success";
  }

  async consoleList(): Promise<Record<string, MsfConsole>> {
    return (await this.call("console.list")) as Record<string, MsfConsole>;
  }

  async consoleWrite(id: string, command: string): Promise<number> {
    const result = (await this.call("console.write", id, command + "\n")) as { wrote: number };
    return result.wrote;
  }

  async consoleRead(id: string): Promise<{ data: string; prompt: string; busy: boolean }> {
    return (await this.call("console.read", id)) as { data: string; prompt: string; busy: boolean };
  }

  async consoleTabs(id: string, line: string): Promise<string[]> {
    const result = (await this.call("console.tabs", id, line)) as { tabs: string[] };
    return result.tabs;
  }

  // Plugins
  async pluginLoad(name: string, options?: Record<string, unknown>): Promise<boolean> {
    const result = (await this.call("plugin.load", name, options || {})) as { result: string };
    return result.result === "success";
  }

  async pluginUnload(name: string): Promise<boolean> {
    const result = (await this.call("plugin.unload", name)) as { result: string };
    return result.result === "success";
  }

  async pluginLoaded(): Promise<string[]> {
    const result = (await this.call("plugin.loaded")) as { plugins: string[] };
    return result.plugins;
  }

  // Database
  async dbStatus(): Promise<{ driver: string; db: string }> {
    return (await this.call("db.status")) as { driver: string; db: string };
  }

  async dbHosts(options?: Record<string, unknown>): Promise<{ hosts: Array<Record<string, unknown>> }> {
    return (await this.call("db.hosts", options || {})) as { hosts: Array<Record<string, unknown>> };
  }

  async dbServices(options?: Record<string, unknown>): Promise<{ services: Array<Record<string, unknown>> }> {
    return (await this.call("db.services", options || {})) as { services: Array<Record<string, unknown>> };
  }

  async dbVulns(options?: Record<string, unknown>): Promise<{ vulns: Array<Record<string, unknown>> }> {
    return (await this.call("db.vulns", options || {})) as { vulns: Array<Record<string, unknown>> };
  }

  async dbWorkspaces(): Promise<{ workspaces: Array<Record<string, unknown>> }> {
    return (await this.call("db.workspaces")) as { workspaces: Array<Record<string, unknown>> };
  }

  async dbCurrentWorkspace(): Promise<{ workspace: string; workspace_id: number }> {
    return (await this.call("db.current_workspace")) as { workspace: string; workspace_id: number };
  }

  async dbSetWorkspace(name: string): Promise<boolean> {
    const result = (await this.call("db.set_workspace", name)) as { result: string };
    return result.result === "success";
  }

  async dbImportData(data: string): Promise<boolean> {
    const result = (await this.call("db.import_data", { data })) as { result: string };
    return result.result === "success";
  }

  async dbNmap(args: string): Promise<boolean> {
    const result = (await this.call("db.nmap", args)) as { result: string };
    return result.result === "success";
  }

  // Health check
  async isConnected(): Promise<boolean> {
    try {
      await this.version();
      return true;
    } catch {
      return false;
    }
  }
}
