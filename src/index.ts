#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { MetasploitClient } from "./msf-client.js";
import { getEngagementDB, type Finding } from "./engagement-db.js";
import * as fs from "fs";

// Configuration from environment variables
const MSF_HOST = process.env.MSF_HOST || "127.0.0.1";
const MSF_PORT = parseInt(process.env.MSF_PORT || "55552", 10);
const MSF_SSL = process.env.MSF_SSL !== "false";
const MSF_USERNAME = process.env.MSF_USERNAME || "msf";
const MSF_PASSWORD = process.env.MSF_PASSWORD || "";
const MSF_TOKEN = process.env.MSF_TOKEN || "";

let client: MetasploitClient | null = null;

function getClient(): MetasploitClient {
  if (!client) {
    client = new MetasploitClient({
      host: MSF_HOST,
      port: MSF_PORT,
      ssl: MSF_SSL,
      username: MSF_USERNAME,
      password: MSF_PASSWORD,
      token: MSF_TOKEN || undefined,
    });
  }
  return client;
}

// Tool definitions
const tools: Tool[] = [
  // Connection & Auth
  {
    name: "msf_connect",
    description: "Connect and authenticate to Metasploit RPC server. Required before using other tools unless MSF_TOKEN is set.",
    inputSchema: {
      type: "object",
      properties: {
        username: { type: "string", description: "Username (default: from MSF_USERNAME env)" },
        password: { type: "string", description: "Password (default: from MSF_PASSWORD env)" },
      },
    },
  },
  {
    name: "msf_version",
    description: "Get Metasploit Framework version information",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "msf_status",
    description: "Get Metasploit status including module stats and database connection",
    inputSchema: { type: "object", properties: {} },
  },

  // Module Operations
  {
    name: "msf_module_search",
    description: "Search for Metasploit modules by keyword (exploits, auxiliary, post, payloads)",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search query (e.g., 'smb', 'apache', 'cve:2021')" },
      },
      required: ["query"],
    },
  },
  {
    name: "msf_module_info",
    description: "Get detailed information about a specific module",
    inputSchema: {
      type: "object",
      properties: {
        type: { type: "string", enum: ["exploit", "auxiliary", "post", "payload", "encoder", "nop"], description: "Module type" },
        name: { type: "string", description: "Module name (e.g., 'windows/smb/ms17_010_eternalblue')" },
      },
      required: ["type", "name"],
    },
  },
  {
    name: "msf_module_options",
    description: "Get available options for a module",
    inputSchema: {
      type: "object",
      properties: {
        type: { type: "string", enum: ["exploit", "auxiliary", "post", "payload", "encoder", "nop"], description: "Module type" },
        name: { type: "string", description: "Module name" },
      },
      required: ["type", "name"],
    },
  },
  {
    name: "msf_module_execute",
    description: "Execute a Metasploit module with given options. Use with caution - only for authorized testing.",
    inputSchema: {
      type: "object",
      properties: {
        type: { type: "string", enum: ["exploit", "auxiliary", "post"], description: "Module type" },
        name: { type: "string", description: "Module name" },
        options: {
          type: "object",
          description: "Module options (e.g., {RHOSTS: '192.168.1.1', RPORT: 445})",
          additionalProperties: true,
        },
      },
      required: ["type", "name", "options"],
    },
  },
  {
    name: "msf_module_check",
    description: "Run vulnerability check for an exploit module without exploitation",
    inputSchema: {
      type: "object",
      properties: {
        type: { type: "string", enum: ["exploit", "auxiliary"], description: "Module type" },
        name: { type: "string", description: "Module name" },
        options: {
          type: "object",
          description: "Module options (e.g., {RHOSTS: '192.168.1.1'})",
          additionalProperties: true,
        },
      },
      required: ["type", "name", "options"],
    },
  },
  {
    name: "msf_compatible_payloads",
    description: "List compatible payloads for an exploit module",
    inputSchema: {
      type: "object",
      properties: {
        module: { type: "string", description: "Exploit module name" },
      },
      required: ["module"],
    },
  },

  // Session Management
  {
    name: "msf_sessions_list",
    description: "List all active sessions (shells, meterpreter)",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "msf_session_interact",
    description: "Read output from or write command to a session",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number", description: "Session ID" },
        command: { type: "string", description: "Command to execute (optional - omit to just read)" },
        type: { type: "string", enum: ["shell", "meterpreter"], description: "Session type", default: "shell" },
      },
      required: ["id"],
    },
  },
  {
    name: "msf_session_stop",
    description: "Terminate a session",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number", description: "Session ID" },
      },
      required: ["id"],
    },
  },
  {
    name: "msf_session_upgrade",
    description: "Upgrade a shell session to meterpreter",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number", description: "Session ID" },
        lhost: { type: "string", description: "Local host for callback" },
        lport: { type: "number", description: "Local port for callback" },
      },
      required: ["id", "lhost", "lport"],
    },
  },

  // Job Management
  {
    name: "msf_jobs_list",
    description: "List all running jobs (handlers, scanners, etc.)",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "msf_job_info",
    description: "Get detailed information about a job",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number", description: "Job ID" },
      },
      required: ["id"],
    },
  },
  {
    name: "msf_job_stop",
    description: "Stop a running job",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number", description: "Job ID" },
      },
      required: ["id"],
    },
  },

  // Console
  {
    name: "msf_console_create",
    description: "Create a new Metasploit console for interactive commands",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "msf_console_list",
    description: "List active consoles",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "msf_console_execute",
    description: "Execute a command in a console and return output",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Console ID" },
        command: { type: "string", description: "Command to execute" },
        wait: { type: "boolean", description: "Wait for command completion", default: true },
      },
      required: ["id", "command"],
    },
  },
  {
    name: "msf_console_destroy",
    description: "Destroy a console",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Console ID" },
      },
      required: ["id"],
    },
  },

  // Database
  {
    name: "msf_db_status",
    description: "Check database connection status",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "msf_db_hosts",
    description: "List hosts in the database",
    inputSchema: {
      type: "object",
      properties: {
        workspace: { type: "string", description: "Workspace name (optional)" },
        limit: { type: "number", description: "Maximum number of hosts" },
      },
    },
  },
  {
    name: "msf_db_services",
    description: "List discovered services in the database",
    inputSchema: {
      type: "object",
      properties: {
        host: { type: "string", description: "Filter by host" },
        port: { type: "number", description: "Filter by port" },
        proto: { type: "string", description: "Filter by protocol (tcp/udp)" },
      },
    },
  },
  {
    name: "msf_db_vulns",
    description: "List vulnerabilities in the database",
    inputSchema: {
      type: "object",
      properties: {
        host: { type: "string", description: "Filter by host" },
      },
    },
  },
  {
    name: "msf_db_workspaces",
    description: "List and manage workspaces",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "msf_db_nmap",
    description: "Run nmap and import results into database",
    inputSchema: {
      type: "object",
      properties: {
        args: { type: "string", description: "Nmap arguments (e.g., '-sV -p 1-1000 192.168.1.0/24')" },
      },
      required: ["args"],
    },
  },
  {
    name: "msf_db_import",
    description: "Import scan results (nmap XML, Nessus, etc.)",
    inputSchema: {
      type: "object",
      properties: {
        data: { type: "string", description: "Scan data (XML content)" },
      },
      required: ["data"],
    },
  },

  // Payload Generation (msfvenom-style)
  {
    name: "msf_payload_generate",
    description: "Generate a payload using msfvenom with full options for format, encoding, and output",
    inputSchema: {
      type: "object",
      properties: {
        payload: { type: "string", description: "Payload name (e.g., 'windows/meterpreter/reverse_tcp', 'linux/x64/shell_reverse_tcp')" },
        lhost: { type: "string", description: "Listener host (your IP)" },
        lport: { type: "number", description: "Listener port" },
        format: {
          type: "string",
          description: "Output format: exe, elf, raw, c, python, powershell, bash, java, dll, msi, psh, psh-cmd, psh-reflection, aspx, jsp, war, pl, py, rb, etc.",
          default: "raw"
        },
        encoder: { type: "string", description: "Encoder to use (e.g., 'x86/shikata_ga_nai', 'x64/xor')" },
        iterations: { type: "number", description: "Number of encoding iterations", default: 1 },
        badchars: { type: "string", description: "Characters to avoid (e.g., '\\x00\\x0a\\x0d')" },
        platform: { type: "string", description: "Target platform (windows, linux, osx, etc.)" },
        arch: { type: "string", description: "Target architecture (x86, x64, etc.)" },
        outfile: { type: "string", description: "Output file path (if not set, returns base64)" },
        extra_options: {
          type: "object",
          description: "Additional payload options",
          additionalProperties: true,
        },
      },
      required: ["payload", "lhost", "lport"],
    },
  },
  {
    name: "msf_payload_list",
    description: "List available payloads, optionally filtered by platform or architecture",
    inputSchema: {
      type: "object",
      properties: {
        filter: { type: "string", description: "Filter string (e.g., 'windows', 'meterpreter', 'linux/x64')" },
      },
    },
  },
  {
    name: "msf_encoder_list",
    description: "List available encoders",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "msf_format_list",
    description: "List available output formats for payloads",
    inputSchema: { type: "object", properties: {} },
  },

  // Engagement Management
  {
    name: "engagement_start",
    description: "Start a new engagement or resume an existing one. All subsequent actions will be logged.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Engagement name (e.g., 'GOAD Lab Test')" },
        target: { type: "string", description: "Target environment description" },
        notes: { type: "string", description: "Initial notes about the engagement" },
        resume_id: { type: "number", description: "Resume an existing engagement by ID" },
      },
    },
  },
  {
    name: "engagement_status",
    description: "Get current engagement status, statistics, and recent actions",
    inputSchema: {
      type: "object",
      properties: {
        show_actions: { type: "number", description: "Number of recent actions to show (default: 10)" },
        show_findings: { type: "boolean", description: "Include findings summary", default: true },
      },
    },
  },
  {
    name: "engagement_log",
    description: "Manually log an action or note to the current engagement",
    inputSchema: {
      type: "object",
      properties: {
        phase: { type: "string", description: "Attack phase (e.g., 'enumeration', 'credentials', 'lateral_movement')" },
        action: { type: "string", description: "Description of the action taken" },
        output: { type: "string", description: "Output or result of the action" },
        status: { type: "string", enum: ["success", "failed", "partial"], description: "Action result status" },
        notes: { type: "string", description: "Additional notes" },
      },
      required: ["phase", "action"],
    },
  },
  {
    name: "engagement_finding",
    description: "Record a finding (credential, hash, vulnerability, etc.)",
    inputSchema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          enum: ["credential", "hash", "ticket", "vulnerability", "access", "host", "user", "share", "file", "other"],
          description: "Type of finding",
        },
        name: { type: "string", description: "Finding name/identifier (e.g., 'Administrator NTLM')" },
        value: { type: "string", description: "The actual finding value (hash, password, path, etc.)" },
        notes: { type: "string", description: "Additional context" },
      },
      required: ["type", "name", "value"],
    },
  },
  {
    name: "engagement_check",
    description: "Check if a specific action has already been performed in this engagement",
    inputSchema: {
      type: "object",
      properties: {
        tool: { type: "string", description: "Tool name to check" },
        target: { type: "string", description: "Target to check (optional)" },
      },
      required: ["tool"],
    },
  },
  {
    name: "engagement_export",
    description: "Export engagement data to markdown or JSON file",
    inputSchema: {
      type: "object",
      properties: {
        format: { type: "string", enum: ["markdown", "json"], description: "Export format", default: "markdown" },
        output_path: { type: "string", description: "Output file path (optional, returns content if not specified)" },
      },
    },
  },
  {
    name: "engagement_list",
    description: "List all engagements",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "engagement_clear",
    description: "Delete an engagement and all its data",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number", description: "Engagement ID to delete" },
        confirm: { type: "boolean", description: "Confirm deletion (must be true)" },
      },
      required: ["id", "confirm"],
    },
  },
];

// Tool to phase mapping for auto-logging
const toolPhaseMap: Record<string, string> = {
  // Connection
  msf_connect: "setup",
  msf_version: "setup",
  msf_status: "setup",

  // Enumeration
  msf_module_search: "enumeration",
  msf_module_info: "enumeration",
  msf_module_options: "enumeration",
  msf_compatible_payloads: "enumeration",
  msf_sessions_list: "enumeration",
  msf_jobs_list: "enumeration",
  msf_console_list: "enumeration",
  msf_db_status: "enumeration",
  msf_db_hosts: "enumeration",
  msf_db_services: "enumeration",
  msf_db_vulns: "enumeration",
  msf_db_workspaces: "enumeration",
  msf_payload_list: "enumeration",
  msf_encoder_list: "enumeration",
  msf_format_list: "enumeration",

  // Exploitation
  msf_module_execute: "exploitation",
  msf_module_check: "exploitation",
  msf_db_nmap: "exploitation",

  // Session interaction
  msf_session_interact: "post_exploitation",
  msf_session_stop: "post_exploitation",
  msf_session_upgrade: "post_exploitation",

  // Console
  msf_console_create: "setup",
  msf_console_execute: "post_exploitation",
  msf_console_destroy: "setup",

  // Jobs
  msf_job_info: "enumeration",
  msf_job_stop: "setup",

  // Payloads
  msf_payload_generate: "payload_generation",

  // Database
  msf_db_import: "enumeration",
};

// Helper to get target from args
function extractTarget(args: Record<string, unknown>): string | undefined {
  const options = args.options as Record<string, unknown> | undefined;
  return (
    args.target ||
    args.RHOSTS ||
    args.host ||
    options?.RHOSTS ||
    options?.RHOST ||
    args.id?.toString()
  ) as string | undefined;
}

// Auto-logging wrapper for MSF tools
async function withAutoLogging(
  name: string,
  args: Record<string, unknown>,
  handler: () => Promise<string>
): Promise<string> {
  const db = getEngagementDB();
  const phase = toolPhaseMap[name];

  // Skip logging for engagement tools or if no engagement is active
  if (!phase || name.startsWith("engagement_") || !db.getCurrentEngagementId()) {
    return handler();
  }

  // Log the action start
  const startTime = Date.now();
  const actionId = db.logAction(
    phase,
    name,
    args,
    extractTarget(args)
  );

  try {
    const result = await handler();
    const duration = Date.now() - startTime;

    // Determine status from result
    const status: "success" | "failed" | "partial" =
      result.toLowerCase().includes("error") || result.toLowerCase().includes("failed")
        ? "failed"
        : "success";

    // Truncate output if too long for storage
    const truncatedOutput = result.length > 50000 ? result.substring(0, 50000) + "\n... (truncated)" : result;
    db.updateAction(actionId, truncatedOutput, status, duration);

    return result;
  } catch (error) {
    const duration = Date.now() - startTime;
    const message = error instanceof Error ? error.message : String(error);
    db.updateAction(actionId, `Error: ${message}`, "failed", duration);
    throw error;
  }
}

// Tool handler implementation
async function handleTool(name: string, args: Record<string, unknown>): Promise<string> {
  const msf = getClient();
  const db = getEngagementDB();

  // Wrap MSF tools with auto-logging
  const executeHandler = async (): Promise<string> => {
    switch (name) {
      // Connection & Auth
      case "msf_connect": {
        const token = await msf.login(
          args.username as string | undefined,
          args.password as string | undefined
        );
        return `Connected successfully. Token: ${token.substring(0, 8)}...`;
      }

      case "msf_version": {
        const version = await msf.version();
        return JSON.stringify(version, null, 2);
      }

      case "msf_status": {
        const [version, stats, dbStatus] = await Promise.all([
          msf.version(),
          msf.moduleStats(),
          msf.dbStatus().catch(() => ({ driver: "none", db: "not connected" })),
        ]);
        return JSON.stringify({ version, moduleStats: stats, database: dbStatus }, null, 2);
      }

      // Module Operations
      case "msf_module_search": {
        const results = await msf.moduleSearch(args.query as string);
        if (results.length === 0) return "No modules found matching query.";
        const formatted = results.slice(0, 50).map((m) => ({
          type: m.type,
          name: m.fullname || m.name,
          rank: m.rank,
          description: m.description,
        }));
        return JSON.stringify(formatted, null, 2);
      }

      case "msf_module_info": {
        const info = await msf.moduleInfo(args.type as string, args.name as string);
        return JSON.stringify(info, null, 2);
      }

      case "msf_module_options": {
        const options = await msf.moduleOptions(args.type as string, args.name as string);
        return JSON.stringify(options, null, 2);
      }

      case "msf_module_execute": {
        const result = await msf.moduleExecute(
          args.type as string,
          args.name as string,
          args.options as Record<string, unknown>
        );
        if (result.job_id !== undefined) {
          return `Module launched as job ${result.job_id}. Use msf_job_info to check status.`;
        }
        return JSON.stringify(result, null, 2);
      }

      case "msf_module_check": {
        const result = await msf.moduleCheck(
          args.type as string,
          args.name as string,
          args.options as Record<string, unknown>
        );
        return JSON.stringify(result, null, 2);
      }

      case "msf_compatible_payloads": {
        const payloads = await msf.compatiblePayloads(args.module as string);
        return payloads.length > 0 ? payloads.join("\n") : "No compatible payloads found.";
      }

      // Session Management
      case "msf_sessions_list": {
        const sessions = await msf.sessionList();
        if (Object.keys(sessions).length === 0) return "No active sessions.";
        const formatted = Object.entries(sessions).map(([id, s]) => ({
          id,
          type: s.type,
          info: s.info,
          tunnel: `${s.tunnel_local} -> ${s.tunnel_peer}`,
          via: s.via_exploit,
          target: s.target_host,
        }));
        return JSON.stringify(formatted, null, 2);
      }

      case "msf_session_interact": {
        const sessionId = args.id as number;
        const sessionType = (args.type as string) || "shell";
        const command = args.command as string | undefined;

        if (sessionType === "meterpreter") {
          if (command) {
            await msf.meterpreterWrite(sessionId, command);
            await new Promise((r) => setTimeout(r, 500));
          }
          const output = await msf.meterpreterRead(sessionId);
          return output || "(no output)";
        } else {
          if (command) {
            await msf.shellWrite(sessionId, command + "\n");
            await new Promise((r) => setTimeout(r, 500));
          }
          const result = await msf.shellRead(sessionId);
          return result.data || "(no output)";
        }
      }

      case "msf_session_stop": {
        const success = await msf.sessionStop(args.id as number);
        return success ? `Session ${args.id} terminated.` : `Failed to stop session ${args.id}.`;
      }

      case "msf_session_upgrade": {
        const success = await msf.shellUpgrade(
          args.id as number,
          args.lhost as string,
          args.lport as number
        );
        return success ? "Upgrade initiated." : "Failed to initiate upgrade.";
      }

      // Job Management
      case "msf_jobs_list": {
        const jobs = await msf.jobList();
        if (Object.keys(jobs).length === 0) return "No running jobs.";
        return JSON.stringify(jobs, null, 2);
      }

      case "msf_job_info": {
        const info = await msf.jobInfo(args.id as number);
        return JSON.stringify(info, null, 2);
      }

      case "msf_job_stop": {
        const success = await msf.jobStop(args.id as number);
        return success ? `Job ${args.id} stopped.` : `Failed to stop job ${args.id}.`;
      }

      // Console
      case "msf_console_create": {
        const console = await msf.consoleCreate();
        return `Console created. ID: ${console.id}\nPrompt: ${console.prompt}`;
      }

      case "msf_console_list": {
        const consoles = await msf.consoleList();
        if (Object.keys(consoles).length === 0) return "No active consoles.";
        return JSON.stringify(consoles, null, 2);
      }

      case "msf_console_execute": {
        const consoleId = args.id as string;
        const command = args.command as string;
        const wait = args.wait !== false;

        await msf.consoleWrite(consoleId, command);

        if (wait) {
          let output = "";
          let busy = true;
          const maxWait = 30000;
          const start = Date.now();

          while (busy && Date.now() - start < maxWait) {
            await new Promise((r) => setTimeout(r, 500));
            const result = await msf.consoleRead(consoleId);
            output += result.data;
            busy = result.busy;
          }
          return output || "(no output)";
        }
        return "Command sent.";
      }

      case "msf_console_destroy": {
        const success = await msf.consoleDestroy(args.id as string);
        return success ? `Console ${args.id} destroyed.` : `Failed to destroy console ${args.id}.`;
      }

      // Database
      case "msf_db_status": {
        const status = await msf.dbStatus();
        return JSON.stringify(status, null, 2);
      }

      case "msf_db_hosts": {
        const options: Record<string, unknown> = {};
        if (args.workspace) options.workspace = args.workspace;
        if (args.limit) options.limit = args.limit;
        const result = await msf.dbHosts(options);
        return JSON.stringify(result.hosts, null, 2);
      }

      case "msf_db_services": {
        const options: Record<string, unknown> = {};
        if (args.host) options.host = args.host;
        if (args.port) options.port = args.port;
        if (args.proto) options.proto = args.proto;
        const result = await msf.dbServices(options);
        return JSON.stringify(result.services, null, 2);
      }

      case "msf_db_vulns": {
        const options: Record<string, unknown> = {};
        if (args.host) options.host = args.host;
        const result = await msf.dbVulns(options);
        return JSON.stringify(result.vulns, null, 2);
      }

      case "msf_db_workspaces": {
        const result = await msf.dbWorkspaces();
        return JSON.stringify(result.workspaces, null, 2);
      }

      case "msf_db_nmap": {
        const success = await msf.dbNmap(args.args as string);
        return success ? "Nmap scan initiated." : "Failed to start nmap scan.";
      }

      case "msf_db_import": {
        const success = await msf.dbImportData(args.data as string);
        return success ? "Data imported successfully." : "Failed to import data.";
      }

      // Payload Generation (msfvenom-style via RPC)
      case "msf_payload_generate": {
        const options: Record<string, unknown> = {
          LHOST: args.lhost,
          LPORT: args.lport,
        };

        // Add format
        if (args.format) options.Format = args.format;
        if (args.encoder) options.Encoder = args.encoder;
        if (args.iterations) options.Iterations = args.iterations;
        if (args.badchars) options.BadChars = args.badchars;

        // Add extra options
        if (args.extra_options) {
          Object.assign(options, args.extra_options);
        }

        const result = await msf.moduleExecute("payload", args.payload as string, options);

        if (result.payload) {
          const payloadBytes = typeof result.payload === "string"
            ? Buffer.from(result.payload, "binary")
            : Buffer.from(result.payload as unknown as ArrayBuffer);

          const outfile = args.outfile as string | undefined;
          if (outfile) {
            // Write to file using console
            const b64 = payloadBytes.toString("base64");
            const console = await msf.consoleCreate();
            await msf.consoleWrite(console.id, `echo '${b64}' | base64 -d > ${outfile}`);
            await new Promise((r) => setTimeout(r, 1000));
            await msf.consoleDestroy(console.id);
            return `Payload written to ${outfile} (${payloadBytes.length} bytes)`;
          }

          // Return info based on format
          const format = (args.format as string) || "raw";
          if (["c", "python", "ruby", "perl", "csharp", "java", "powershell", "psh", "bash"].includes(format)) {
            return `Payload generated (${payloadBytes.length} bytes):\n\n${payloadBytes.toString("utf8")}`;
          }
          return `Payload generated (${payloadBytes.length} bytes):\nBase64: ${payloadBytes.toString("base64")}`;
        }
        return JSON.stringify(result, null, 2);
      }

      case "msf_payload_list": {
        const payloads = await msf.payloads();
        const filter = args.filter as string | undefined;
        let filtered = payloads;
        if (filter) {
          filtered = payloads.filter(p => p.toLowerCase().includes(filter.toLowerCase()));
        }
        return `Found ${filtered.length} payloads:\n${filtered.slice(0, 100).join("\n")}${filtered.length > 100 ? "\n... and more" : ""}`;
      }

      case "msf_encoder_list": {
        const encoders = await msf.encoders();
        return `Available encoders (${encoders.length}):\n${encoders.join("\n")}`;
      }

      case "msf_format_list": {
        try {
          const [executable, transform] = await Promise.all([
            msf.executableFormats().catch(() => []),
            msf.transformFormats().catch(() => []),
          ]);
          let output = "";
          if (executable.length > 0) {
            output += `Executable formats (${executable.length}):\n${executable.join(", ")}\n\n`;
          }
          if (transform.length > 0) {
            output += `Transform formats (${transform.length}):\n${transform.join(", ")}`;
          }
          return output || "Format list unavailable via RPC. Common formats: raw, exe, elf, c, python, powershell, psh, bash, ruby, perl";
        } catch {
          return "Executable formats: exe, exe-small, elf, elf-so, macho, msi, dll\nTransform formats: raw, hex, c, csharp, python, powershell, psh, bash, perl, ruby, java";
        }
      }

      // Engagement Management
      case "engagement_start": {
        if (args.resume_id) {
          const engagement = db.setCurrentEngagement(args.resume_id as number);
          if (!engagement) {
            return `Engagement ${args.resume_id} not found.`;
          }
          const stats = db.getEngagementStats(engagement.id);
          return `Resumed engagement: ${engagement.name}\n` +
            `Target: ${engagement.target}\n` +
            `Started: ${engagement.start_time}\n` +
            `Status: ${engagement.status}\n` +
            `Actions: ${stats.totalActions}, Findings: ${stats.totalFindings}`;
        }

        if (!args.name || !args.target) {
          // Check for active engagement
          const active = db.getActiveEngagement();
          if (active) {
            db.setCurrentEngagement(active.id);
            const stats = db.getEngagementStats(active.id);
            return `Active engagement found: ${active.name} (ID: ${active.id})\n` +
              `Target: ${active.target}\n` +
              `Started: ${active.start_time}\n` +
              `Actions: ${stats.totalActions}, Findings: ${stats.totalFindings}\n\n` +
              `Use resume_id to explicitly resume, or provide name and target to start a new one.`;
          }
          return "Please provide 'name' and 'target' to start a new engagement, or 'resume_id' to resume an existing one.";
        }

        const engagement = db.createEngagement(
          args.name as string,
          args.target as string,
          args.notes as string | undefined
        );
        return `Engagement started: ${engagement.name} (ID: ${engagement.id})\n` +
          `Target: ${engagement.target}\n` +
          `All actions will now be logged.\n\n` +
          `Use engagement_status to check progress, engagement_export to generate report.`;
      }

      case "engagement_status": {
        const engagementId = db.getCurrentEngagementId();
        if (!engagementId) {
          return "No active engagement. Use engagement_start to begin.";
        }

        const engagement = db.getEngagement(engagementId)!;
        const stats = db.getEngagementStats(engagementId) as {
          totalActions: number;
          successfulActions: number;
          failedActions: number;
          totalFindings: number;
          findingsByType: Record<string, number>;
          actionsByPhase: Record<string, number>;
          activeSessions: number;
          totalSessions: number;
        };
        const actions = db.getActionsForEngagement(engagementId);
        const showCount = (args.show_actions as number) || 10;

        let output = `## Engagement: ${engagement.name} (ID: ${engagement.id})\n`;
        output += `**Target:** ${engagement.target}\n`;
        output += `**Status:** ${engagement.status}\n`;
        output += `**Started:** ${engagement.start_time}\n\n`;

        output += `### Statistics\n`;
        output += `- Total Actions: ${stats.totalActions} (${stats.successfulActions} successful, ${stats.failedActions} failed)\n`;
        output += `- Total Findings: ${stats.totalFindings}\n`;
        output += `- Active Sessions: ${stats.activeSessions}\n\n`;

        if (stats.totalFindings > 0 && args.show_findings !== false) {
          output += `### Findings by Type\n`;
          for (const [type, count] of Object.entries(stats.findingsByType)) {
            output += `- ${type}: ${count}\n`;
          }
          output += "\n";
        }

        output += `### Actions by Phase\n`;
        for (const [phase, count] of Object.entries(stats.actionsByPhase)) {
          output += `- ${phase}: ${count}\n`;
        }
        output += "\n";

        if (actions.length > 0) {
          output += `### Recent Actions (last ${Math.min(showCount, actions.length)})\n`;
          const recentActions = actions.slice(-showCount);
          for (const action of recentActions) {
            const icon = action.status === "success" ? "✅" : action.status === "failed" ? "❌" : "⚠️";
            output += `${icon} [${action.timestamp}] **${action.tool}**`;
            if (action.target) output += ` → ${action.target}`;
            output += "\n";
          }
        }

        return output;
      }

      case "engagement_log": {
        const engagementId = db.getCurrentEngagementId();
        if (!engagementId) {
          return "No active engagement. Use engagement_start to begin.";
        }

        const actionId = db.logAction(
          args.phase as string,
          args.action as string,
          undefined,
          undefined,
          args.notes as string | undefined
        );

        if (args.output || args.status) {
          db.updateAction(
            actionId,
            (args.output as string) || "",
            (args.status as "success" | "failed" | "partial") || "success"
          );
        }

        return `Logged: [${args.phase}] ${args.action}`;
      }

      case "engagement_finding": {
        const engagementId = db.getCurrentEngagementId();
        if (!engagementId) {
          return "No active engagement. Use engagement_start to begin.";
        }

        // Check if finding already exists
        if (db.findingExists(args.type as Finding["type"], args.value as string)) {
          return `Finding already recorded: ${args.name}`;
        }

        const findingId = db.addFinding(
          args.type as Finding["type"],
          args.name as string,
          args.value as string,
          undefined,
          args.notes as string | undefined
        );

        return `Finding recorded (ID: ${findingId}): [${args.type}] ${args.name}`;
      }

      case "engagement_check": {
        const engagementId = db.getCurrentEngagementId();
        if (!engagementId) {
          return "No active engagement.";
        }

        const existingAction = db.findSimilarAction(
          args.tool as string,
          undefined,
          args.target as string | undefined
        );

        if (existingAction) {
          return `YES - Action already performed:\n` +
            `Tool: ${existingAction.tool}\n` +
            `Time: ${existingAction.timestamp}\n` +
            `Status: ${existingAction.status}\n` +
            `Target: ${existingAction.target || "N/A"}\n\n` +
            `Output preview:\n${(existingAction.output || "").substring(0, 500)}`;
        }

        return `NO - "${args.tool}" has not been run${args.target ? ` against "${args.target}"` : ""} in this engagement.`;
      }

      case "engagement_export": {
        const engagementId = db.getCurrentEngagementId();
        if (!engagementId) {
          return "No active engagement.";
        }

        const format = (args.format as string) || "markdown";
        const content = format === "json"
          ? db.exportToJSON(engagementId)
          : db.exportToMarkdown(engagementId);

        if (args.output_path) {
          fs.writeFileSync(args.output_path as string, content);
          return `Exported to ${args.output_path}`;
        }

        return content;
      }

      case "engagement_list": {
        const engagements = db.listEngagements();
        if (engagements.length === 0) {
          return "No engagements found.";
        }

        const currentId = db.getCurrentEngagementId();
        let output = "## Engagements\n\n";
        output += "| ID | Name | Target | Status | Started |\n";
        output += "|----|------|--------|--------|--------|\n";

        for (const eng of engagements) {
          const marker = eng.id === currentId ? " ⬅️" : "";
          output += `| ${eng.id}${marker} | ${eng.name} | ${eng.target} | ${eng.status} | ${eng.start_time} |\n`;
        }

        return output;
      }

      case "engagement_clear": {
        if (!args.confirm) {
          return "Please set confirm: true to delete the engagement.";
        }

        const id = args.id as number;
        const engagement = db.getEngagement(id);
        if (!engagement) {
          return `Engagement ${id} not found.`;
        }

        const name = engagement.name;
        db.clearEngagement(id);
        return `Engagement "${name}" (ID: ${id}) and all its data have been deleted.`;
      }

      default:
        return `Unknown tool: ${name}`;
    }
  };

  // Use auto-logging wrapper
  try {
    return await withAutoLogging(name, args, executeHandler);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return `Error: ${message}`;
  }
}

// Create and run MCP server
async function main() {
  const server = new Server(
    {
      name: "metasploit-mcp-server",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // List tools handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools };
  });

  // Call tool handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const result = await handleTool(name, (args || {}) as Record<string, unknown>);
    return {
      content: [{ type: "text", text: result }],
    };
  });

  // Connect to stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("Metasploit MCP Server running on stdio");
}

main().catch(console.error);
