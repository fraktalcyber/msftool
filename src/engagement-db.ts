import Database from "better-sqlite3";
import * as path from "path";
import * as fs from "fs";

export interface Engagement {
  id: number;
  name: string;
  target: string;
  start_time: string;
  end_time: string | null;
  status: "active" | "completed" | "paused";
  notes: string | null;
}

export interface Action {
  id: number;
  engagement_id: number;
  timestamp: string;
  phase: string;
  tool: string;
  target: string | null;
  input_params: string | null;
  output: string | null;
  status: "success" | "failed" | "partial" | "running";
  duration_ms: number | null;
  notes: string | null;
}

export interface Finding {
  id: number;
  engagement_id: number;
  timestamp: string;
  type: "credential" | "hash" | "ticket" | "vulnerability" | "access" | "host" | "user" | "share" | "file" | "other";
  name: string;
  value: string;
  source_action_id: number | null;
  notes: string | null;
}

export interface Session {
  id: number;
  engagement_id: number;
  msf_session_id: string;
  session_type: string;
  target_host: string;
  target_user: string | null;
  status: "active" | "dead" | "upgraded";
  created_at: string;
  notes: string | null;
}

export class EngagementDB {
  private db: Database.Database;
  private currentEngagementId: number | null = null;

  constructor(dbPath?: string) {
    const defaultPath = path.join(process.env.HOME || ".", ".msftool", "engagements.db");
    const finalPath = dbPath || defaultPath;

    // Ensure directory exists
    const dir = path.dirname(finalPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(finalPath);
    this.initialize();
  }

  private initialize(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS engagements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        target TEXT NOT NULL,
        start_time TEXT NOT NULL DEFAULT (datetime('now')),
        end_time TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        notes TEXT
      );

      CREATE TABLE IF NOT EXISTS actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL,
        timestamp TEXT NOT NULL DEFAULT (datetime('now')),
        phase TEXT NOT NULL,
        tool TEXT NOT NULL,
        target TEXT,
        input_params TEXT,
        output TEXT,
        status TEXT NOT NULL DEFAULT 'running',
        duration_ms INTEGER,
        notes TEXT,
        FOREIGN KEY (engagement_id) REFERENCES engagements(id)
      );

      CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL,
        timestamp TEXT NOT NULL DEFAULT (datetime('now')),
        type TEXT NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        source_action_id INTEGER,
        notes TEXT,
        FOREIGN KEY (engagement_id) REFERENCES engagements(id),
        FOREIGN KEY (source_action_id) REFERENCES actions(id)
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL,
        msf_session_id TEXT NOT NULL,
        session_type TEXT NOT NULL,
        target_host TEXT NOT NULL,
        target_user TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        notes TEXT,
        FOREIGN KEY (engagement_id) REFERENCES engagements(id)
      );

      CREATE INDEX IF NOT EXISTS idx_actions_engagement ON actions(engagement_id);
      CREATE INDEX IF NOT EXISTS idx_actions_tool ON actions(tool);
      CREATE INDEX IF NOT EXISTS idx_actions_phase ON actions(phase);
      CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
      CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
      CREATE INDEX IF NOT EXISTS idx_sessions_engagement ON sessions(engagement_id);
    `);
  }

  // Engagement methods
  createEngagement(name: string, target: string, notes?: string): Engagement {
    const stmt = this.db.prepare(`
      INSERT INTO engagements (name, target, notes) VALUES (?, ?, ?)
    `);
    const result = stmt.run(name, target, notes || null);
    this.currentEngagementId = result.lastInsertRowid as number;
    return this.getEngagement(this.currentEngagementId)!;
  }

  getEngagement(id: number): Engagement | null {
    const stmt = this.db.prepare("SELECT * FROM engagements WHERE id = ?");
    return stmt.get(id) as Engagement | null;
  }

  getActiveEngagement(): Engagement | null {
    const stmt = this.db.prepare("SELECT * FROM engagements WHERE status = 'active' ORDER BY start_time DESC LIMIT 1");
    return stmt.get() as Engagement | null;
  }

  listEngagements(): Engagement[] {
    const stmt = this.db.prepare("SELECT * FROM engagements ORDER BY start_time DESC");
    return stmt.all() as Engagement[];
  }

  setCurrentEngagement(id: number): Engagement | null {
    const engagement = this.getEngagement(id);
    if (engagement) {
      this.currentEngagementId = id;
    }
    return engagement;
  }

  getCurrentEngagementId(): number | null {
    return this.currentEngagementId;
  }

  updateEngagementStatus(id: number, status: "active" | "completed" | "paused"): void {
    const stmt = this.db.prepare("UPDATE engagements SET status = ?, end_time = ? WHERE id = ?");
    const endTime = status === "completed" ? new Date().toISOString() : null;
    stmt.run(status, endTime, id);
  }

  clearEngagement(id: number): void {
    // Delete in order due to foreign keys
    this.db.prepare("DELETE FROM findings WHERE engagement_id = ?").run(id);
    this.db.prepare("DELETE FROM sessions WHERE engagement_id = ?").run(id);
    this.db.prepare("DELETE FROM actions WHERE engagement_id = ?").run(id);
    this.db.prepare("DELETE FROM engagements WHERE id = ?").run(id);

    if (this.currentEngagementId === id) {
      this.currentEngagementId = null;
    }
  }

  // Action methods
  logAction(
    phase: string,
    tool: string,
    inputParams?: Record<string, unknown>,
    target?: string,
    notes?: string
  ): number {
    if (!this.currentEngagementId) {
      throw new Error("No active engagement. Start one with engagement_start.");
    }

    const stmt = this.db.prepare(`
      INSERT INTO actions (engagement_id, phase, tool, target, input_params, notes)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      this.currentEngagementId,
      phase,
      tool,
      target || null,
      inputParams ? JSON.stringify(inputParams) : null,
      notes || null
    );
    return result.lastInsertRowid as number;
  }

  updateAction(id: number, output: string, status: "success" | "failed" | "partial", durationMs?: number): void {
    const stmt = this.db.prepare(`
      UPDATE actions SET output = ?, status = ?, duration_ms = ? WHERE id = ?
    `);
    stmt.run(output, status, durationMs || null, id);
  }

  getAction(id: number): Action | null {
    const stmt = this.db.prepare("SELECT * FROM actions WHERE id = ?");
    return stmt.get(id) as Action | null;
  }

  getActionsForEngagement(engagementId: number): Action[] {
    const stmt = this.db.prepare("SELECT * FROM actions WHERE engagement_id = ? ORDER BY timestamp");
    return stmt.all(engagementId) as Action[];
  }

  findSimilarAction(tool: string, inputParams?: Record<string, unknown>, target?: string): Action | null {
    if (!this.currentEngagementId) return null;

    let query = "SELECT * FROM actions WHERE engagement_id = ? AND tool = ?";
    const params: (string | number)[] = [this.currentEngagementId, tool];

    if (target) {
      query += " AND target = ?";
      params.push(target);
    }

    if (inputParams) {
      query += " AND input_params = ?";
      params.push(JSON.stringify(inputParams));
    }

    query += " AND status = 'success' ORDER BY timestamp DESC LIMIT 1";

    const stmt = this.db.prepare(query);
    return stmt.get(...params) as Action | null;
  }

  getActionsByPhase(engagementId: number, phase: string): Action[] {
    const stmt = this.db.prepare("SELECT * FROM actions WHERE engagement_id = ? AND phase = ? ORDER BY timestamp");
    return stmt.all(engagementId, phase) as Action[];
  }

  getActionsByTool(engagementId: number, tool: string): Action[] {
    const stmt = this.db.prepare("SELECT * FROM actions WHERE engagement_id = ? AND tool = ? ORDER BY timestamp");
    return stmt.all(engagementId, tool) as Action[];
  }

  // Finding methods
  addFinding(
    type: Finding["type"],
    name: string,
    value: string,
    sourceActionId?: number,
    notes?: string
  ): number {
    if (!this.currentEngagementId) {
      throw new Error("No active engagement.");
    }

    const stmt = this.db.prepare(`
      INSERT INTO findings (engagement_id, type, name, value, source_action_id, notes)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      this.currentEngagementId,
      type,
      name,
      value,
      sourceActionId || null,
      notes || null
    );
    return result.lastInsertRowid as number;
  }

  getFindingsForEngagement(engagementId: number): Finding[] {
    const stmt = this.db.prepare("SELECT * FROM findings WHERE engagement_id = ? ORDER BY timestamp");
    return stmt.all(engagementId) as Finding[];
  }

  getFindingsByType(engagementId: number, type: Finding["type"]): Finding[] {
    const stmt = this.db.prepare("SELECT * FROM findings WHERE engagement_id = ? AND type = ? ORDER BY timestamp");
    return stmt.all(engagementId, type) as Finding[];
  }

  findingExists(type: Finding["type"], value: string): boolean {
    if (!this.currentEngagementId) return false;
    const stmt = this.db.prepare("SELECT 1 FROM findings WHERE engagement_id = ? AND type = ? AND value = ? LIMIT 1");
    return !!stmt.get(this.currentEngagementId, type, value);
  }

  // Session methods
  addSession(
    msfSessionId: string,
    sessionType: string,
    targetHost: string,
    targetUser?: string,
    notes?: string
  ): number {
    if (!this.currentEngagementId) {
      throw new Error("No active engagement.");
    }

    const stmt = this.db.prepare(`
      INSERT INTO sessions (engagement_id, msf_session_id, session_type, target_host, target_user, notes)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      this.currentEngagementId,
      msfSessionId,
      sessionType,
      targetHost,
      targetUser || null,
      notes || null
    );
    return result.lastInsertRowid as number;
  }

  updateSessionStatus(msfSessionId: string, status: "active" | "dead" | "upgraded"): void {
    const stmt = this.db.prepare("UPDATE sessions SET status = ? WHERE msf_session_id = ?");
    stmt.run(status, msfSessionId);
  }

  getSessionsForEngagement(engagementId: number): Session[] {
    const stmt = this.db.prepare("SELECT * FROM sessions WHERE engagement_id = ? ORDER BY created_at");
    return stmt.all(engagementId) as Session[];
  }

  // Export methods
  exportToMarkdown(engagementId: number): string {
    const engagement = this.getEngagement(engagementId);
    if (!engagement) {
      throw new Error("Engagement not found");
    }

    const actions = this.getActionsForEngagement(engagementId);
    const findings = this.getFindingsForEngagement(engagementId);
    const sessions = this.getSessionsForEngagement(engagementId);

    let md = `# Engagement: ${engagement.name}\n\n`;
    md += `**Target:** ${engagement.target}\n`;
    md += `**Started:** ${engagement.start_time}\n`;
    if (engagement.end_time) {
      md += `**Ended:** ${engagement.end_time}\n`;
    }
    md += `**Status:** ${engagement.status}\n`;
    if (engagement.notes) {
      md += `**Notes:** ${engagement.notes}\n`;
    }
    md += "\n---\n\n";

    // Sessions
    if (sessions.length > 0) {
      md += "## Sessions\n\n";
      md += "| ID | Type | Host | User | Status |\n";
      md += "|----|------|------|------|--------|\n";
      for (const session of sessions) {
        md += `| ${session.msf_session_id} | ${session.session_type} | ${session.target_host} | ${session.target_user || "-"} | ${session.status} |\n`;
      }
      md += "\n";
    }

    // Findings summary
    if (findings.length > 0) {
      md += "## Findings Summary\n\n";

      const findingsByType = new Map<string, Finding[]>();
      for (const finding of findings) {
        if (!findingsByType.has(finding.type)) {
          findingsByType.set(finding.type, []);
        }
        findingsByType.get(finding.type)!.push(finding);
      }

      for (const [type, typeFindings] of findingsByType) {
        md += `### ${type.charAt(0).toUpperCase() + type.slice(1)}s (${typeFindings.length})\n\n`;
        for (const finding of typeFindings) {
          md += `- **${finding.name}**: \`${finding.value}\``;
          if (finding.notes) {
            md += ` - ${finding.notes}`;
          }
          md += "\n";
        }
        md += "\n";
      }
    }

    // Action timeline
    md += "## Action Timeline\n\n";

    let currentPhase = "";
    for (const action of actions) {
      if (action.phase !== currentPhase) {
        currentPhase = action.phase;
        md += `### Phase: ${currentPhase}\n\n`;
      }

      const statusIcon = action.status === "success" ? "✅" : action.status === "failed" ? "❌" : "⚠️";
      md += `#### ${statusIcon} ${action.tool}\n`;
      md += `*${action.timestamp}*`;
      if (action.target) {
        md += ` | Target: \`${action.target}\``;
      }
      if (action.duration_ms) {
        md += ` | Duration: ${action.duration_ms}ms`;
      }
      md += "\n\n";

      if (action.input_params) {
        md += "**Input:**\n```json\n" + action.input_params + "\n```\n\n";
      }

      if (action.output) {
        // Truncate very long outputs
        const output = action.output.length > 2000
          ? action.output.substring(0, 2000) + "\n... (truncated)"
          : action.output;
        md += "**Output:**\n```\n" + output + "\n```\n\n";
      }

      if (action.notes) {
        md += `**Notes:** ${action.notes}\n\n`;
      }

      md += "---\n\n";
    }

    return md;
  }

  exportToJSON(engagementId: number): string {
    const engagement = this.getEngagement(engagementId);
    if (!engagement) {
      throw new Error("Engagement not found");
    }

    return JSON.stringify({
      engagement,
      actions: this.getActionsForEngagement(engagementId),
      findings: this.getFindingsForEngagement(engagementId),
      sessions: this.getSessionsForEngagement(engagementId),
    }, null, 2);
  }

  // Get summary stats
  getEngagementStats(engagementId: number): Record<string, unknown> {
    const actions = this.getActionsForEngagement(engagementId);
    const findings = this.getFindingsForEngagement(engagementId);
    const sessions = this.getSessionsForEngagement(engagementId);

    const phaseCount = new Map<string, number>();
    const toolCount = new Map<string, number>();
    let successCount = 0;
    let failedCount = 0;

    for (const action of actions) {
      phaseCount.set(action.phase, (phaseCount.get(action.phase) || 0) + 1);
      toolCount.set(action.tool, (toolCount.get(action.tool) || 0) + 1);
      if (action.status === "success") successCount++;
      if (action.status === "failed") failedCount++;
    }

    const findingsByType = new Map<string, number>();
    for (const finding of findings) {
      findingsByType.set(finding.type, (findingsByType.get(finding.type) || 0) + 1);
    }

    return {
      totalActions: actions.length,
      successfulActions: successCount,
      failedActions: failedCount,
      totalFindings: findings.length,
      findingsByType: Object.fromEntries(findingsByType),
      actionsByPhase: Object.fromEntries(phaseCount),
      actionsByTool: Object.fromEntries(toolCount),
      activeSessions: sessions.filter(s => s.status === "active").length,
      totalSessions: sessions.length,
    };
  }

  close(): void {
    this.db.close();
  }
}

// Singleton instance
let dbInstance: EngagementDB | null = null;

export function getEngagementDB(): EngagementDB {
  if (!dbInstance) {
    dbInstance = new EngagementDB();
  }
  return dbInstance;
}
