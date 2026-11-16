import type { McpTool } from '../tool';
import { explainTool, suggestFixTool } from './ai';
import { gateStatusTool } from './gate-status';
import { issueTool } from './issue';
import { issuesTool } from './issues';
import { measuresTool } from './measures';
import { packageUsagesTool } from './package-usages';
import { projectsTool } from './projects';
import { ruleTool } from './rule';
import { transitionTool } from './transition';

/** Every tool `/mcp` serves (spec §5); Task 13 appends its own. */
export const MCP_TOOLS: readonly McpTool[] = [
  projectsTool,
  gateStatusTool,
  issuesTool,
  issueTool,
  ruleTool,
  measuresTool,
  explainTool,
  suggestFixTool,
  transitionTool,
  packageUsagesTool,
] as readonly McpTool[];
