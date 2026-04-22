import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { VERSION } from './version.js';
import { EVALUATE_TOOL, runEvaluateTool, EvaluateArgs } from './tools/evaluate.js';
import {
  DESCRIBE_ARTIFACT_TOOL,
  runDescribeArtifactTool,
  DescribeArgs,
} from './tools/describe-artifact.js';
import {
  LIST_RULES_TOOL,
  runListRulesTool,
  ListRulesArgs,
} from './tools/list-rules.js';

export interface ServerOptions {
  defaultArtifact: string;
}

export async function startServer(opts: ServerOptions): Promise<void> {
  const server = new Server(
    { name: 'logicpearl', version: VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [EVALUATE_TOOL, DESCRIBE_ARTIFACT_TOOL, LIST_RULES_TOOL],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args = {} } = req.params;
    try {
      let result: unknown;
      if (name === EVALUATE_TOOL.name) {
        result = await runEvaluateTool(args as unknown as EvaluateArgs, opts.defaultArtifact);
      } else if (name === DESCRIBE_ARTIFACT_TOOL.name) {
        result = await runDescribeArtifactTool(args as unknown as DescribeArgs, opts.defaultArtifact);
      } else if (name === LIST_RULES_TOOL.name) {
        result = await runListRulesTool(args as unknown as ListRulesArgs, opts.defaultArtifact);
      } else {
        return {
          isError: true,
          content: [{ type: 'text', text: `Unknown tool: ${name}` }],
        };
      }
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    } catch (err) {
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: `Error calling ${name}: ${(err as Error).message}`,
          },
        ],
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
