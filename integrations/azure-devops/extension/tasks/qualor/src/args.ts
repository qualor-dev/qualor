import { ToolRunner } from 'azure-pipelines-task-lib/toolrunner';

const PARSER_GONE = 'azure-pipelines-task-lib no longer has the argument parser of ToolRunner.line';

/**
 * One line split as task-lib splits a command line (`ToolRunner.line`: spaces separate, double
 * quotes group). The parser is private and uses no instance state; an instance cannot be used,
 * since its constructor needs the tool to exist on the agent.
 */
function splitLine(line: string): string[] {
  const parse = (ToolRunner.prototype as unknown as { _argStringToArray?: unknown })
    ._argStringToArray;
  const args: unknown =
    typeof parse === 'function' ? parse.call(ToolRunner.prototype, line) : undefined;
  if (!Array.isArray(args) || !args.every((a) => typeof a === 'string')) {
    throw new Error(PARSER_GONE);
  }
  return args;
}

/**
 * The task's `arguments` input as an argument list: one line, or a YAML block
 * (`arguments: |`) with one or more arguments per line. Each line is split on its own, so a
 * quote never spans lines.
 */
export function splitArguments(input: string): string[] {
  return input.split(/\r?\n/).flatMap(splitLine);
}
