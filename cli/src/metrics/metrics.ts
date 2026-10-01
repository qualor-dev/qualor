import type { Node } from 'web-tree-sitter';
import { FAMILY_RULES, type SyntaxFamily } from './rules';

/** report-format §6 `files[].metrics`. */
export interface FileMetrics {
  ncloc: number;
  commentLines: number;
  functions: number;
  classes: number;
  statements: number;
  complexity: number;
  cognitiveComplexity: number;
}

interface Frame {
  node: Node;
  /** Cognitive nesting level applied to this node's own increment. */
  nesting: number;
  /** Inside a function or lambda body. */
  inFunction: boolean;
  parentType: string;
  /** The parent's logical operator (`&&`/`||`) when the parent is a logical expression. */
  parentOperator: string | null;
}

function logicalOperator(node: Node): string | null {
  if (node.type !== 'binary_expression') return null;
  const op = node.childForFieldName('operator')?.type;
  return op === '&&' || op === '||' ? op : null;
}

/**
 * Size and complexity of one parsed file (ruling C3). The walk is iterative and carries parent
 * facts in its frames, so very deep trees (long operator chains, minified code) cost O(nodes)
 * and cannot overflow the stack.
 */
export function computeMetrics(root: Node, family: SyntaxFamily): FileMetrics {
  const rules = FAMILY_RULES[family];
  const codeLines = new Set<number>();
  const commentLines = new Set<number>();
  const elseIfs = new Set<number>();
  const statementChildren = new Set<number>(); // statementChild (plan 9B)
  let functions = 0;
  let classes = 0;
  let statements = 0;
  let complexity = 0;
  let cognitive = 0;

  const stack: Frame[] = [
    { node: root, nesting: 0, inFunction: false, parentType: '', parentOperator: null },
  ];
  for (let frame = stack.pop(); frame !== undefined; frame = stack.pop()) {
    const { node, nesting, inFunction } = frame;
    const type = node.type;
    // Ruby's `__END__` data (plan 9B): neither code nor comment.
    if (rules.skipped?.has(type) === true) continue;

    if (rules.comments.has(type) || rules.isComment?.(node) === true) {
      for (let r = node.startPosition.row; r <= node.endPosition.row; r++) commentLines.add(r + 1);
      continue;
    }
    // Swift (plan 8F): every named child of a `statements` wrapper, or of the file itself, is one
    // statement, a bare expression or literal included, so this runs before leaves are skipped.
    if (
      statementChildren.has(node.id) ||
      (rules.statementParents?.has(frame.parentType) === true &&
        node.isNamed &&
        (rules.isStatement?.(node, frame.parentType) ?? true))
    ) {
      statements++;
    }
    const count = node.childCount;
    if (count === 0 || rules.atoms?.has(type) === true) {
      // Zero-width leaves are tokens inserted by error recovery; whitespace-only leaves (JSX text) are not code.
      if (node.endIndex > node.startIndex && node.text.trim() !== '') {
        if (rules.rowWiseLeaves?.has(type) === true) {
          node.text.split('\n').forEach((row, i) => {
            if (row.trim() !== '') codeLines.add(node.startPosition.row + i + 1);
          });
        } else {
          for (let r = node.startPosition.row; r <= node.endPosition.row; r++) codeLines.add(r + 1);
        }
      }
      continue;
    }

    let childNesting = nesting;
    let childInFunction = inFunction;
    let operator: string | null = null;
    const isFunction = rules.functions.has(type) && (rules.isFunction?.(node) ?? true);
    if (isFunction || rules.lambdas.has(type)) {
      if (isFunction) {
        functions++;
        complexity++;
      }
      // Top-level functions and methods start at nesting 0; nested functions and lambdas add one.
      childNesting = inFunction ? nesting + 1 : 0;
      childInFunction = true;
    }
    if (rules.classes.has(type) && (rules.isClass?.(node) ?? true)) classes++;
    const own = rules.statementChild?.(node) ?? null;
    if (own !== null) statementChildren.add(own.id);
    if (rules.statements.has(type) && (rules.isStatement?.(node, frame.parentType) ?? true)) {
      statements++;
    }

    if (type === (rules.ifType ?? 'if_statement')) {
      complexity++;
      if (elseIfs.has(node.id)) {
        cognitive += 1; // hybrid increment: no nesting penalty and no extra nesting level
      } else {
        cognitive += 1 + nesting;
        childNesting = nesting + 1;
      }
      const elseIf = rules.elseIf(node);
      if (elseIf !== null) elseIfs.add(elseIf.id);
      if (rules.plainElse(node) !== null) cognitive += 1;
    } else if (type === rules.elseIfClause) {
      // Python's `elif` (plan 8C): a decision, and a hybrid increment like an `else if`.
      complexity++;
      cognitive += 1;
    } else if (
      rules.loops.has(type) ||
      rules.branches?.has(type) === true ||
      type === rules.catchClause ||
      type === rules.ternary
    ) {
      complexity++;
      cognitive += 1 + nesting;
      childNesting = nesting + 1;
    } else if (rules.switches.has(type)) {
      cognitive += 1 + nesting;
      childNesting = nesting + 1;
    } else if (rules.isCase(node)) {
      complexity++;
    } else if (rules.transparent.has(type)) {
      // Redundant grouping parentheses are not a decision point and do not start a new run of
      // logical operators (ruling C3 extension): pass the enclosing operator through unchanged.
      operator = frame.parentOperator;
    } else {
      operator = (rules.logicalOperator ?? logicalOperator)(node);
      if (operator !== null) {
        complexity++;
        if (frame.parentOperator !== operator) cognitive += 1; // a new run of like operators
      }
    }

    for (let i = count - 1; i >= 0; i--) {
      const child = node.child(i);
      if (child !== null) {
        stack.push({
          node: child,
          nesting: childNesting,
          inFunction: childInFunction,
          parentType: type,
          parentOperator: operator,
        });
      }
    }
  }

  return {
    ncloc: codeLines.size,
    commentLines: commentLines.size,
    functions,
    classes,
    statements,
    complexity,
    cognitiveComplexity: cognitive,
  };
}
