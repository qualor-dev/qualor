import type { Node } from 'web-tree-sitter';
import { FAMILY_RULES, type FamilyRules, type SyntaxFamily } from './rules';

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

/** What the walk accumulates. */
interface Tally {
  codeLines: Set<number>;
  commentLines: Set<number>;
  elseIfs: Set<number>;
  /** statementChild (plan 9B). */
  statementChildren: Set<number>;
  functions: number;
  classes: number;
  statements: number;
  complexity: number;
  cognitive: number;
}

/** What a node passes on to its children besides its type. */
interface ChildContext {
  nesting: number;
  inFunction: boolean;
  operator: string | null;
}

/** Adds the 1-based rows a node spans. */
function addRows(lines: Set<number>, node: Node): void {
  for (let r = node.startPosition.row; r <= node.endPosition.row; r++) lines.add(r + 1);
}

/** A leaf's code lines. */
function countLeaf(rules: FamilyRules, codeLines: Set<number>, node: Node): void {
  // Zero-width leaves are tokens inserted by error recovery; whitespace-only leaves (JSX text) are not code.
  if (node.endIndex <= node.startIndex || node.text.trim() === '') return;
  if (rules.rowWiseLeaves?.has(node.type) === true) {
    node.text.split('\n').forEach((row, i) => {
      if (row.trim() !== '') codeLines.add(node.startPosition.row + i + 1);
    });
  } else {
    addRows(codeLines, node);
  }
}

/**
 * Swift (plan 8F): every named child of a `statements` wrapper, or of the file itself, is one
 * statement, a bare expression or literal included, so this runs before leaves are skipped.
 */
function isStatementChild(
  rules: FamilyRules,
  statementChildren: Set<number>,
  frame: Frame,
): boolean {
  const { node, parentType } = frame;
  if (statementChildren.has(node.id)) return true;
  return (
    rules.statementParents?.has(parentType) === true &&
    node.isNamed &&
    (rules.isStatement?.(node, parentType) ?? true)
  );
}

/** Counts a function; a function or lambda body changes the nesting of its children. */
function enterFunction(
  rules: FamilyRules,
  t: Tally,
  frame: Frame,
  type: string,
): Pick<ChildContext, 'nesting' | 'inFunction'> {
  const { node, nesting, inFunction } = frame;
  const isFunction = rules.functions.has(type) && (rules.isFunction?.(node) ?? true);
  if (!isFunction && !rules.lambdas.has(type)) return { nesting, inFunction };
  if (isFunction) {
    t.functions++;
    t.complexity++;
  }
  // Top-level functions and methods start at nesting 0; nested functions and lambdas add one.
  return { nesting: inFunction ? nesting + 1 : 0, inFunction: true };
}

/** Classes, the child a node makes a statement (plan 9B), and statements by node type. */
function countDeclarations(rules: FamilyRules, t: Tally, frame: Frame, type: string): void {
  const { node, parentType } = frame;
  if (rules.classes.has(type) && (rules.isClass?.(node) ?? true)) t.classes++;
  const own = rules.statementChild?.(node) ?? null;
  if (own !== null) t.statementChildren.add(own.id);
  if (rules.statements.has(type) && (rules.isStatement?.(node, parentType) ?? true)) {
    t.statements++;
  }
}

/** An `if`: its children's nesting (`childNesting` for an `else if`). */
function countIf(rules: FamilyRules, t: Tally, frame: Frame, childNesting: number): number {
  const { node, nesting } = frame;
  let next = childNesting;
  t.complexity++;
  if (t.elseIfs.has(node.id)) {
    t.cognitive += 1; // hybrid increment: no nesting penalty and no extra nesting level
  } else {
    t.cognitive += 1 + nesting;
    next = nesting + 1;
  }
  const elseIf = rules.elseIf(node);
  if (elseIf !== null) t.elseIfs.add(elseIf.id);
  if (rules.plainElse(node) !== null) t.cognitive += 1;
  return next;
}

/**
 * The node's decision increments: its children's nesting (`childNesting` unless it is a nesting
 * structure) and the run of logical operators they continue.
 */
function countDecision(
  rules: FamilyRules,
  t: Tally,
  frame: Frame,
  type: string,
  childNesting: number,
): Pick<ChildContext, 'nesting' | 'operator'> {
  const { node, nesting } = frame;
  if (type === (rules.ifType ?? 'if_statement')) {
    return { nesting: countIf(rules, t, frame, childNesting), operator: null };
  }
  if (type === rules.elseIfClause) {
    // Python's `elif` (plan 8C): a decision, and a hybrid increment like an `else if`.
    t.complexity++;
    t.cognitive += 1;
    return { nesting: childNesting, operator: null };
  }
  if (
    rules.loops.has(type) ||
    rules.branches?.has(type) === true ||
    type === rules.catchClause ||
    type === rules.ternary
  ) {
    t.complexity++;
    t.cognitive += 1 + nesting;
    return { nesting: nesting + 1, operator: null };
  }
  if (rules.switches.has(type)) {
    t.cognitive += 1 + nesting;
    return { nesting: nesting + 1, operator: null };
  }
  if (rules.isCase(node)) {
    t.complexity++;
    return { nesting: childNesting, operator: null };
  }
  if (rules.transparent.has(type)) {
    // Redundant grouping parentheses are not a decision point and do not start a new run of
    // logical operators (ruling C3 extension): pass the enclosing operator through unchanged.
    return { nesting: childNesting, operator: frame.parentOperator };
  }
  const operator = (rules.logicalOperator ?? logicalOperator)(node);
  if (operator !== null) {
    t.complexity++;
    if (frame.parentOperator !== operator) t.cognitive += 1; // a new run of like operators
  }
  return { nesting: childNesting, operator };
}

/** Counts one node of the walk and pushes its children. */
function visit(rules: FamilyRules, t: Tally, frame: Frame, stack: Frame[]): void {
  const { node } = frame;
  const type = node.type;
  // Ruby's `__END__` data (plan 9B): neither code nor comment.
  if (rules.skipped?.has(type) === true) return;

  if (rules.comments.has(type) || rules.isComment?.(node) === true) {
    addRows(t.commentLines, node);
    return;
  }
  if (isStatementChild(rules, t.statementChildren, frame)) t.statements++;
  const count = node.childCount;
  if (count === 0 || rules.atoms?.has(type) === true) {
    countLeaf(rules, t.codeLines, node);
    return;
  }

  const scope = enterFunction(rules, t, frame, type);
  countDeclarations(rules, t, frame, type);
  const decision = countDecision(rules, t, frame, type, scope.nesting);

  for (let i = count - 1; i >= 0; i--) {
    const child = node.child(i);
    if (child !== null) {
      stack.push({
        node: child,
        nesting: decision.nesting,
        inFunction: scope.inFunction,
        parentType: type,
        parentOperator: decision.operator,
      });
    }
  }
}

/**
 * Size and complexity of one parsed file (ruling C3). The walk is iterative and carries parent
 * facts in its frames, so very deep trees (long operator chains, minified code) cost O(nodes)
 * and cannot overflow the stack.
 */
export function computeMetrics(root: Node, family: SyntaxFamily): FileMetrics {
  const rules = FAMILY_RULES[family];
  const t: Tally = {
    codeLines: new Set<number>(),
    commentLines: new Set<number>(),
    elseIfs: new Set<number>(),
    statementChildren: new Set<number>(),
    functions: 0,
    classes: 0,
    statements: 0,
    complexity: 0,
    cognitive: 0,
  };

  const stack: Frame[] = [
    { node: root, nesting: 0, inFunction: false, parentType: '', parentOperator: null },
  ];
  for (let frame = stack.pop(); frame !== undefined; frame = stack.pop()) {
    visit(rules, t, frame, stack);
  }

  return {
    ncloc: t.codeLines.size,
    commentLines: t.commentLines.size,
    functions: t.functions,
    classes: t.classes,
    statements: t.statements,
    complexity: t.complexity,
    cognitiveComplexity: t.cognitive,
  };
}
