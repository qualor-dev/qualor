import type { Node } from 'web-tree-sitter';

/** `(MISSING name)` or `(MISSING "token")` in a node's S-expression. */
const MISSING_IN_SEXP = /\(MISSING ("(?:[^"\\]|\\.)*"|[^\s()]+)/g;

/**
 * True when the S-expression of `node` names an ERROR, or a MISSING node that is not benign.
 * web-tree-sitter hides nodes of hidden grammar symbols (`_class_member_semi`) from `children`,
 * `child()` and tree cursors, even when they are MISSING; only the S-expression shows them.
 */
function sexpHasRealError(node: Node, benignMissing?: ReadonlySet<string>): boolean {
  const sexp = node.toString();
  if (sexp.includes('(ERROR') || sexp.includes('(UNEXPECTED')) return true;
  for (const m of sexp.matchAll(MISSING_IN_SEXP)) {
    const name = m[1] ?? '';
    const type = name.startsWith('"') ? name.slice(1, -1) : name;
    if (benignMissing?.has(type) !== true) return true;
  }
  return false;
}

/**
 * True when the tree has a syntax error other than a zero-width MISSING node the family lists as
 * benign (FamilyRules.benignMissing). Walks only the subtrees that report an error, so a clean
 * file costs nothing and an iterative walk cannot overflow the stack. A node that reports an
 * error none of its visible children holds has it in a hidden child: its S-expression decides.
 */
export function hasRealParseErrors(root: Node, benignMissing?: ReadonlySet<string>): boolean {
  if (!root.hasError) return false;
  const stack: Node[] = [root];
  for (let node = stack.pop(); node !== undefined; node = stack.pop()) {
    if (node.isError) return true;
    if (node.isMissing) {
      if (benignMissing?.has(node.type) !== true) return true;
      continue;
    }
    const visible = pushErrorChildren(node, stack);
    if (!visible && sexpHasRealError(node, benignMissing)) return true;
  }
  return false;
}

/** Pushes the visible children of `node` that report an error; true when there was one. */
function pushErrorChildren(node: Node, stack: Node[]): boolean {
  let visible = false;
  for (const child of node.children) {
    if (child !== null && (child.hasError || child.isMissing)) {
      stack.push(child);
      visible = true;
    }
  }
  return visible;
}
