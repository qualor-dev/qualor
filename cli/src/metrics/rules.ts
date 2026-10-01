import type { Node } from 'web-tree-sitter';
import type { GrammarId } from '../parse/grammars';

export type SyntaxFamily =
  'ecmascript' | 'java' | 'csharp' | 'python' | 'markup' | 'stylesheet' | 'kotlin' | 'swift' | 'go';

/**
 * Node tables of ruling C3 (node type names of the pinned grammars, C1). No rule looks at
 * `node.parent`: in web-tree-sitter that walks down from the root, so it is O(depth) per call.
 */
export interface FamilyRules {
  /** Leaf node types that are comments. */
  comments: ReadonlySet<string>;
  /** Counted as functions (+1 complexity each); start a function context. */
  functions: ReadonlySet<string>;
  /** Start a function context without being counted (Java lambdas). */
  lambdas: ReadonlySet<string>;
  classes: ReadonlySet<string>;
  statements: ReadonlySet<string>;
  loops: ReadonlySet<string>;
  switches: ReadonlySet<string>;
  catchClause: string;
  ternary: string;
  /**
   * Purely syntactic wrappers (redundant grouping parentheses) that a run of like logical
   * operators sees through: `(a && b) && c` is one run, same as `a && b && c`. Any other node
   * standing between two same-operator logical expressions — a unary `!`, a call, an assignment —
   * still starts a new run, because it is not just grouping syntax.
   */
  transparent: ReadonlySet<string>;
  /** `case` labels; `default` is not a decision. */
  isCase(node: Node): boolean;
  /** The `if` that forms the `else if` branch of this `if`, or null. */
  elseIf(ifNode: Node): Node | null;
  /** The plain `else` branch of this `if` (not an `else if`), or null. */
  plainElse(ifNode: Node): Node | null;
  /** Extra check for statement types that are also expressions (Java `switch`). */
  isStatement?(node: Node, parentType: string): boolean;
  /**
   * Extra check for node types that are functions only in some shapes (C# accessors and
   * properties: only with a body, ruling D14 of plan 2D). Called for types in `functions`.
   */
  isFunction?(node: Node): boolean;
  /**
   * The operator of a node that is a logical expression counting as a decision, or null.
   * Default: a `binary_expression` whose operator is `&&` or `||`. Python: `and`/`or`.
   */
  logicalOperator?(node: Node): string | null;
  /**
   * A clause type that is an `else if` of its own (Python's `elif_clause`): +1 complexity and a
   * hybrid +1 cognitive increment without nesting, like an `else if` (plan 8C).
   */
  elseIfClause?: string;
  /** Nodes that count as comments though they are not comment leaves (Python docstrings). */
  isComment?(node: Node): boolean;
  /**
   * Node types whose whole text is one leaf for metrics and one token for duplication, because
   * the grammar hides part of their text from their children (tree-sitter-css `color_value`:
   * only `#` is a child of `#fff`; `integer_value`: only the unit of `1px`).
   */
  atoms?: ReadonlySet<string>;
  /**
   * Leaf types that span rows (HTML text and `<script>`/`<style>` bodies): only their rows with
   * non-blank text are code lines.
   */
  rowWiseLeaves?: ReadonlySet<string>;
  /** The node type of an `if` (default `if_statement`); Kotlin's `if` is an expression. */
  ifType?: string;
  /**
   * Zero-width MISSING nodes the grammar inserts where the source is fine (Kotlin: a class member
   * ending on the line of the body's `}`); a tree whose only problems are these is not reported
   * as a syntax error (cli/src/metrics/errors.ts).
   */
  benignMissing?: ReadonlySet<string>;
  /**
   * Statements that branch without an else chain (Swift's `guard`, plan 8F): like a loop, +1
   * complexity and +1 (plus nesting) cognitive complexity, and their body one level deeper.
   */
  branches?: ReadonlySet<string>;
  /**
   * Node types every named child of which is one statement, for a grammar whose expression
   * statements have no node of their own (Swift's `statements` wrapper, and a file's top level,
   * plan 8F). `isStatement` can still refuse a child (a declaration). Unlike `statements` (which
   * Kotlin uses with an enumerated list), a child counts before leaves are skipped, so a bare
   * literal or identifier (`get { 1 }`, a closure's `x`) is a statement too; and it needs no
   * list of expression types, which tree-sitter-swift has many of.
   */
  statementParents?: ReadonlySet<string>;
  /**
   * Extra check for node types in `classes` that are classes only in some shapes (Go's
   * `type_spec`: only a struct or interface type, plan 9C). Absent: every such node is a class.
   */
  isClass?(node: Node): boolean;
}

const ECMASCRIPT: FamilyRules = {
  comments: new Set(['comment', 'html_comment']),
  functions: new Set([
    'function_declaration',
    'generator_function_declaration',
    'function_expression',
    'generator_function',
    'arrow_function',
    'method_definition',
  ]),
  lambdas: new Set(),
  classes: new Set(['class_declaration', 'abstract_class_declaration', 'class']),
  statements: new Set([
    'expression_statement',
    'lexical_declaration',
    'variable_declaration',
    'if_statement',
    'for_statement',
    'for_in_statement',
    'while_statement',
    'do_statement',
    'return_statement',
    'break_statement',
    'continue_statement',
    'throw_statement',
    'try_statement',
    'switch_statement',
    'labeled_statement',
    'debugger_statement',
    'with_statement',
  ]),
  loops: new Set(['for_statement', 'for_in_statement', 'while_statement', 'do_statement']),
  switches: new Set(['switch_statement']),
  catchClause: 'catch_clause',
  ternary: 'ternary_expression',
  transparent: new Set(['parenthesized_expression']),
  isCase: (n) => n.type === 'switch_case',
  // `if (a) … else if (b) …` is if_statement > else_clause > if_statement.
  elseIf: (n) =>
    n.childForFieldName('alternative')?.namedChildren.find((c) => c?.type === 'if_statement') ??
    null,
  plainElse: (n) => {
    const alt = n.childForFieldName('alternative');
    if (alt === null) return null;
    return alt.namedChildren.some((c) => c?.type === 'if_statement') ? null : alt;
  },
};

const JAVA_STATEMENT_PARENTS = new Set([
  'block',
  'constructor_body',
  'switch_block_statement_group',
  'labeled_statement',
]);

const JAVA: FamilyRules = {
  comments: new Set(['line_comment', 'block_comment']),
  functions: new Set([
    'method_declaration',
    'constructor_declaration',
    'compact_constructor_declaration',
  ]),
  lambdas: new Set(['lambda_expression']),
  classes: new Set([
    'class_declaration',
    'interface_declaration',
    'enum_declaration',
    'record_declaration',
    'annotation_type_declaration',
  ]),
  statements: new Set([
    'expression_statement',
    'local_variable_declaration',
    'if_statement',
    'for_statement',
    'enhanced_for_statement',
    'while_statement',
    'do_statement',
    'return_statement',
    'break_statement',
    'continue_statement',
    'throw_statement',
    'try_statement',
    'try_with_resources_statement',
    'synchronized_statement',
    'assert_statement',
    'yield_statement',
    'labeled_statement',
    'switch_expression',
  ]),
  loops: new Set(['for_statement', 'enhanced_for_statement', 'while_statement', 'do_statement']),
  switches: new Set(['switch_expression']),
  catchClause: 'catch_clause',
  ternary: 'ternary_expression',
  transparent: new Set(['parenthesized_expression']),
  isCase: (n) => n.type === 'switch_label' && n.child(0)?.type === 'case',
  // Java has no else_clause: the alternative of an `if` is the `else if` itself.
  elseIf: (n) => {
    const alt = n.childForFieldName('alternative');
    return alt !== null && alt.type === 'if_statement' ? alt : null;
  },
  plainElse: (n) => {
    const alt = n.childForFieldName('alternative');
    return alt !== null && alt.type !== 'if_statement' ? alt : null;
  },
  isStatement: (n, parentType) =>
    n.type !== 'switch_expression' || JAVA_STATEMENT_PARENTS.has(parentType),
};

/** A C# accessor, property or indexer with its own body (`{ … }` or `=> …`), ruling D14. */
function hasCSharpBody(node: Node): boolean {
  if (node.type === 'accessor_declaration') {
    return node.children.some((c) => c?.type === 'block' || c?.type === 'arrow_expression_clause');
  }
  if (node.type === 'property_declaration' || node.type === 'indexer_declaration') {
    return node.children.some((c) => c?.type === 'arrow_expression_clause');
  }
  return true;
}

const CSHARP: FamilyRules = {
  comments: new Set(['comment']),
  functions: new Set([
    'method_declaration',
    'constructor_declaration',
    'destructor_declaration',
    'operator_declaration',
    'conversion_operator_declaration',
    'local_function_statement',
    'accessor_declaration',
    'property_declaration',
    'indexer_declaration',
  ]),
  lambdas: new Set(['lambda_expression', 'anonymous_method_expression']),
  classes: new Set([
    'class_declaration',
    'struct_declaration',
    'record_declaration',
    'interface_declaration',
    'enum_declaration',
  ]),
  statements: new Set([
    'expression_statement',
    'local_declaration_statement',
    'local_function_statement',
    'if_statement',
    'for_statement',
    'foreach_statement',
    'while_statement',
    'do_statement',
    'return_statement',
    'break_statement',
    'continue_statement',
    'throw_statement',
    'try_statement',
    'switch_statement',
    'using_statement',
    'lock_statement',
    'yield_statement',
    'goto_statement',
    'labeled_statement',
    'checked_statement',
    'fixed_statement',
    'unsafe_statement',
  ]),
  loops: new Set(['for_statement', 'foreach_statement', 'while_statement', 'do_statement']),
  switches: new Set(['switch_statement', 'switch_expression']),
  catchClause: 'catch_clause',
  ternary: 'conditional_expression',
  transparent: new Set(['parenthesized_expression']),
  // tree-sitter-c-sharp 0.23 gives each `case` label its own switch_section (probe of plan 2D).
  isCase: (n) =>
    (n.type === 'switch_section' && n.child(0)?.type === 'case') ||
    (n.type === 'switch_expression_arm' && n.child(0)?.type !== 'discard'),
  // Like Java: the alternative of an `if` is the `else if` itself, or a block.
  elseIf: (n) => {
    const alt = n.childForFieldName('alternative');
    return alt !== null && alt.type === 'if_statement' ? alt : null;
  },
  plainElse: (n) => {
    const alt = n.childForFieldName('alternative');
    return alt !== null && alt.type !== 'if_statement' ? alt : null;
  },
  isFunction: hasCSharpBody,
};

/** A statement that is a string alone: a docstring, or a bare string used as a comment (plan 8C). */
function isPythonStringStatement(node: Node): boolean {
  if (node.type !== 'expression_statement' || node.namedChildCount !== 1) return false;
  const only = node.namedChild(0)?.type;
  return only === 'string' || only === 'concatenated_string';
}

function pythonLogicalOperator(node: Node): string | null {
  if (node.type !== 'boolean_operator') return null;
  const op = node.childForFieldName('operator')?.type;
  return op === 'and' || op === 'or' ? op : null;
}

const PYTHON: FamilyRules = {
  comments: new Set(['comment']),
  // `def` and `async def` alike, methods and nested functions included.
  functions: new Set(['function_definition']),
  lambdas: new Set(['lambda']),
  classes: new Set(['class_definition']),
  statements: new Set([
    'expression_statement',
    'return_statement',
    'pass_statement',
    'if_statement',
    'for_statement',
    'while_statement',
    'try_statement',
    'with_statement',
    'raise_statement',
    'assert_statement',
    'import_statement',
    'import_from_statement',
    'future_import_statement',
    'global_statement',
    'nonlocal_statement',
    'delete_statement',
    'break_statement',
    'continue_statement',
    'match_statement',
    'type_alias_statement',
    'print_statement',
    'exec_statement',
  ]),
  loops: new Set(['for_statement', 'while_statement']),
  switches: new Set(['match_statement']),
  // `except*` parses as an except_clause too.
  catchClause: 'except_clause',
  ternary: 'conditional_expression',
  transparent: new Set(['parenthesized_expression']),
  // A bare `case _:` is the default arm, not a decision; a guarded `case _ if cond:` is one.
  isCase: (n) =>
    n.type === 'case_clause' &&
    (n.namedChild(0)?.text !== '_' || n.namedChildren.some((c) => c?.type === 'if_clause')),
  // Python's `elif` is its own clause (elseIfClause), never a nested if_statement.
  elseIf: () => null,
  // Only called for if_statement: a for/while/try `else` is not a branch of an if.
  plainElse: (n) => n.children.find((c) => c?.type === 'else_clause') ?? null,
  elseIfClause: 'elif_clause',
  isComment: isPythonStringStatement,
  logicalOperator: pythonLogicalOperator,
};

const NONE: ReadonlySet<string> = new Set();

/** Markup and style sheets (plan 8D): lines and comments only, no functions or decisions. */
function linesOnly(comments: string[], atoms: string[], rowWise: string[]): FamilyRules {
  return {
    comments: new Set(comments),
    functions: NONE,
    lambdas: NONE,
    classes: NONE,
    statements: NONE,
    loops: NONE,
    switches: NONE,
    catchClause: '',
    ternary: '',
    transparent: NONE,
    isCase: () => false,
    elseIf: () => null,
    plainElse: () => null,
    atoms: new Set(atoms),
    rowWiseLeaves: new Set(rowWise),
  };
}

const MARKUP = linesOnly(['comment'], ['doctype'], ['text', 'raw_text']);
const STYLESHEET = linesOnly(
  ['comment', 'js_comment'],
  ['color_value', 'integer_value', 'float_value'],
  [],
);

/** The node after the `else` keyword of a Kotlin if_expression (its alternative), or null. */
function kotlinElse(ifNode: Node): Node | null {
  let seenElse = false;
  for (const c of ifNode.children) {
    if (c === null) continue;
    if (seenElse && c.isNamed) return c;
    if (c.type === 'else') seenElse = true;
  }
  return null;
}

/**
 * The grammar's `statement` supertype (@tree-sitter-grammars/tree-sitter-kotlin 1.1.0
 * node-types.json) without the declarations it also holds (class, object, function, type alias):
 * a local function counts as a function, a local class as a class.
 */
const KOTLIN_STATEMENTS = new Set([
  'annotated_expression',
  'anonymous_function',
  'as_expression',
  'assignment',
  'binary_expression',
  'call_expression',
  'callable_reference',
  'character_literal',
  'collection_literal',
  'do_while_statement',
  'float_literal',
  'for_statement',
  'identifier',
  'if_expression',
  'in_expression',
  'index_expression',
  'infix_expression',
  'is_expression',
  'labeled_expression',
  'lambda_literal',
  'multiline_string_literal',
  'navigation_expression',
  'number_literal',
  'object_literal',
  'parenthesized_expression',
  'property_declaration',
  'range_expression',
  'return_expression',
  'spread_expression',
  'string_literal',
  'super_expression',
  'this_expression',
  'throw_expression',
  'try_expression',
  'unary_expression',
  'when_expression',
  'while_statement',
]);
/** Kotlin has no statement node: a statement is an entry of a block or a lambda body. */
const KOTLIN_STATEMENT_PARENTS = new Set(['block', 'lambda_literal']);

const KOTLIN: FamilyRules = {
  comments: new Set(['line_comment', 'block_comment']),
  functions: new Set(['function_declaration', 'secondary_constructor', 'getter', 'setter']),
  lambdas: new Set(['lambda_literal', 'anonymous_function']),
  classes: new Set(['class_declaration', 'object_declaration', 'companion_object']),
  statements: KOTLIN_STATEMENTS,
  loops: new Set(['for_statement', 'while_statement', 'do_while_statement']),
  switches: new Set(['when_expression']),
  catchClause: 'catch_block',
  // Kotlin has no conditional operator (`if` is an expression and counts as an if), and
  // tree-sitter never produces a node of type ''.
  ternary: '',
  ifType: 'if_expression',
  transparent: new Set(['parenthesized_expression']),
  isCase: (n) => n.type === 'when_entry' && n.child(0)?.type !== 'else',
  elseIf: (n) => {
    const alt = kotlinElse(n);
    return alt !== null && alt.type === 'if_expression' ? alt : null;
  },
  plainElse: (n) => {
    const alt = kotlinElse(n);
    return alt !== null && alt.type !== 'if_expression' ? alt : null;
  },
  // A script's (.kts) top-level calls are statements; a top-level property is a declaration.
  isStatement: (n, parentType) =>
    KOTLIN_STATEMENT_PARENTS.has(parentType) ||
    (parentType === 'source_file' && n.type !== 'property_declaration'),
  // A getter or setter is a function only with a body (`get() = …` or `get() { … }`).
  isFunction: (n) =>
    (n.type !== 'getter' && n.type !== 'setter') ||
    n.children.some((c) => c?.type === 'function_body'),
  benignMissing: new Set(['_class_member_semi']),
};

/** Swift declarations: never statements (JavaScript, Java and C# count none of theirs either). */
const SWIFT_DECLARATIONS = new Set([
  'import_declaration',
  'class_declaration',
  'protocol_declaration',
  'function_declaration',
  'init_declaration',
  'deinit_declaration',
  'subscript_declaration',
  'typealias_declaration',
  'operator_declaration',
  'precedence_group_declaration',
  'associatedtype_declaration',
]);

/** The node right after an `if`'s `else` keyword: the `else if` statement, or the else block's `{`. */
function swiftElse(ifNode: Node): Node | null {
  for (let i = 0; i < ifNode.childCount; i++) {
    if (ifNode.child(i)?.type === 'else') return ifNode.child(i + 1);
  }
  return null;
}

/** tree-sitter-swift 0.7.3 (plan 8F, probe F7). */
const SWIFT: FamilyRules = {
  comments: new Set(['comment', 'multiline_comment']),
  functions: new Set([
    'function_declaration',
    'init_declaration',
    'deinit_declaration',
    'computed_getter',
    'computed_setter',
    'willset_clause',
    'didset_clause',
    // Only a shorthand getter (`var x: Int { … }`, `subscript … { … }`): see isFunction.
    'computed_property',
  ]),
  lambdas: new Set(['lambda_literal']),
  // class_declaration is also struct, enum, actor and extension.
  classes: new Set(['class_declaration', 'protocol_declaration']),
  // Counted through statementParents instead (expression statements have no node type).
  statements: new Set(),
  loops: new Set(['for_statement', 'while_statement', 'repeat_while_statement']),
  switches: new Set(['switch_statement']),
  catchClause: 'catch_block',
  ternary: 'ternary_expression',
  // `(a && b)` is a one-element tuple_expression.
  transparent: new Set(['tuple_expression']),
  isCase: (n) =>
    n.type === 'switch_entry' && !n.children.some((c) => c?.type === 'default_keyword'),
  elseIf: (n) => {
    const next = swiftElse(n);
    return next !== null && next.type === 'if_statement' ? next : null;
  },
  // An empty `else { }` has no statements node: the `{` token after `else` is the branch.
  plainElse: (n) => {
    const next = swiftElse(n);
    return next !== null && next.type !== 'if_statement' ? next : null;
  },
  isStatement: (n) => !SWIFT_DECLARATIONS.has(n.type),
  // A computed_property is a function only when it is a shorthand getter (it holds the body's
  // `statements` directly); with get/set, the accessors count instead.
  isFunction: (n) =>
    n.type !== 'computed_property' || n.children.some((c) => c?.type === 'statements'),
  logicalOperator: (n) =>
    n.type === 'conjunction_expression' ? '&&' : n.type === 'disjunction_expression' ? '||' : null,
  branches: new Set(['guard_statement']),
  statementParents: new Set(['statements', 'source_file']),
};

/** tree-sitter-go 0.25.0 (plan 9C, probe G10). */
const GO: FamilyRules = {
  comments: new Set(['comment']),
  functions: new Set(['function_declaration', 'method_declaration']),
  lambdas: new Set(['func_literal']),
  // Only a named struct or interface type (`type T struct { … }`): see isClass.
  classes: new Set(['type_spec']),
  // Counted through statementParents: every item of a statement list is one statement.
  statements: new Set(),
  loops: new Set(['for_statement']),
  switches: new Set(['expression_switch_statement', 'type_switch_statement', 'select_statement']),
  // Go has neither try/catch nor ?:.
  catchClause: '',
  ternary: '',
  transparent: new Set(['parenthesized_expression']),
  // default_case is not a decision.
  isCase: (n) =>
    n.type === 'expression_case' || n.type === 'type_case' || n.type === 'communication_case',
  elseIf: (n) => {
    const alt = n.childForFieldName('alternative');
    return alt !== null && alt.type === 'if_statement' ? alt : null;
  },
  plainElse: (n) => {
    const alt = n.childForFieldName('alternative');
    return alt !== null && alt.type !== 'if_statement' ? alt : null;
  },
  isClass: (n) => {
    const t = n.childForFieldName('type')?.type;
    return t === 'struct_type' || t === 'interface_type';
  },
  statementParents: new Set(['statement_list']),
};

export const FAMILY_RULES: Readonly<Record<SyntaxFamily, FamilyRules>> = {
  ecmascript: ECMASCRIPT,
  java: JAVA,
  csharp: CSHARP,
  python: PYTHON,
  markup: MARKUP,
  stylesheet: STYLESHEET,
  kotlin: KOTLIN,
  swift: SWIFT,
  go: GO,
};

export function familyOf(grammar: GrammarId): SyntaxFamily {
  if (grammar === 'java') return 'java';
  if (grammar === 'csharp') return 'csharp';
  if (grammar === 'python') return 'python';
  if (grammar === 'html') return 'markup';
  if (grammar === 'css') return 'stylesheet';
  if (grammar === 'kotlin') return 'kotlin';
  if (grammar === 'swift') return 'swift';
  if (grammar === 'go') return 'go';
  return 'ecmascript';
}
