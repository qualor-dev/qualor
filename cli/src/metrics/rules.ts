import type { Node } from 'web-tree-sitter';
import type { GrammarId } from '../parse/grammars';

export type SyntaxFamily = 'ecmascript' | 'java' | 'csharp';

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

export const FAMILY_RULES: Readonly<Record<SyntaxFamily, FamilyRules>> = {
  ecmascript: ECMASCRIPT,
  java: JAVA,
  csharp: CSHARP,
};

export function familyOf(grammar: GrammarId): SyntaxFamily {
  if (grammar === 'java') return 'java';
  if (grammar === 'csharp') return 'csharp';
  return 'ecmascript';
}
