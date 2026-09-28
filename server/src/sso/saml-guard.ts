// @ts-expect-error -- the untyped entry on purpose: xmldom's index.d.ts pulls lib "dom" into the program (see below).
import xmldom from '@xmldom/xmldom/lib/index.js';

/**
 * The part of the DOM (xmldom 0.8) the pre-check and its callers read. xmldom's own typings start
 * with `/// <reference lib="dom" />`, which would pull the browser's DOM library into the whole
 * server program (its `fetch` and `RequestInit` replace Node's), so the module is imported through
 * its untyped entry file and typed by these interfaces instead. It is the same code, and it stays
 * an external runtime dependency of the bundle (esbuild keeps a dependency's subpaths external).
 */
export interface XmlNode {
  readonly nodeType: number;
  readonly nodeName: string;
  readonly nodeValue: string | null;
  readonly parentNode: XmlNode | null;
  readonly firstChild: XmlNode | null;
  readonly nextSibling: XmlNode | null;
  readonly textContent: string | null;
}
export interface XmlAttr {
  readonly name: string;
  readonly localName: string;
  readonly prefix: string | null;
  readonly namespaceURI: string | null;
  readonly value: string;
}
interface XmlList<T> {
  readonly length: number;
  item(index: number): T | null;
}
export interface XmlElement extends XmlNode {
  readonly localName: string;
  readonly prefix: string | null;
  readonly namespaceURI: string | null;
  readonly attributes: XmlList<XmlAttr>;
  getAttribute(name: string): string | null;
  getAttributeNS(namespace: string | null, localName: string): string | null;
  getElementsByTagNameNS(namespace: string, localName: string): XmlList<XmlElement>;
}
export interface XmlDocument extends XmlNode {
  readonly documentElement: XmlElement | null;
  getElementsByTagNameNS(namespace: string, localName: string): XmlList<XmlElement>;
}
type ErrorCallback = (message: unknown) => never;
interface XmlDom {
  DOMParser: new (options: {
    locator: object;
    errorHandler: { warning: ErrorCallback; error: ErrorCallback; fatalError: ErrorCallback };
  }) => { parseFromString(xml: string, mimeType: string): XmlDocument };
}
const { DOMParser } = xmldom as XmlDom;

/**
 * The SAML pre-check (sso-scim.md §6.2): every SAML document (a response at the ACS, an IdP's
 * metadata) passes here before node-saml, xml-crypto or anything else parses it. The raw-text
 * checks run first, so no parser ever sees a DOCTYPE, a processing instruction, a comment or a
 * CDATA section; then xmldom parses with handlers that throw on any warning or error; then a walk
 * of the tree checks the shape. Every rule is by namespace URI and local name, never by prefix,
 * so `saml:`, `saml2:`, no prefix and rebound prefixes are all seen for what they are. The codes
 * are fixed strings, safe to log; nothing of the document is ever returned in an error.
 */

export const SAML_MAX_BYTES = 262_144;
export const SAML_METADATA_MAX_BYTES = 1_048_576;
const P = 'urn:oasis:names:tc:SAML:2.0:protocol';
const A = 'urn:oasis:names:tc:SAML:2.0:assertion';
const MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const DS = 'http://www.w3.org/2000/09/xmldsig#';
const MAX_DEPTH = 32;
const MAX_ELEMENTS = 5_000;
const MAX_ATTRIBUTE = 65_536;
/**
 * Raw bounds checked before xmldom runs. Its namespace scopes cost time per level and per
 * declaration, so depth (MAX_DEPTH), start tags and attributes per element are bounded from the
 * tag stream. The number of `xmlns` declarations is not: Keycloak, Okta and Google declare
 * `xmlns:xs` and `xmlns:xsi` on every AttributeValue, once per group.
 */
const MAX_ATTRIBUTES_PER_ELEMENT = 64;
const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const SIGNATURE_METHODS = new Set([
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512',
]);
const DIGEST_METHODS = new Set([
  'http://www.w3.org/2001/04/xmlenc#sha256',
  'http://www.w3.org/2001/04/xmlenc#sha512',
]);
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
/** xml-crypto resolves a Reference URI against any of these attribute names (by local name). */
const ID_NAMES = new Set(['ID', 'Id', 'id']);
/**
 * Where each element that xml-crypto's `loadSignature` looks up by local name (in any namespace,
 * first match in document order) must sit inside a Signature: in the xmldsig namespace, under
 * this xmldsig parent. Anywhere else inside a Signature it is refused, so no hidden
 * `<x:SignatureMethod>` can pick the algorithm xml-crypto uses.
 */
const SIGNATURE_PLACES: Record<string, string> = {
  SignedInfo: 'Signature',
  SignatureValue: 'Signature',
  KeyInfo: 'Signature',
  CanonicalizationMethod: 'SignedInfo',
  SignatureMethod: 'SignedInfo',
  Reference: 'SignedInfo',
  Transforms: 'Reference',
  DigestMethod: 'Reference',
  DigestValue: 'Reference',
  Transform: 'Transforms',
};
/** xmldsig elements that may appear only in their place, inside a Signature or not, keyed to their parent. */
const DS_PARENT: Record<string, string> = {
  SignedInfo: 'Signature',
  SignatureValue: 'Signature',
  SignatureMethod: 'SignedInfo',
  Reference: 'SignedInfo',
};

export type PreCheckCode =
  | 'base64'
  | 'too_large'
  | 'doctype'
  | 'processing_instruction'
  | 'comment'
  | 'cdata'
  | 'malformed'
  | 'not_response'
  | 'too_complex'
  | 'assertion_count'
  | 'encrypted_without_key'
  | 'signature_shape'
  | 'forbidden_name'
  | 'duplicate_id'
  | 'idp_status';
type Fail = { ok: false; code: PreCheckCode };
const fail = (code: PreCheckCode): Fail => ({ ok: false, code });

/** Standard alphabet, canonical padding, nothing else (whitespace is removed first). */
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MAX_BASE64 = 4 * Math.ceil(SAML_MAX_BYTES / 3);

export function decodeSamlResponse(
  b64: string,
): { ok: true; xml: string } | { ok: false; code: 'base64' | 'too_large' } {
  const compact = b64.replace(/[\t\n\r ]/g, '');
  if (compact.length > MAX_BASE64) return { ok: false, code: 'too_large' };
  if (compact === '' || !BASE64.test(compact)) return { ok: false, code: 'base64' };
  const bytes = Buffer.from(compact, 'base64');
  // Non-zero bits in the last character's unused part decode silently; refuse them.
  if (bytes.toString('base64') !== compact) return { ok: false, code: 'base64' };
  if (bytes.length > SAML_MAX_BYTES) return { ok: false, code: 'too_large' };
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)
    return { ok: false, code: 'base64' };
  try {
    return {
      ok: true,
      xml: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes),
    };
  } catch {
    return { ok: false, code: 'base64' };
  }
}

/** A leading XML declaration: version 1.0, UTF-8 if an encoding is named, standalone yes or no. */
const DECLARATION = /^<\?xml(\s[^<>?]*)\?>/;
const DECLARATION_BODY =
  /^\s+version\s*=\s*(["'])1\.0\1(?:\s+encoding\s*=\s*(["'])([A-Za-z][A-Za-z0-9._-]*)\2)?(?:\s+standalone\s*=\s*(["'])(?:yes|no)\4)?\s*$/;

/** Comments, removed from the text the raw bounds scan when a metadata document may hold them. */
const COMMENTS = /<!--[\s\S]*?-->/g;

/**
 * The checks on the raw text, before any parser; `declared` says whether a declaration leads.
 * `allowComments` (IdP metadata only: unsigned, reviewed by an admin, and Shibboleth writes
 * comments) lets comments through; everything else is as strict as for a response.
 */
function rawCheck(
  xml: string,
  maxBytes: number,
  allowComments = false,
): PreCheckCode | { declared: boolean } {
  // UTF-8 never takes fewer bytes than UTF-16 code units, so the length is a cheap first bound.
  if (xml.length > maxBytes || Buffer.byteLength(xml, 'utf8') > maxBytes) return 'too_complex';
  // `<` is never allowed raw in text or in an attribute value, so any `<!` is markup: a DOCTYPE,
  // ENTITY, ELEMENT, ATTLIST or NOTATION declaration (any case, any spacing), a comment or CDATA.
  if (/<!(?!--|\[CDATA\[)/.test(xml)) return 'doctype';
  if (!allowComments && xml.includes('<!--')) return 'comment';
  if (xml.includes('<![CDATA[')) return 'cdata';
  if (xml.charCodeAt(0) === 0xfeff) return 'malformed';
  const decl = DECLARATION.exec(xml);
  let rest = xml;
  if (decl) {
    const body = DECLARATION_BODY.exec(decl[1] ?? '');
    if (!body) return 'malformed';
    if (body[3] !== undefined && body[3].toLowerCase() !== 'utf-8') return 'malformed';
    rest = xml.slice(decl[0].length);
  }
  // Before comments are removed: a PI is refused even inside a comment, as DOCTYPE and CDATA are.
  if (rest.includes('<?')) return 'processing_instruction';
  if (allowComments) rest = rest.replace(COMMENTS, '');
  if (!xmlCharsOnly(xml)) return 'malformed';
  if (occurrences(xml, '<') > 2 * MAX_ELEMENTS) return 'too_complex';
  if (!tagStreamWithinBounds(rest)) return 'too_complex';
  return { declared: decl !== null };
}

function occurrences(text: string, needle: string): number {
  let n = 0;
  for (let i = text.indexOf(needle); i !== -1; i = text.indexOf(needle, i + needle.length)) n += 1;
  return n;
}

/**
 * Depth, element count and attributes per element, read from the tag stream in one linear pass
 * (quotes respected, since `>` and `/` are legal in attribute values). Only a bound: the parser
 * still decides whether the tags are well formed. `text` holds no PI, comment, CDATA or DOCTYPE.
 */
function tagStreamWithinBounds(text: string): boolean {
  let depth = 0;
  let elements = 0;
  for (let i = text.indexOf('<'); i !== -1;) {
    let j = i + 1;
    let quote = '';
    let attributes = 0;
    for (; j < text.length; j += 1) {
      const ch = text[j];
      if (quote) {
        if (ch === quote) quote = '';
      } else if (ch === '"' || ch === "'") quote = ch;
      else if (ch === '=') attributes += 1;
      else if (ch === '>') break;
    }
    if (j >= text.length) return true; // unterminated: the parser refuses it
    if (text[i + 1] === '/') depth -= 1;
    else {
      elements += 1;
      if (text[j - 1] !== '/') depth += 1;
      if (depth > MAX_DEPTH || elements > MAX_ELEMENTS) return false;
      if (attributes > MAX_ATTRIBUTES_PER_ELEMENT) return false;
    }
    i = text.indexOf('<', j);
  }
  return true;
}

/** XML 1.0 `Char`: tab, LF, CR, U+0020 up, well-formed surrogate pairs, not U+FFFE or U+FFFF. */
function xmlCharsOnly(xml: string): boolean {
  for (let i = 0; i < xml.length; i += 1) {
    const c = xml.charCodeAt(i);
    if (c < 0x20) {
      if (c !== 0x09 && c !== 0x0a && c !== 0x0d) return false;
    } else if (c >= 0xd800 && c <= 0xdbff) {
      const next = xml.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i += 1;
    } else if ((c >= 0xdc00 && c <= 0xdfff) || c === 0xfffe || c === 0xffff) {
      return false;
    }
  }
  return true;
}

function parse(xml: string): XmlDocument | 'malformed' | 'not_response' {
  let first: string | null = null;
  const thrower = (msg: unknown) => {
    first ??= String(msg);
    throw new Error('xml');
  };
  try {
    return new DOMParser({
      locator: {},
      errorHandler: { warning: thrower, error: thrower, fatalError: thrower },
    }).parseFromString(xml, 'text/xml');
  } catch (error) {
    // xmldom reports a second root element as a DOM hierarchy error: elements next to the root.
    const message = `${first ?? ''} ${error instanceof Error ? error.message : ''}`;
    return /Hierarchy request error/.test(message) ? 'not_response' : 'malformed';
  }
}

export function samlPreCheck(
  xml: string,
  options: { root: 'Response' | 'EntityDescriptor'; hasSpKey: boolean },
): { ok: true; doc: XmlDocument; inResponseTo: string | null; destination: string | null } | Fail {
  const metadata = options.root === 'EntityDescriptor';
  const raw = rawCheck(xml, metadata ? SAML_METADATA_MAX_BYTES : SAML_MAX_BYTES, metadata);
  if (typeof raw === 'string') return fail(raw);
  const doc = parse(xml);
  if (typeof doc === 'string') return fail(doc);

  const root = doc.documentElement;
  if (!root || root.localName !== options.root || root.namespaceURI !== (metadata ? MD : P)) {
    return fail('not_response');
  }
  // Nothing beside the document element but whitespace, and the declaration (a PI node in xmldom 0.8).
  for (let n = doc.firstChild; n; n = n.nextSibling) {
    if (n === root) continue;
    if (n.nodeType === 3 && /^[\t\n\r ]*$/.test(n.nodeValue ?? '')) continue;
    if (n.nodeType === 7 && n === doc.firstChild && raw.declared && n.nodeName === 'xml') continue;
    if (n.nodeType === 8 && metadata) continue;
    return fail('not_response');
  }

  const walked = walk(root, metadata ? 'metadata' : 'response');
  if (typeof walked === 'string') return fail(walked);
  if (walked.misplacedAssertion) return fail('assertion_count');
  if (!metadata && walked.direct.length === 0 && !walked.duplicateId && !walked.badSignature) {
    // sso-scim.md §6.3: an IdP's refusal (no assertion, a status other than Success) is idp_error.
    const status = topStatus(root);
    if (status !== null && status !== SUCCESS) return fail('idp_status');
  }
  if (!metadata && walked.direct.length !== 1) return fail('assertion_count');
  if (walked.duplicateId) return fail('duplicate_id');
  if (walked.badSignature) return fail('signature_shape');
  if (metadata) return { ok: true, doc, inResponseTo: null, destination: null };
  if (walked.direct[0]?.localName === 'EncryptedAssertion' && !options.hasSpKey) {
    return fail('encrypted_without_key');
  }
  return {
    ok: true,
    doc,
    inResponseTo: root.getAttribute('InResponseTo') || null,
    destination: root.getAttribute('Destination') || null,
  };
}

const SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

/** The top-level `StatusCode` of a Response's `Status` (its `Value`), or null without one. */
export function topStatus(root: XmlElement): string | null {
  const status = childElements(root).find((c) => c.namespaceURI === P && c.localName === 'Status');
  const code = status
    ? childElements(status).find((c) => c.namespaceURI === P && c.localName === 'StatusCode')
    : undefined;
  return code ? code.getAttribute('Value') : null;
}

/**
 * The pre-check of an assertion on its own (sso-scim.md §6.3): what node-saml verified
 * (`profile.getAssertionXml()`, the signed bytes) and the plaintext of an `EncryptedAssertion`
 * before node-saml decrypts it. The same text rules as a response (no DOCTYPE, PI, comment or
 * CDATA; bounds; names; signature shape; no duplicate ID), and the document element must be one
 * `Assertion` in the assertion namespace with no other `Assertion` or `Response` inside.
 */
export function samlAssertionCheck(
  xml: string,
): { ok: true; doc: XmlDocument; assertion: XmlElement } | Fail {
  const raw = rawCheck(xml, SAML_MAX_BYTES);
  if (typeof raw === 'string') return fail(raw);
  const doc = parse(xml);
  if (typeof doc === 'string') return fail(doc);
  const root = doc.documentElement;
  if (!root || root.localName !== 'Assertion' || root.namespaceURI !== A) {
    return fail('not_response');
  }
  for (let n = doc.firstChild; n; n = n.nextSibling) {
    if (n === root) continue;
    if (n.nodeType === 3 && /^[\t\n\r ]*$/.test(n.nodeValue ?? '')) continue;
    if (n.nodeType === 7 && n === doc.firstChild && raw.declared && n.nodeName === 'xml') continue;
    return fail('not_response');
  }
  const walked = walk(root, 'assertion');
  if (typeof walked === 'string') return fail(walked);
  if (walked.misplacedAssertion) return fail('assertion_count');
  if (walked.duplicateId) return fail('duplicate_id');
  if (walked.badSignature) return fail('signature_shape');
  return { ok: true, doc, assertion: root };
}

interface Walked {
  /** The Assertion or EncryptedAssertion children of a Response root, in the assertion namespace. */
  direct: XmlElement[];
  /** An Assertion, EncryptedAssertion or Response (any namespace: node-saml matches on local-name()) elsewhere. */
  misplacedAssertion: boolean;
  duplicateId: boolean;
  badSignature: boolean;
}

/**
 * One pass over every element. Bounds, forbidden names, namespace well-formedness and node types
 * fail at once; the structural findings are collected so that the result does not depend on the
 * order of the walk (an assertion wrapped in a signature is `assertion_count`, whatever else).
 */
function walk(
  root: XmlElement,
  mode: 'response' | 'metadata' | 'assertion',
): Walked | PreCheckCode {
  const out: Walked = {
    direct: [],
    misplacedAssertion: false,
    duplicateId: false,
    badSignature: false,
  };
  const ids = new Set<string>();
  let elements = 0;
  const stack: { node: XmlElement; depth: number; inSignature: boolean }[] = [
    { node: root, depth: 1, inSignature: false },
  ];
  for (let item = stack.pop(); item; item = stack.pop()) {
    const { node, depth, inSignature } = item;
    elements += 1;
    if (depth > MAX_DEPTH || elements > MAX_ELEMENTS) return 'too_complex';
    const nameProblem = checkNames(node);
    if (nameProblem) return nameProblem;
    for (let i = 0; i < node.attributes.length; i += 1) {
      const attr = node.attributes.item(i);
      if (!attr) continue;
      if (attr.value.length > MAX_ATTRIBUTE) return 'too_complex';
      // Character references decode here: `&#0;` or `&#xD800;` passed the raw check.
      if (!xmlCharsOnly(attr.value)) return 'malformed';
      if (ID_NAMES.has(attr.localName)) {
        if (ids.has(attr.value)) out.duplicateId = true;
        ids.add(attr.value);
      }
    }

    const local = node.localName;
    if (local === 'Assertion' || local === 'EncryptedAssertion') {
      if (mode === 'assertion' && node === root) {
        // The document element of samlAssertionCheck.
      } else if (mode === 'response' && node.parentNode === root && node.namespaceURI === A) {
        out.direct.push(node);
      } else out.misplacedAssertion = true;
    }
    if (local === 'Response' && node !== root) out.misplacedAssertion = true;
    if (local === 'Signature' && !signatureShapeOk(node)) out.badSignature = true;
    if (inSignature && Object.hasOwn(SIGNATURE_PLACES, local)) {
      const parent = node.parentNode as XmlElement | null;
      if (
        node.namespaceURI !== DS ||
        parent?.namespaceURI !== DS ||
        parent.localName !== SIGNATURE_PLACES[local]
      ) {
        out.badSignature = true;
      }
    }
    if (node.namespaceURI === DS && Object.hasOwn(DS_PARENT, local)) {
      const parent = node.parentNode as XmlElement | null;
      if (parent?.namespaceURI !== DS || parent.localName !== DS_PARENT[local])
        out.badSignature = true;
    }

    for (let c = node.firstChild; c; c = c.nextSibling) {
      if (c.nodeType === 1) {
        stack.push({
          node: c as XmlElement,
          depth: depth + 1,
          inSignature: inSignature || local === 'Signature',
        });
      } else if (c.nodeType === 3) {
        if (!xmlCharsOnly(c.nodeValue ?? '')) return 'malformed';
      } else if (c.nodeType === 8) {
        // IdP metadata may carry comments (Ruling M-3); nothing signed ever does.
        if (mode !== 'metadata') return 'comment';
      } else if (c.nodeType === 4) return 'cdata';
      else if (c.nodeType === 7) return 'processing_instruction';
      else if (c.nodeType !== 3) return 'malformed';
    }
  }
  return out;
}

/** Forbidden local names and prefixes, and namespace well-formedness (no unbound prefix, no `xmlns:p=""`). */
function checkNames(node: XmlElement): PreCheckCode | null {
  if (FORBIDDEN.has(node.localName) || (node.prefix !== null && FORBIDDEN.has(node.prefix)))
    return 'forbidden_name';
  if (node.prefix && !node.namespaceURI) return 'malformed';
  for (let i = 0; i < node.attributes.length; i += 1) {
    const attr = node.attributes.item(i);
    if (!attr) continue;
    if (FORBIDDEN.has(attr.localName) || (attr.prefix !== null && FORBIDDEN.has(attr.prefix)))
      return 'forbidden_name';
    if (attr.prefix === 'xmlns' && attr.value === '') return 'malformed';
    if (attr.prefix && attr.prefix !== 'xmlns' && attr.prefix !== 'xml' && !attr.namespaceURI)
      return 'malformed';
  }
  return null;
}

function childElements(e: XmlElement): XmlElement[] {
  const out: XmlElement[] = [];
  for (let c = e.firstChild; c; c = c.nextSibling) if (c.nodeType === 1) out.push(c as XmlElement);
  return out;
}

/**
 * The xmldsig children of `e`, in exactly this order (`optional` ones may be missing), and no
 * other element child. Returns them by local name, or null.
 */
function sequence(
  e: XmlElement,
  pattern: readonly (readonly [string, 'one' | 'optional'])[],
): Map<string, XmlElement> | null {
  const children = childElements(e);
  const found = new Map<string, XmlElement>();
  let k = 0;
  for (const [name, mode] of pattern) {
    const c = children[k];
    if (c && c.namespaceURI === DS && c.localName === name) {
      found.set(name, c);
      k += 1;
    } else if (mode === 'one') {
      return null;
    }
  }
  return k === children.length ? found : null;
}

const isLeaf = (e: XmlElement | undefined): e is XmlElement =>
  e !== undefined && childElements(e).length === 0;

/** CanonicalizationMethod and Transform hold nothing but exclusive c14n's InclusiveNamespaces. */
const onlyInclusiveNamespaces = (e: XmlElement | undefined): e is XmlElement =>
  e !== undefined &&
  childElements(e).every(
    (c) => c.namespaceURI === EXC_C14N && c.localName === 'InclusiveNamespaces' && isLeaf(c),
  );

/**
 * The xmldsig schema's shape, in order: Signature = SignedInfo, SignatureValue, KeyInfo? (no
 * Object: a place to hide a wrapped assertion); SignedInfo = CanonicalizationMethod,
 * SignatureMethod, Reference (one Reference, CVE-2025-29774); Reference = Transforms?,
 * DigestMethod, DigestValue; Transforms = one or two Transform. SignatureMethod, DigestMethod,
 * DigestValue and SignatureValue hold no elements. The algorithms are SHA-256 or stronger (SHA-1
 * and HMAC refused).
 */
function signatureShapeOk(signature: XmlElement): boolean {
  if (signature.namespaceURI !== DS) return false;
  const parts = sequence(signature, [
    ['SignedInfo', 'one'],
    ['SignatureValue', 'one'],
    ['KeyInfo', 'optional'],
  ]);
  if (!parts || !isLeaf(parts.get('SignatureValue'))) return false;
  const info = parts.get('SignedInfo');
  const inner =
    info &&
    sequence(info, [
      ['CanonicalizationMethod', 'one'],
      ['SignatureMethod', 'one'],
      ['Reference', 'one'],
    ]);
  if (!inner || !onlyInclusiveNamespaces(inner.get('CanonicalizationMethod'))) return false;
  const method = inner.get('SignatureMethod');
  if (!isLeaf(method) || !SIGNATURE_METHODS.has(method.getAttribute('Algorithm') ?? '')) {
    return false;
  }
  const ref = inner.get('Reference');
  const refParts =
    ref &&
    sequence(ref, [
      ['Transforms', 'optional'],
      ['DigestMethod', 'one'],
      ['DigestValue', 'one'],
    ]);
  if (!refParts || !isLeaf(refParts.get('DigestValue'))) return false;
  const transforms = refParts.get('Transforms');
  if (transforms) {
    const list = childElements(transforms);
    if (list.length < 1 || list.length > 2) return false;
    for (const t of list) {
      if (t.namespaceURI !== DS || t.localName !== 'Transform' || !onlyInclusiveNamespaces(t)) {
        return false;
      }
    }
  }
  const digest = refParts.get('DigestMethod');
  return isLeaf(digest) && DIGEST_METHODS.has(digest.getAttribute('Algorithm') ?? '');
}
