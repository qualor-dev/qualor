import { createReadStream } from 'node:fs';
import { SaxesParser, type SaxesTagPlain } from 'saxes';

const MAX_XML_DEPTH = 256;

export interface XmlHandler {
  /** `parents` are the enclosing element names, outermost first (the element itself excluded). */
  open(name: string, attributes: Readonly<Record<string, string>>, parents: readonly string[]): void;
  close?(name: string, parents: readonly string[]): void;
  /** `parents` ends with the element containing the text. */
  text?(text: string, parents: readonly string[]): void;
}

/**
 * Streams an XML file through saxes (Review Focus 4). No DTD is ever loaded or processed: saxes
 * only reports the DOCTYPE and rejects any entity other than the predefined ones, so external
 * entities (XXE) and entity expansion cannot happen.
 */
export async function parseXmlFile(absPath: string, handler: XmlHandler): Promise<void> {
  const parser = new SaxesParser();
  const stack: string[] = [];
  let failure: Error | null = null;
  parser.on('error', (err: Error) => {
    failure ??= err;
  });
  parser.on('opentag', (tag: SaxesTagPlain) => {
    if (failure !== null) return;
    if (stack.length >= MAX_XML_DEPTH) {
      failure = new Error(`XML nesting deeper than ${MAX_XML_DEPTH}`);
      return;
    }
    handler.open(tag.name, tag.attributes, stack);
    stack.push(tag.name);
  });
  parser.on('closetag', (tag: SaxesTagPlain) => {
    if (failure !== null) return;
    stack.pop();
    handler.close?.(tag.name, stack);
  });
  parser.on('text', (text: string) => {
    if (failure === null) handler.text?.(text, stack);
  });
  for await (const chunk of createReadStream(absPath, { encoding: 'utf8', highWaterMark: 64 * 1024 })) {
    parser.write(String(chunk));
    if (failure !== null) throw failure;
  }
  parser.close();
  if (failure !== null) throw failure;
}
