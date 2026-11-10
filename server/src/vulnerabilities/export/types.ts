/** What an export document says about itself and the target it describes. */
export interface ExportDocument {
  project: { key: string; name: string };
  organization: string;
  target: { kind: 'branch' | 'version'; name: string };
  generatedAt: Date;
  /** A uuid, the document's serial number. */
  serial: string;
  toolVersion: string;
}

/** One entry of a target's dependency inventory. */
export interface ExportPackage {
  ecosystem: string;
  name: string;
  version: string;
  purl: string | null;
  licenses: string[];
}

/** The product identity of a target: a generic purl, used by every export format. */
export function productId(project: { key: string }, target: { name: string }): string {
  return `pkg:generic/${encodeURIComponent(project.key)}@${encodeURIComponent(target.name)}`;
}
