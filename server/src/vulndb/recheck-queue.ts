/**
 * Asks for a re-check of the tracked targets: all of them, or those of these projects. The
 * vulnerability database code calls it through this module, so tests can substitute it
 * (`VulndbUpdateDeps.enqueueRecheck`); the job itself lives in vulnerabilities/recheck.ts.
 */
export { enqueueRecheck } from '../vulnerabilities/recheck';
