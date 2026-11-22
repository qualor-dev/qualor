/**
 * Azure DevOps sub-plan 2: what the parts not built yet say about an Azure DevOps connection (each
 * use carries its pending marker). Sub-plan 4 builds the decoration and removes this.
 */

/** Why a decoration through an Azure DevOps connection does nothing. */
export const AZURE_DECORATION_PENDING = 'Azure DevOps pull request decoration is not available yet';

/** The warn line of a re-evaluation or an AI review's end that does not decorate on Azure DevOps. */
export const AZURE_NOT_DECORATED = 'Azure DevOps decoration is not available yet';
