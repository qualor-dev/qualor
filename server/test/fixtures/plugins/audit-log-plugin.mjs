// A plugin that implements `audit-log` and registers nothing (core records, rbac-audit.md §15), so
// a boot test of the test bundle can run with audit-log active (sso-scim.md §10.4's boot event).
export default { name: 'audit-log-fixture', apiVersion: 1, features: ['audit-log'], register() {} };
