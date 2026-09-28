import { z } from 'zod';
import { reportSchema } from './report/schema';
import { configSchema } from './config/schema';
import { importReportSchema } from './import/report';

function render(schema: z.ZodType, id: string): string {
  const json = z.toJSONSchema(schema, { io: 'input', unrepresentable: 'any' });
  return `${JSON.stringify({ $id: id, ...json }, null, 2)}\n`;
}

/** File name → JSON Schema text. `pnpm schemas` writes these; a test checks they are fresh. */
export function generatedSchemas(): Record<string, string> {
  return {
    'report.schema.json': render(reportSchema, 'https://qualor.dev/schema/report.schema.json'),
    'qualor.schema.json': render(configSchema, 'https://qualor.dev/schema/qualor.schema.json'),
    'import-report.schema.json': render(
      importReportSchema,
      'https://qualor.dev/schema/import-report.schema.json',
    ),
  };
}
