import { clip } from './text';

/** The server's bound on gate and profile names (`z.string().trim().min(1).max(100)`). */
const NAME_MAX_LENGTH = 100;

/**
 * The name of a copy, such as "Strict (copy)", with the original name shortened when the whole
 * would exceed the server's 100 characters (never cutting a surrogate pair in half).
 */
export function copyName(name: string, format: (name: string) => string): string {
  const whole = format(name);
  if (whole.length <= NAME_MAX_LENGTH) return whole;
  const room = NAME_MAX_LENGTH - (whole.length - name.length) - 1;
  return format(`${clip(name, Math.max(room, 1)).trimEnd()}…`);
}
