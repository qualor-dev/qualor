/**
 * The app's icons (spec §5): 24px, stroked with currentColor, drawn for Qualor (no icon package).
 * `d` are path data; `c` are circles as [cx, cy, r].
 */
export const ICONS = {
  'chevron-down': { d: ['M6 9l6 6 6-6'] },
  check: { d: ['M5 12.5l4.5 4.5L19 7.5'] },
  cross: { d: ['M6.5 6.5l11 11M17.5 6.5l-11 11'] },
  minus: { d: ['M6 12h12'] },
  alert: { d: ['M12 7.5v6', 'M12 16.8v.2'], c: [[12, 12, 9]] },
  branch: {
    d: ['M6 7.2v9.6', 'M18 9.2c0 5-6 4-11 7.5'],
    c: [
      [6, 5, 2.2],
      [6, 19, 2.2],
      [18, 7, 2.2],
    ],
  },
  'merge-request': {
    d: ['M6 8.2v7.6', 'M18 15.8V9.5A3.5 3.5 0 0 0 14.5 6H11', 'M13.5 3.5L11 6l2.5 2.5'],
    c: [
      [6, 6, 2.2],
      [6, 18, 2.2],
      [18, 18, 2.2],
    ],
  },
  clock: { d: ['M12 7v5l3 2'], c: [[12, 12, 9]] },
  search: { d: ['M16.5 16.5L21 21'], c: [[11, 11, 6.5]] },
  plus: { d: ['M12 5v14M5 12h14'] },
  external: {
    d: ['M14 4h6v6', 'M20 4l-9 9', 'M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5'],
  },
  user: { d: ['M4.5 20c.8-3.6 3.8-6 7.5-6s6.7 2.4 7.5 6'], c: [[12, 8, 4]] },
  'log-out': {
    d: ['M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3', 'M10 16l-4-4 4-4', 'M6 12h10'],
  },
  folder: { d: ['M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z'] },
  file: { d: ['M7 3h7l5 5v11a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z', 'M14 3v5h5'] },
  key: { d: ['M10.5 13.5L20 4', 'M16 8l2.5 2.5', 'M13.5 10.5L16 13'], c: [[7.5, 16.5, 3.5]] },
} as const satisfies Record<
  string,
  { d: readonly string[]; c?: readonly (readonly [number, number, number])[] }
>;

export type IconName = keyof typeof ICONS;
