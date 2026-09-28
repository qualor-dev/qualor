declare module '*.wasm' {
  /** Path of the embedded file (`import x from '…wasm' with { type: 'file' }` under bun). */
  const path: string;
  export default path;
}
