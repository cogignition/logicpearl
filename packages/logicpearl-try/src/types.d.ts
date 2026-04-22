declare module '@logicpearl/browser' {
  export function loadArtifact(
    reference: string,
    options?: { fetchImpl?: typeof fetch; instantiateWasm?: unknown; layout?: string },
  ): Promise<unknown>;
}
