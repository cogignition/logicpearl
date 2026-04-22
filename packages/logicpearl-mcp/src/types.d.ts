declare module '@logicpearl/browser' {
  export function loadArtifact(
    ref: string,
    opts?: { fetchImpl?: typeof fetch },
  ): Promise<{
    manifest: Record<string, unknown>;
    metadata: Record<string, unknown>;
    featureCount: number;
    evaluate: (input: Record<string, unknown>) => {
      allow: boolean;
      bitmask?: bigint;
      firedRules: Array<{
        id: string;
        bit: number;
        label?: string;
        message?: string;
        counterfactual_hint?: string;
        action?: string;
      }>;
      primaryReason: unknown;
      counterfactualHints: string[];
    };
    rules: () => Array<unknown>;
    inspect: () => {
      gateId: string;
      artifactName: string;
      featureCount: number;
      ruleCount: number;
      artifactVersion: string;
    };
  }>;
}
