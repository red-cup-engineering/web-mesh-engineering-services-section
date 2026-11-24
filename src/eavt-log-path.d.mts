// Type declarations for EAVT's JavaScript utterance log codec.
declare module "@red-cup-engineering/eavt-engineering-services-section/log-path" {
  type Carrier = import("@red-cup-engineering/http-server-core-service/internal/witness").UtteranceLog["utterances"][number];
  type JsonValue = ReturnType<typeof import("@red-cup-engineering/json-engine").parse>;

  export function dehydrateUtterances(utterances: readonly Carrier[]): JsonValue;
  export function rehydrateUtterances(value: JsonValue): readonly Carrier[];
}
