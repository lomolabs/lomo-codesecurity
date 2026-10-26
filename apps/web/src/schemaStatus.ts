export type SchemaInitStatus = Readonly<{
  startable: false;
  state: 'completed' | 'unverified';
  schema_id: string | null;
  schema_fingerprint: string | null;
  initialized_at: string | null;
  evidence: 'schema-identity-and-api-startup-verification' | null;
}>;

type VerifiedSchemaInitStatus = SchemaInitStatus & Readonly<{
  state: 'completed';
  schema_id: string;
  schema_fingerprint: string;
  initialized_at: string;
  evidence: 'schema-identity-and-api-startup-verification';
}>;

const SHA256 = /^[0-9a-f]{64}$/u;

export function schemaInitIsVerified(
  status: SchemaInitStatus | null | undefined,
): status is VerifiedSchemaInitStatus {
  return status?.state === 'completed'
    && status.startable === false
    && status.evidence === 'schema-identity-and-api-startup-verification'
    && Boolean(status.schema_id)
    && SHA256.test(status.schema_fingerprint || '')
    && Boolean(status.initialized_at);
}
