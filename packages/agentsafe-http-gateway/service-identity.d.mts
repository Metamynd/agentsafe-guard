// Type declarations for @metamynd/agentsafe-http-gateway/service-identity (service-identity.mjs).

export const SERVICE_IDENTITY_FORMAT: string;

/** The gateway's own identity: a did:key and its Ed25519 key (PKCS#8 DER hex), as SERVICE_DID / SERVICE_KEY take them. */
export interface ServiceIdentity {
  format?: string;
  serviceDid: string;
  serviceKey: string;
  createdAt?: string;
}

export function createServiceIdentity(): ServiceIdentity;
/** Throws unless the DID is a did:key whose key is the private key's own public key. */
export function checkServiceIdentity(id: unknown): ServiceIdentity;
/** Owner-readable only; refuses to overwrite unless `force`. Returns the path. */
export function writeServiceIdentity(path: string, id: ServiceIdentity, opts?: { force?: boolean }): string;
export function readServiceIdentity(path: string): ServiceIdentity;
/** Sign the Trusted Counterparties registration challenge as this identity; returns the 128-hex signature. */
export function acceptChallenge(identity: ServiceIdentity, message: string): Promise<string>;
