/** SHA-256 en hex. Lo inyecta cli con node:crypto, porque core no hace E/S. */
export type Hasher = (bytes: Uint8Array) => string;

/** Bytes aleatorios criptográficamente seguros, para la sal. */
export type RandomBytes = (n: number) => Uint8Array;
