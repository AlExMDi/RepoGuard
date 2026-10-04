// TextEncoder es un global del lenguaje en Node (no E/S), pero lib ES2023 no lo tipa y
// core no usa @types/node. Declaración mínima de lo que usa policy/fingerprint.
declare class TextEncoder {
  encode(input: string): Uint8Array;
}
