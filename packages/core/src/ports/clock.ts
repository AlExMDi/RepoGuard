/** Milisegundos monotónicos, para durationMs. Inyectado para que los tests sean deterministas. */
export type Clock = () => number;
