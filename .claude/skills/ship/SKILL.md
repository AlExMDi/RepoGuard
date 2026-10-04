---
name: ship
description: Verifica, revisa y abre la PR de la rama actual
disable-model-invocation: true
---
1. Ejecuta pnpm lint, pnpm typecheck y pnpm test. Si algo falla, para y enséñamelo.
2. Usa el subagente architect sobre el diff contra main.
3. Si el diff toca ficheros, procesos, red o salida de hallazgos, usa también security-reviewer.
4. Enséñame los hallazgos bloqueantes y espera mi decisión.
5. Commit convencional, push de la rama y gh pr create con: qué cambia, por qué,
   cómo se ha verificado (con la salida de los tests) y "Closes #<issue>".
