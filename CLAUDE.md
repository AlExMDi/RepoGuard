RepoGuard
Escáner de seguridad local-first (secretos, dependencias, misconfiguraciones). Spec del MVP: @docs/specs/mvp.md

Comandos
pnpm test <ruta> tests de un fichero (prefiere esto a la suite completa; sin `--`: con pnpm 11 vitest recibe el `--` e ignora el filtro)
pnpm typecheck obligatorio antes de dar una tarea por terminada
pnpm lint
Arquitectura
Hexagonal. packages/core no depende de ningún otro paquete ni de E/S.
Escaners, reporters y storage son adaptadores que implementan puertos de core.
Decisiones en docs/adr/. Si contradices un ADR, para y pregunta.
Flujo
Rama por issue: feat/<n>-<slug>. Commits convencionales. Nunca push a main.
Tests primero. No modifiques un test para que pase sin decírmelo.
Trampas
IMPORTANT: nunca imprimas, loguees ni guardes un secreto sin redactar.
fixtures/ contiene secretos FALSOS a propósito; no los “arregles”.
