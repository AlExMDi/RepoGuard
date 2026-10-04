---
paths:
  - "packages/core/**"
---
- core solo importa de sí mismo. Nada de fs, http, SQLite ni de otros paquetes del monorepo.
- Toda dependencia externa entra como puerto (interfaz) definido en core/src/ports.
- Funciones puras siempre que sea posible; los efectos van en los adaptadores.
