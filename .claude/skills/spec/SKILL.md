---
name: spec
description: Entrevista al usuario y escribe la spec de una feature en docs/specs/
disable-model-invocation: true
---
Quiero especificar: $ARGUMENTS

Lee CLAUDE.md, docs/adr/ y el código relacionado. Luego entrevístame con la herramienta
AskUserQuestion sobre lo difícil: casos borde, errores, rendimiento, seguridad, trade-offs.
No preguntes lo obvio. Cuando esté todo cubierto, escribe docs/specs/<slug>.md con:
problema, alcance, no-objetivos, interfaces y ficheros afectados, casos de test,
riesgos de seguridad y un paso de verificación de punta a punta. No escribas código.
