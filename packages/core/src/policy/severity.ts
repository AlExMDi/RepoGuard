import type { Category, Severity } from "../domain/finding";

/** Mayor = más grave. */
export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/** Mayor = antes, a igual severidad (mvp §2.6: secret > dependency > misconfig). */
export const CATEGORY_RANK: Record<Category, number> = { secret: 3, dependency: 2, misconfig: 1 };
