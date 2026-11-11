import { describe, expect, it } from "vitest";
import { en, fr } from "./messages";

// Every UI string must exist in both languages (French and English are both first-class).
function keys(o: unknown, prefix = ""): string[] {
  if (o === null || typeof o !== "object" || Array.isArray(o)) return [prefix];
  return Object.entries(o as Record<string, unknown>).flatMap(([k, v]) => keys(v, prefix ? `${prefix}.${k}` : k));
}

describe("i18n dictionaries", () => {
  it("have the same keys in French and English", () => {
    expect(keys(en).sort()).toEqual(keys(fr).sort());
  });
  it("have no empty strings", () => {
    for (const dict of [fr, en]) {
      const walk = (o: unknown): void => {
        if (typeof o === "string") expect(o.trim().length).toBeGreaterThan(0);
        else if (o && typeof o === "object") Object.values(o).forEach(walk);
      };
      walk(dict);
    }
  });
  it("never promise absolute safety", () => {
    const text = JSON.stringify({ fr, en }).toLowerCase();
    for (const banned of ["100% safe", "100 % sûr", "guaranteed safe", "garanti sans danger"]) expect(text).not.toContain(banned);
  });
});
