import { describe, expect, it } from "vitest";
import { DICTIONARIES, detectSystemLocale } from "./i18n";

describe("i18n dictionaries", () => {
  it("contains identical top-level keys across en, ko, and ja", () => {
    const enKeys = Object.keys(DICTIONARIES.en).sort();
    const koKeys = Object.keys(DICTIONARIES.ko).sort();
    const jaKeys = Object.keys(DICTIONARIES.ja).sort();
    expect(koKeys).toEqual(enKeys);
    expect(jaKeys).toEqual(enKeys);

    const enErrorKeys = Object.keys(DICTIONARIES.en.errors).sort();
    expect(Object.keys(DICTIONARIES.ko.errors).sort()).toEqual(enErrorKeys);
    expect(Object.keys(DICTIONARIES.ja.errors).sort()).toEqual(enErrorKeys);

    const enPhaseKeys = Object.keys(DICTIONARIES.en.phases).sort();
    expect(Object.keys(DICTIONARIES.ko.phases).sort()).toEqual(enPhaseKeys);
    expect(Object.keys(DICTIONARIES.ja.phases).sort()).toEqual(enPhaseKeys);

    const enWarningKindKeys = Object.keys(DICTIONARIES.en.warningKinds).sort();
    expect(Object.keys(DICTIONARIES.ko.warningKinds).sort()).toEqual(enWarningKindKeys);
    expect(Object.keys(DICTIONARIES.ja.warningKinds).sort()).toEqual(enWarningKindKeys);
  });

  it("detects locale from BCP-47 language tags", () => {
    expect(detectSystemLocale("ko-KR")).toBe("ko");
    expect(detectSystemLocale("ja-JP")).toBe("ja");
    expect(detectSystemLocale("en-US")).toBe("en");
    expect(detectSystemLocale("fr-FR")).toBe("en");
  });

  it("includes explicit Windows Explorer AES-256 note in all languages", () => {
    expect(DICTIONARIES.en.aesWindowsWarning).toContain("Windows Explorer");
    expect(DICTIONARIES.ko.aesWindowsWarning).toContain("AES-256");
    expect(DICTIONARIES.ja.aesWindowsWarning).toContain("AES-256");
  });
});
