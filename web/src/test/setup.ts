import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";
import { installMatchMedia, resetMedia } from "./matchMedia";

installMatchMedia();

afterEach(() => {
  cleanup();
  localStorage.clear();
  resetMedia();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

if (typeof window.ResizeObserver !== "function") {
  window.ResizeObserver = class {
    observe() { /* jsdom has no layout */ }
    unobserve() { /* jsdom has no layout */ }
    disconnect() { /* jsdom has no layout */ }
  };
}
