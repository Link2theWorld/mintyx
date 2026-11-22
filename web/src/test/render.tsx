import { QueryClientProvider } from "@tanstack/react-query";
import { render, type RenderResult } from "@testing-library/react";
import type { ReactElement } from "react";
import { AntProviders, makeQueryClient } from "../App";
import { I18nProvider } from "../i18n/I18nProvider";
import { ThemeProvider } from "../theme/ThemeProvider";

export function renderWithProviders(ui: ReactElement): RenderResult {
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <I18nProvider>
        <ThemeProvider>
          <AntProviders>{ui}</AntProviders>
        </ThemeProvider>
      </I18nProvider>
    </QueryClientProvider>,
  );
}
