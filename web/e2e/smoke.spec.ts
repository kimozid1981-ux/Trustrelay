import { expect, test } from "@playwright/test";

// Core user journey: register → onboarding → analyse a scam SMS → read the result → history → delete.
test("register, analyse a message, review and delete it", async ({ page }) => {
  const email = `e2e-${Date.now()}@example.com`;
  await page.addInitScript(() => window.localStorage.setItem("tr_locale", "en"));
  await page.goto("/register");
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Password", { exact: true }).fill("Correct-Horse-42!");
  await page.getByLabel(/I accept the terms/).check();
  await page.getByRole("button", { name: "Create account" }).click();

  await expect(page.getByRole("heading", { name: "Welcome to TrustRelay" })).toBeVisible();
  for (let i = 0; i < 3; i++) await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Get started" }).click();

  await expect(page.getByRole("heading", { name: "What do you want to check?" })).toBeVisible();
  await page.getByRole("tab", { name: "A message" }).click();
  await page.getByLabel("A message").fill(
    "Ameli: votre carte Vitale expire. Mettez à jour vos informations sous 24h sinon vos remboursements seront suspendus : https://ameli-remboursement.test-phish/maj",
  );
  await page.getByRole("button", { name: "Analyse" }).click();

  await page.waitForURL(/\/analysis\//);
  // The mock reputation source lists *.test-phish, so the verdict must be the strongest category.
  await expect(page.locator(".verdict.v-known_malicious")).toBeVisible();
  await page.screenshot({ path: "test-results/analysis-result.png", fullPage: true });
  await expect(page.getByText("What we found")).toBeVisible();
  await expect(page.getByText("What we recommend")).toBeVisible();
  await expect(page.locator("body")).not.toContainText(/100% safe/i);

  await page.getByRole("link", { name: "History" }).click();
  await expect(page.getByRole("heading", { name: "History" })).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByRole("button", { name: "Delete this analysis" }).click();
  await expect(page.getByText("No analyses yet.")).toBeVisible();
});

test("protected pages redirect to sign-in", async ({ page }) => {
  await page.goto("/history");
  await page.waitForURL(/\/login/);
  await expect(page.locator("#email")).toBeVisible();
});
