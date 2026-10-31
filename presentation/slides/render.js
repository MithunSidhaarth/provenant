// Renders each <section> of deck.html to slide-N.png (1920x1080) for build_deck.js.
const { chromium } = require("playwright");
const path = require("path");
(async () => {
  const b = await chromium.launch(); const p = await b.newPage({ viewport: { width: 1920, height: 1080 } });
  await p.goto("file://" + path.join(__dirname, "deck.html")); await p.evaluate(() => document.fonts.ready); await p.waitForTimeout(400);
  const n = await p.$$eval("section.s", (s) => s.length);
  for (let i = 1; i <= n; i++) await (await p.$(`#s${i}`)).screenshot({ path: path.join(__dirname, `slide-${i}.png`) });
  console.log("rendered", n); await b.close();
})();
