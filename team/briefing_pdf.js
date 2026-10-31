const { chromium } = require("playwright");
(async () => { const b = await chromium.launch(); const p = await b.newPage();
  for (let i = 2; i < process.argv.length; i += 2) { await p.goto("file://" + process.argv[i]); await p.pdf({ path: process.argv[i+1], preferCSSPageSize: true, printBackground: true, tagged: true }); }
  await b.close(); console.log("ok"); })();
