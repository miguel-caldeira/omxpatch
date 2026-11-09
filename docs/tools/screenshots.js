// Capturas de ecrã para o manual. Uso: NODE_PATH=$(npm root -g) node docs/tools/screenshots.js http://127.0.0.1:8130 docs/img
const { chromium } = require('playwright');
const base = process.argv[2] || 'http://127.0.0.1:8130', out = process.argv[3] || 'docs/img';
const PASS = 'Demo-Passw0rd!2026';
async function login(b, email) {
  const ctx = await b.newContext({ viewport: { width: 1360, height: 900 }, deviceScaleFactor: 1 });
  const p = await ctx.newPage();
  await p.goto(base + '/login'); await p.fill('input[name=email]', email); await p.fill('input[name=password]', PASS);
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');
  return p;
}
async function shot(p, path, file, h = 1400) {
  await p.goto(base + path); await p.waitForLoadState('networkidle');
  await p.screenshot({ path: `${out}/${file}.png`, clip: { x: 0, y: 0, width: 1360, height: h }, fullPage: true });
  console.log('ok', file);
}
(async () => {
  const b = await chromium.launch();
  let p = await login(b, 'admin@oramix.example');
  await shot(p, '/', 'centro-de-comando', 1900);
  await shot(p, '/exposures?sort=loss', 'exposicoes', 900);
  const link = await p.$eval('a[href^="/exposures/"]', a => a.getAttribute('href'));
  await shot(p, link, 'exposicao-detalhe', 1700);
  await shot(p, '/assets', 'ativos', 900);
  const al = await p.$eval('a[href^="/assets/"]:not([href$="new"])', a => a.getAttribute('href')).catch(() => '/assets/1');
  await shot(p, '/assets/1', 'ativo-detalhe', 1900);
  await shot(p, '/updates', 'atualizacoes', 1400);
  await shot(p, '/plans', 'planos', 800);
  await shot(p, '/plans/1', 'plano-detalhe', 1500);
  await shot(p, '/practices', 'boas-praticas', 1300);
  await shot(p, '/baseline', 'linha-de-base', 1100);
  await shot(p, '/controls', 'controlos', 800);
  await shot(p, '/agents', 'agentes', 1500);
  await shot(p, '/integrations', 'integracoes', 1500);
  await shot(p, '/compliance', 'conformidade', 1300);
  await shot(p, '/executive', 'executivo', 1300);
  await shot(p, '/users', 'utilizadores', 800);
  p = await login(b, 'root@oramix.example');
  await shot(p, '/system', 'sistema', 1300);
  await shot(p, '/system/capacity', 'capacidade', 1700);
  await shot(p, '/system/settings', 'configuracao', 1600);
  await shot(p, '/tenants', 'organizacoes', 700);
  await b.close();
})();
