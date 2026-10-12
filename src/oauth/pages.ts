export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}

const STYLE = `body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;line-height:1.5;color:#1b1b1b}
h1{font-size:1.4rem}.box{border:1px solid #ccc;border-radius:8px;padding:1rem;margin:1rem 0}
label{display:block;margin:.5rem 0 .25rem}input[type=password]{width:100%;padding:.5rem;font-size:1rem;box-sizing:border-box}
button{padding:.6rem 1.2rem;font-size:1rem;margin-right:.5rem;margin-top:1rem;cursor:pointer}.err{color:#b00020}
code{word-break:break-all}`;

function layout(title: string, body: string): string {
  return `<!doctype html><html lang="sk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body>${body}</body></html>`;
}

export function consentPage(p: { requestId: string; clientName: string; redirectHost: string; error?: string }): string {
  return layout(
    'Povoliť prístup k Google Tasks',
    `<h1>Povoliť prístup k Google Tasks</h1>
<div class="box">
<p>Aplikácia <strong>${escapeHtml(p.clientName)}</strong> (<code>${escapeHtml(p.redirectHost)}</code>) žiada o prístup k tomuto serveru.</p>
<p>Po schválení bude môcť čítať, vytvárať, upravovať, dokončovať a mazať úlohy v Google Tasks pripojeného účtu. Nezíska prístup ku Gmailu, Google Disku ani Kalendáru a nikdy neuvidí vaše Google tokeny.</p>
</div>
${p.error ? `<p class="err" role="alert">${escapeHtml(p.error)}</p>` : ''}
<form method="post" action="/oauth/authorize" autocomplete="off">
<input type="hidden" name="request_id" value="${escapeHtml(p.requestId)}">
<label for="pp">Prístupová fráza vlastníka servera</label>
<input id="pp" type="password" name="passphrase" required autofocus>
<button type="submit" name="decision" value="approve">Povoliť a pokračovať na Google</button>
<button type="submit" name="decision" value="deny" formnovalidate>Zamietnuť</button>
</form>`,
  );
}

export function errorPage(message: string): string {
  return layout('Chyba autorizácie', `<h1>Chyba autorizácie</h1><p class="err">${escapeHtml(message)}</p><p>Zatvorte toto okno a skúste pripojenie znova.</p>`);
}
