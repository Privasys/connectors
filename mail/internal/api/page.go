// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

// linkPage is the whole account-linking surface: one document, no external
// requests, no framework.
//
// A page that asks someone for their mail password has no business fetching a
// script from a third party, and a reader should be able to check that claim
// by viewing the source rather than by trusting a build. That rules out a
// bundle, so it is written by hand and kept small enough to read.
//
// It is deliberately plain about what happens to the password, because the
// only reason to type one here is that the sentence explaining why is true.
const linkPage = `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect your mailbox</title>
<style>
  :root { color-scheme: light dark; --fg:#111; --muted:#5a5f66; --line:#d9dce1;
          --bg:#fff; --accent:#1a56db; --bad:#b42318; --ok:#067647; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e8eaed; --muted:#9aa0a6; --line:#3c4043; --bg:#16181c;
            --accent:#8ab4f8; --bad:#f2b8b5; --ok:#6dd58c; }
  }
  * { box-sizing: border-box }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif }
  main { max-width:34rem; margin:0 auto; padding:2.5rem 1.25rem 4rem }
  h1 { font-size:1.5rem; margin:0 0 .35rem }
  .sub { color:var(--muted); margin:0 0 2rem }
  fieldset { border:1px solid var(--line); border-radius:12px; padding:1.1rem 1.1rem 1.35rem; margin:0 0 1.25rem }
  legend { padding:0 .4rem; font-weight:600; font-size:.95rem }
  label { display:block; margin:.9rem 0 .3rem; font-weight:500; font-size:.92rem }
  input { width:100%; padding:.6rem .7rem; font:inherit; color:var(--fg);
          background:transparent; border:1px solid var(--line); border-radius:8px }
  input:focus { outline:2px solid var(--accent); outline-offset:1px }
  .hint { color:var(--muted); font-size:.85rem; margin:.35rem 0 0 }
  button { font:inherit; font-weight:600; padding:.65rem 1.1rem; border-radius:8px;
           border:1px solid transparent; background:var(--accent); color:#fff; cursor:pointer }
  button.secondary { background:transparent; color:var(--fg); border-color:var(--line) }
  button[disabled] { opacity:.6; cursor:progress }
  .row { display:flex; gap:.6rem; align-items:center; flex-wrap:wrap }
  .msg { margin:1rem 0 0; padding:.7rem .85rem; border-radius:8px; border:1px solid var(--line); font-size:.92rem }
  .msg.bad { border-color:var(--bad); color:var(--bad) }
  .msg.ok  { border-color:var(--ok); color:var(--ok) }
  .facts { margin:2rem 0 0; padding:0; list-style:none; color:var(--muted); font-size:.9rem }
  .facts li { padding-left:1.1rem; position:relative; margin:.45rem 0 }
  .facts li::before { content:"—"; position:absolute; left:0 }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.88em }
</style>
<main>
  <h1>Connect your mailbox</h1>
  <p class="sub">So an agent can read what arrives and leave you drafts. It can never send.</p>

  <div id="status" class="msg" hidden></div>

  <form id="form" autocomplete="off">
    <fieldset>
      <legend>Your mailbox</legend>

      <label for="user">Email address</label>
      <input id="user" name="user" type="email" required autocomplete="username"
             inputmode="email" placeholder="you@example.com">

      <label for="password">App password</label>
      <input id="password" name="password" type="password" required autocomplete="new-password">
      <p class="hint">Not your normal password. Create an app password with your
        provider; for Gmail that needs 2-Step Verification switched on.</p>

      <label for="host">IMAP server</label>
      <input id="host" name="host" value="imap.gmail.com:993">
      <p class="hint">Leave as is for Gmail.</p>

      <label for="domains">Your own domains <span class="hint">(optional)</span></label>
      <input id="domains" name="domains" placeholder="example.com, example.co.uk">
      <p class="hint">Used only to tell colleagues from customers when learning
        how you write.</p>
    </fieldset>

    <div class="row">
      <button id="submit" type="submit">Connect</button>
      <button id="disconnect" type="button" class="secondary" hidden>Disconnect</button>
    </div>
  </form>

  <ul class="facts">
    <li>Your password is checked against your mailbox, then encrypted and stored
        in your own Drive. This service keeps nothing.</li>
    <li>Your mail is never copied here. It stays with your provider and is read
        one message at a time, in memory.</li>
    <li>Connecting grants nothing on its own. Each app you want to use it must
        be approved separately, on your phone.</li>
    <li>Disconnecting stops all of it, and so does revoking this service's
        access to your Drive.</li>
  </ul>
</main>
<script nonce="__NONCE__">
(() => {
  const $ = (id) => document.getElementById(id);
  const status = $("status");

  const show = (text, kind) => {
    status.textContent = text;
    status.className = "msg" + (kind ? " " + kind : "");
    status.hidden = false;
  };

  async function api(method, body) {
    const res = await fetch("/v1/link", {
      method,
      headers: body ? { "content-type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      credentials: "same-origin",
    });
    let data = {};
    try { data = await res.json(); } catch {}
    if (!res.ok) throw new Error(data.error || ("the service answered " + res.status));
    return data;
  }

  async function refresh() {
    try {
      const s = await api("GET");
      if (s.linked) {
        show("Connected as " + s.account.user + ". Approve an app on your phone to let it read.", "ok");
        $("user").value = s.account.user;
        $("host").value = s.account.host;
        $("disconnect").hidden = false;
        $("submit").textContent = "Reconnect";
      } else {
        $("disconnect").hidden = true;
      }
    } catch (e) {
      show(e.message, "bad");
    }
  }

  $("form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = $("submit");
    btn.disabled = true;
    show("Checking these details against your mailbox…");
    try {
      const out = await api("POST", {
        host: $("host").value.trim(),
        user: $("user").value.trim(),
        password: $("password").value,
        own_domains: $("domains").value.split(",").map(s => s.trim()).filter(Boolean),
      });
      // Clear it the moment it is no longer needed. It is still in the page's
      // memory until then, which is unavoidable; leaving it in a form field
      // afterwards is not.
      $("password").value = "";
      show("Connected as " + out.account.user + ". " + out.next, "ok");
      $("disconnect").hidden = false;
      $("submit").textContent = "Reconnect";
    } catch (e) {
      show(e.message, "bad");
    } finally {
      btn.disabled = false;
    }
  });

  $("disconnect").addEventListener("click", async () => {
    if (!confirm("Disconnect this mailbox? Nothing will be able to read it until you connect again.")) return;
    try {
      const out = await api("DELETE");
      show(out.note, "ok");
      $("disconnect").hidden = true;
      $("submit").textContent = "Connect";
    } catch (e) {
      show(e.message, "bad");
    }
  });

  refresh();
})();
</script>
`
