#!/usr/bin/env node
/**
 * Patch gitbook-plugin-mermaid-2 for HonKit 6.
 *
 * Two defects, both fixed here:
 *
 * 1. The plugin injects its mermaid.min.js <script> via the legacy GitBook
 *    `website.html["head:end"]` hook. HonKit dropped that hook, so the built
 *    pages load plugin.js + mermaid.css but never the mermaid library itself:
 *    plugin.js calls mermaid.init() -> ReferenceError, and every diagram
 *    degrades to raw text. Rewrite the client script to load the bundled
 *    mermaid.min.js (path relative to plugin.js itself) before calling init.
 *
 * 2. The plugin ships mermaid 7.x (bower-era), which does not understand the
 *    `flowchart` keyword used by several book diagrams. Copy the mermaid 9.x
 *    dist (npm devDependency, last line with the UMD global + init()) over
 *    the bundled copy.
 *
 * Wired as an npm postinstall hook so fresh `npm install` runs stay patched.
 */
const fs = require("fs");
const path = require("path");

const pluginDir = path.join(
    __dirname,
    "..",
    "node_modules",
    "gitbook-plugin-mermaid-2",
    "book",
);
const target = path.join(pluginDir, "plugin.js");
const bundledMermaid = path.join(
    pluginDir,
    "bower_components",
    "mermaid",
    "dist",
    "mermaid.min.js",
);
const mermaid9 = path.join(
    __dirname,
    "..",
    "node_modules",
    "mermaid",
    "dist",
    "mermaid.min.js",
);

const patched = `require([
  'gitbook'
], function (gitbook) {
  // HonKit 6 has no head:end hook, so the plugin's own <script> for
  // mermaid.min.js never reaches the page. Load it here, relative to
  // this plugin.js, then render. Re-init on page.change is safe: the
  // library skips nodes already marked data-processed.
  var pluginBase = (document.currentScript && document.currentScript.src || '').replace(/[^/]*$/, '');
  var libSrc = pluginBase + 'bower_components/mermaid/dist/mermaid.min.js';

  var render = function () {
    if (window.mermaid && typeof window.mermaid.init === 'function') {
      window.mermaid.init();
    }
  };

  var loadLib = function (onReady) {
    if (window.mermaid) { onReady(); return; }
    var s = document.createElement('script');
    s.src = libSrc;
    s.onload = onReady;
    s.onerror = function () {
      console.error('[mermaid-2] failed to load ' + libSrc);
    };
    document.head.appendChild(s);
  };

  gitbook.events.bind('page.change', function () {
    loadLib(render);
  });
});
`;

if (!fs.existsSync(target)) {
    console.error("patch-mermaid-plugin: " + target + " not found (plugin installed?)");
    process.exit(1);
}

const current = fs.readFileSync(target, "utf8");
if (current !== patched) {
    fs.writeFileSync(target, patched);
    console.log("patch-mermaid-plugin: patched " + target);
} else {
    console.log("patch-mermaid-plugin: plugin.js already patched");
}

if (!fs.existsSync(mermaid9)) {
    console.error("patch-mermaid-plugin: " + mermaid9 + " not found (npm i mermaid@9?)");
    process.exit(1);
}
fs.copyFileSync(mermaid9, bundledMermaid);
console.log("patch-mermaid-plugin: mermaid 9.x copied over bundled 7.x");
