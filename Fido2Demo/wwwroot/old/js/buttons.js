!(function() {
    "use strict";

    var t, e, n, a, o = window.document, i = window.encodeURIComponent, r = window.decodeURIComponent, l = window.Math, c = function(t) {
            return o.createElement(t);
        }, d = function(t) {
            return o.createTextNode(t);
        }; n = "faa75404-3b97-5585-b449-4bc51338fbd1", t = (/^http:/.test(o.location) ? "http" : "https") + "://buttons.github.io/", e = function(e) {
        t = e;
    }, a = !{}.hasOwnProperty.call(o, "currentScript") && o.currentScript && delete o.currentScript && o.currentScript ? o.currentScript.src : void 0; var s, h, u; s = function(t, e, n) {
        t.addEventListener ? t.addEventListener("" + e, n) : t.attachEvent("on" + e, n);
    }, h = function(t, e, n) {
        var a; s(t, e, a = function(o) {
            return t.removeEventListener ? t.removeEventListener("" + e, a) : t.detachEvent("on" + e, a), n(o);
        });
    }, u = function(t) {
        var e, n; (/m/).test(o.readyState) || !(/g/).test(o.readyState) && !o.documentElement.doScroll ? setTimeout(t) : o.addEventListener ? (n = 0, h(o, "DOMContentLoaded", e = function() {
            !n && (n = 1) && t();
        }), h(window, "load", e)) : (e = function() {
            (/m/).test(o.readyState) && (o.detachEvent("onreadystatechange", e), t());
        }, o.attachEvent("onreadystatechange", e));
    }; var p, f, g, m, w, b = { "mark-github": { width: 16,
        height: 16,
        path: "<path fill-rule=\"evenodd\" d=\"M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z\"/>" },
    eye: { width: 16,
        height: 16,
        path: "<path fill-rule=\"evenodd\" d=\"M8.06 2C3 2 0 8 0 8s3 6 8.06 6C13 14 16 8 16 8s-3-6-7.94-6zM8 12c-2.2 0-4-1.78-4-4 0-2.2 1.8-4 4-4 2.22 0 4 1.8 4 4 0 2.22-1.78 4-4 4zm2-4c0 1.11-.89 2-2 2-1.11 0-2-.89-2-2 0-1.11.89-2 2-2 1.11 0 2 .89 2 2z\"/>" },
    star: { width: 14,
        height: 16,
        path: "<path fill-rule=\"evenodd\" d=\"M14 6l-4.9-.64L7 1 4.9 5.36 0 6l3.6 3.26L2.67 14 7 11.67 11.33 14l-.93-4.74L14 6z\"/>" },
    "repo-forked": { width: 10,
        height: 16,
        path: "<path fill-rule=\"evenodd\" d=\"M8 1a1.993 1.993 0 0 0-1 3.72V6L5 8 3 6V4.72A1.993 1.993 0 0 0 2 1a1.993 1.993 0 0 0-1 3.72V6.5l3 3v1.78A1.993 1.993 0 0 0 5 15a1.993 1.993 0 0 0 1-3.72V9.5l3-3V4.72A1.993 1.993 0 0 0 8 1zM2 4.2C1.34 4.2.8 3.65.8 3c0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2zm3 10c-.66 0-1.2-.55-1.2-1.2 0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2zm3-10c-.66 0-1.2-.55-1.2-1.2 0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2z\"/>" },
    "issue-opened": { width: 14,
        height: 16,
        path: "<path fill-rule=\"evenodd\" d=\"M7 2.3c3.14 0 5.7 2.56 5.7 5.7s-2.56 5.7-5.7 5.7A5.71 5.71 0 0 1 1.3 8c0-3.14 2.56-5.7 5.7-5.7zM7 1C3.14 1 0 4.14 0 8s3.14 7 7 7 7-3.14 7-7-3.14-7-7-7zm1 3H6v5h2V4zm0 6H6v2h2v-2z\"/>" },
    "cloud-download": { width: 16,
        height: 16,
        path: "<path fill-rule=\"evenodd\" d=\"M9 12h2l-3 3-3-3h2V7h2v5zm3-8c0-.44-.91-3-4.5-3C5.08 1 3 2.92 3 5 1.02 5 0 6.52 0 8c0 1.53 1 3 3 3h3V9.7H3C1.38 9.7 1.3 8.28 1.3 8c0-.17.05-1.7 1.7-1.7h1.3V5c0-1.39 1.56-2.7 3.2-2.7 2.55 0 3.13 1.55 3.2 1.8v1.2H12c.81 0 2.7.22 2.7 2.2 0 2.09-2.25 2.2-2.7 2.2h-2V11h2c2.08 0 4-1.16 4-3.5C16 5.06 14.08 4 12 4z\"/>" } }; p = function(t, e) {
        return t = ("" + t).toLowerCase().replace(/^octicon-/, ""), b.hasOwnProperty(t) || (t = "mark-github"), "<svg version=\"1.1\" width=\"" + e * b[t].width / b[t].height + "\" height=\"" + e + "\" viewBox=\"0 0 " + b[t].width + " " + b[t].height + "\" class=\"octicon octicon-" + t + "\" aria-hidden=\"true\">" + b[t].path + "</svg>";
    }, f = function(t) {
        var e, n; return (e = c("a")).href = t.href, (/\.github\.com$/).test("." + e.hostname) ? (/^https?:\/\/((gist\.)?github\.com\/[^\/?#]+\/[^\/?#]+\/archive\/|github\.com\/[^\/?#]+\/[^\/?#]+\/releases\/download\/|codeload\.github\.com\/)/).test(e.href) && (e.target = "_top") : (e.href = "#", e.target = "_self"), e.className = "btn", (n = t["aria-label"]) && e.setAttribute("aria-label", n), e.innerHTML = p(t["data-icon"], (/^large$/i).test(t["data-size"]) ? 16 : 14), e.appendChild(d(" ")), e.appendChild(c("span")).appendChild(d(t["data-text"] || "")), o.body.appendChild(e);
    }, g = function(t, e) {
        var n, a, i, r, l, d; window.$ = function() {
            window.$ = null;
        }, i = 0, n = function() {
            !i && (i = 1) && (e(...arguments), $());
        }, window.XMLHttpRequest && "withCredentials" in XMLHttpRequest.prototype ? (d = new XMLHttpRequest(), s(d, "abort", n), s(d, "error", n), s(d, "load", function() {
            n(d.status !== 200, JSON.parse(d.responseText));
        }), d.open("GET", t), d.send()) : (window._ = function(t) {
            window._ = null, n(t.meta.status !== 200, t.data);
        }, (l = c("script")).async = !0, l.src = t + (/\?/.test(t) ? "&" : "?") + "callback=_", s(l, "error", r = function() {
                window._ && _({ meta: {} });
            }), l.readyState && s(l, "readystatechange", function() {
                l.readyState === "loaded" && r();
            }), a = o.getElementsByTagName("head")[0], {}.toString.call(window.opera) === "[object Opera]" ? u(function() {
                a.appendChild(l);
            }) : a.appendChild(l));
    }, m = function(t) {
        var e, n, a, o; t.hostname === "github.com" && (a = t.pathname.replace(/^(?!\/)/, "/").match(/^\/([^\/?#]+)(?:\/([^\/?#]+)(?:\/(?:(subscription)|(fork)|(issues)|([^\/?#]+)))?)?(?:[\/?#]|$)/)) && !a[6] && (a[2] ? (e = "repos/" + a[1] + "/" + a[2], a[3] ? (o = "subscribers_count", n = "watchers") : a[4] ? (o = "forks_count", n = "network") : a[5] ? (o = "open_issues_count", n = "issues") : (o = "stargazers_count", n = "stargazers")) : (e = "users/" + a[1], n = o = "followers"), g("https://api.github.com/" + e, function(e, a) {
            var i, r; e || (r = a[o], (i = c("a")).href = a.html_url + "/" + n, i.className = "social-count", i.setAttribute("aria-label", r + " " + o.replace(/_count$/, "").replace("_", " ") + " on GitHub"), i.appendChild(c("b")), i.appendChild(c("i")), i.appendChild(c("span")).appendChild(d(("" + r).replace(/\B(?=(\d{3})+(?!\d))/g, ","))), t.parentNode.insertBefore(i, t.nextSibling));
        }));
    }, w = function(t) {
        var e; t && (/^large$/i.test(t["data-size"]) && (o.body.className = "large"), e = f(t), (/^(true|1)$/i).test(t["data-show-count"]) && m(e));
    }; var v, y, C, z, x, E; y = window.devicePixelRatio || 1, v = function(t) {
        return (y > 1 ? l.ceil(l.round(t * y) / y * 2) / 2 : l.ceil(t)) || 0;
    }, C = function(t) {
        var e, n, a, o, i, r, c; return r = (a = t.contentWindow.document).documentElement, e = a.body, c = r.scrollWidth, i = r.scrollHeight, e.getBoundingClientRect && (o = e.style.display, e.style.display = "inline-block", n = e.getBoundingClientRect(), c = l.max(c, v(n.width || n.right - n.left)), i = l.max(i, v(n.height || n.bottom - n.top)), e.style.display = o), [c, i];
    }, z = function(t, e) {
        t.style.width = e[0] + "px", t.style.height = e[1] + "px";
    }, x = function() {
        var t, e, n, a, i, r, l; if (e = [], o.querySelectorAll)e = o.querySelectorAll("a.github-button"); else for (n = 0, i = (l = o.getElementsByTagName("a")).length; n < i; n++)~(" " + (t = l[n]).className + " ").replace(/[ \t\n\f\r]+/g, " ").indexOf(" github-button ") && e.push(t); for (a = 0, r = e.length; a < r; a++)t = e[a], E(t);
    }, E = function(e, a) {
        var r, l, d, s, u, p, f, g; if (e == null) return x(); for (s in a == null && (a = (function(t) {
            var e, n, a, o, i, r; for (i = { href: t.href,
                title: t.title,
                "aria-label": t.getAttribute("aria-label") }, a = 0, o = (r = ["icon", "text", "size", "show-count"]).length; a < o; a++)i[e = "data-" + (e = r[a])] = t.getAttribute(e); return i["data-text"] == null && (i["data-text"] = t.textContent || t.innerText), (n = function(e, n, a) {
                t.getAttribute(e) && (i[n] = a, window.console && console.warn("GitHub Buttons deprecated `" + e + "`: use `" + n + "=\"" + a + "\"` instead. Please refer to https://github.com/ntkme/github-buttons#readme for more info."));
            })("data-count-api", "data-show-count", "true"), n("data-style", "data-size", "large"), i;
        }(e))), l = "#" + (function(t) {
                var e, n, a; for (e in n = [], t)(a = t[e]) != null && n.push(i(e) + "=" + i(a)); return n.join("&");
            }(a)), d = c("iframe"), p = { allowtransparency: !0,
                scrolling: "no",
                frameBorder: 0 })g = p[s], d.setAttribute(s, g); z(d, [1, 0]), d.style.border = "none", d.src = "javascript:0", (f = a.title) && (d.title = f), o.body.appendChild(d), u = function() {
            var n; n = C(d), d.parentNode.removeChild(d), h(d, "load", function() {
                z(d, n);
            }), d.src = t + "buttons.html" + l, e.parentNode.replaceChild(d, e);
        }, h(d, "load", function() {
            var t; (t = d.contentWindow).$ ? t.$ = u : u();
        }), (r = d.contentWindow.document).open().write("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>" + n + "</title><link rel=\"stylesheet\" href=\"" + t + "assets/css/buttons.css\"><script>document.location.hash = \"" + l + "\";<\/script></head><body><script src=\"" + t + "buttons.js\"><\/script></body></html>"), r.close();
    }, typeof define == "function" && define.amd ? define([], { render: E }) : typeof exports == "object" && typeof exports.nodeName != "string" ? exports.render = E : (a && e(a.replace(/[^\/]*([?#].*)?$/, "")), o.title === n ? w(function(t) {
        var e, n, a, o, i, l; for (o = {}, e = 0, n = (l = t.split("&")).length; e < n; e++)(a = l[e]) !== "" && (i = a.split("="))[0] !== "" && (o[r(i[0])] = r(i.slice(1).join("="))); return o;
    }(o.location.hash.replace(/^#/, ""))) : u(x));
}());
