// ── Client-side web scraper (no backend required) ──────────────────────────
// Uses codetabs.com CORS proxy to fetch pages, then parses everything in-browser.

// Returns raw HTML directly (no JSON wrapper)
const PROXY_CODETABS  = 'https://api.codetabs.com/v1/proxy?quest=';
// Returns JSON: { contents, status: { http_code } }
const PROXY_ALLORIGINS = 'https://api.allorigins.win/get?url=';

// ── Fetch ──────────────────────────────────────────────────────────────────
async function fetchViaProxy(url) {
  // Primary: codetabs — returns raw HTML
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 25000);
    const res = await fetch(`${PROXY_CODETABS}${encodeURIComponent(url)}`, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`codetabs ${res.status}`);
    const html = await res.text();
    if (!html || html.length < 50) throw new Error('Empty response from codetabs');
    return { html, status: res.status };
  } catch (e1) {
    console.warn('codetabs proxy failed:', e1.message, '— trying allorigins fallback');
  }

  // Fallback: allorigins — returns JSON { contents }
  try {
    const controller2 = new AbortController();
    const timer2 = setTimeout(() => controller2.abort(), 25000);
    const res2 = await fetch(`${PROXY_ALLORIGINS}${encodeURIComponent(url)}`, { signal: controller2.signal });
    clearTimeout(timer2);
    if (!res2.ok) throw new Error(`allorigins ${res2.status}`);
    const json = await res2.json();
    if (!json.contents) throw new Error('Empty contents from allorigins');
    return { html: json.contents, status: json.status?.http_code || 200 };
  } catch (e2) {
    throw new Error(`All proxies failed. Last error: ${e2.message}`);
  }
}

function parseHTML(html, baseUrl) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const existing = doc.querySelector('base');
  if (!existing) {
    const base = doc.createElement('base');
    base.href = baseUrl;
    doc.head.prepend(base);
  }
  return doc;
}

function resolveUrl(href, base) {
  try { return new URL(href, base).href; } catch { return href; }
}

// ── Content Extraction ─────────────────────────────────────────────────────
function extractMetaTags(doc) {
  const tags = {};
  doc.querySelectorAll('meta').forEach(m => {
    const name = m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv');
    const content = m.getAttribute('content');
    if (name && content) tags[name] = content;
  });
  return tags;
}

function extractHeadings(doc) {
  const out = [];
  doc.querySelectorAll('h1,h2,h3,h4,h5,h6').forEach(h => {
    const text = h.textContent?.trim();
    if (text) out.push({ level: parseInt(h.tagName[1]), text: text.slice(0, 200) });
  });
  return out;
}

function extractParagraphs(doc) {
  const out = [];
  doc.querySelectorAll('p').forEach(p => {
    const text = p.textContent?.trim();
    if (text && text.length > 10) out.push(text.slice(0, 1000));
  });
  return out;
}

function extractLinks(doc, baseUrl) {
  return [...doc.querySelectorAll('a[href]')].reduce((acc, a) => {
    const href = a.getAttribute('href');
    // eslint-disable-next-line no-script-url
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return acc;
    acc.push({ text: (a.textContent?.trim() || '').slice(0, 100), url: resolveUrl(href, baseUrl) });
    return acc;
  }, []);
}

function extractImages(doc, baseUrl) {
  return [...doc.querySelectorAll('img')].reduce((acc, img) => {
    const src = img.getAttribute('src') || img.getAttribute('data-src') || img.getAttribute('data-lazy-src');
    if (src) acc.push({ src: resolveUrl(src, baseUrl), alt: img.getAttribute('alt') || '' });
    return acc;
  }, []);
}

function extractTables(doc) {
  return [...doc.querySelectorAll('table')].reduce((acc, table) => {
    const rows = [...table.querySelectorAll('tr')].map(tr =>
      [...tr.querySelectorAll('td,th')].map(c => c.textContent?.trim() || '')
    ).filter(r => r.length);
    if (rows.length) acc.push(rows);
    return acc;
  }, []);
}

function extractLists(doc) {
  const ul = [], ol = [];
  doc.querySelectorAll('ul').forEach(list => {
    const items = [...list.querySelectorAll(':scope > li')].map(li => li.textContent?.trim()).filter(Boolean);
    if (items.length) ul.push(items);
  });
  doc.querySelectorAll('ol').forEach(list => {
    const items = [...list.querySelectorAll(':scope > li')].map(li => li.textContent?.trim()).filter(Boolean);
    if (items.length) ol.push(items);
  });
  return { ul, ol };
}

function extractAllText(doc) {
  const clone = doc.body?.cloneNode(true);
  if (!clone) return '';
  clone.querySelectorAll('script,style,noscript').forEach(el => el.remove());
  return clone.textContent?.replace(/\s+/g, ' ').trim().slice(0, 50000) || '';
}

// ── SEO Analysis ───────────────────────────────────────────────────────────
function analyzeSEO(doc, url) {
  const title = doc.title?.trim() || '';
  const description = doc.querySelector('meta[name="description"]')?.getAttribute('content') || '';
  const h1s = [...doc.querySelectorAll('h1')];
  const images = [...doc.querySelectorAll('img')];
  const canonical = doc.querySelector('link[rel="canonical"]')?.getAttribute('href') || '';

  const og = {};
  doc.querySelectorAll('meta[property^="og:"]').forEach(m =>
    (og[m.getAttribute('property').replace('og:', '')] = m.getAttribute('content'))
  );
  const twitter = {};
  doc.querySelectorAll('meta[name^="twitter:"]').forEach(m =>
    (twitter[m.getAttribute('name').replace('twitter:', '')] = m.getAttribute('content'))
  );

  const imgsMissingAlt = images.filter(i => !i.getAttribute('alt')).length;
  const titleOk = title.length >= 10 && title.length <= 60;
  const descOk = description.length >= 50 && description.length <= 160;
  const h1Ok = h1s.length === 1;

  let score = 100;
  if (!titleOk) score -= 20;
  if (!descOk) score -= 20;
  if (!h1Ok) score -= 15;
  if (imgsMissingAlt > 0) score -= Math.min(15, imgsMissingAlt * 3);
  if (!canonical) score -= 10;
  if (!og.title) score -= 10;
  if (!twitter.card) score -= 5;

  return {
    score: Math.max(0, score),
    title, title_length: title.length, title_ok: titleOk,
    description, description_length: description.length, description_ok: descOk,
    h1_count: h1s.length, h1_ok: h1Ok,
    h1_texts: h1s.map(h => h.textContent?.trim()).slice(0, 3),
    images_missing_alt: imgsMissingAlt, images_total: images.length,
    canonical, og, twitter,
    broken_links: [], links_checked: 0,
  };
}

// ── Tech Stack Detection ───────────────────────────────────────────────────
function detectTechStack(html, doc) {
  const h = html.toLowerCase();
  const generator = doc.querySelector('meta[name="generator"]')?.getAttribute('content') || '';
  const gen = generator.toLowerCase();

  // Collect actual asset URLs (script src + link href) — much more reliable than raw HTML text
  const assetUrls = [
    ...[...doc.querySelectorAll('script[src]')].map(s => (s.getAttribute('src') || '').toLowerCase()),
    ...[...doc.querySelectorAll('link[href]')].map(l => (l.getAttribute('href') || '').toLowerCase()),
  ].join(' ');

  let platform = null, cms_version = null;

  // 1. Generator meta tag — most authoritative
  if (gen.includes('wordpress')) {
    platform = 'WordPress';
    const v = generator.match(/wordpress\s+([\d.]+)/i);
    if (v) cms_version = v[1];
  } else if (gen.includes('joomla'))      { platform = 'Joomla'; }
  else if (gen.includes('drupal'))        { platform = 'Drupal'; }
  else if (gen.includes('ghost'))         { platform = 'Ghost'; }
  else if (gen.includes('squarespace'))   { platform = 'Squarespace'; }
  else if (gen.includes('wix'))           { platform = 'Wix'; }

  // 2. Asset URL fingerprints (use actual file paths, not text mentions)
  if (!platform) {
    if (assetUrls.includes('/_next/static/') || h.includes('__next_data__') || h.includes('id="__next"') || h.includes("id='__next'")) {
      platform = 'Next.js';
    } else if (assetUrls.includes('/_nuxt/') || h.includes('window.__nuxt') || h.includes('window.__nuxt_')) {
      platform = 'Nuxt.js';
    } else if (assetUrls.includes('/wp-content/') || assetUrls.includes('/wp-includes/')) {
      platform = 'WordPress';
    } else if (assetUrls.includes('cdn.shopify.com') || assetUrls.includes('cdn.shopifycdn.com')) {
      platform = 'Shopify';
    } else if (assetUrls.includes('static1.squarespace.com') || assetUrls.includes('squarespace-cdn.com') || assetUrls.includes('.squarespace.com')) {
      platform = 'Squarespace';
    } else if (assetUrls.includes('static.wixstatic.com') || assetUrls.includes('wixstatic.com')) {
      platform = 'Wix';
    } else if (assetUrls.includes('webflow.io') || (h.includes('data-wf-page') && h.includes('data-wf-site'))) {
      platform = 'Webflow';
    } else if (h.includes('___gatsby') || assetUrls.includes('/page-data/')) {
      platform = 'Gatsby';
    } else if (h.includes('/components/com_') || h.includes('joomla!')) {
      platform = 'Joomla';
    } else if (h.includes('drupalsettings') || h.includes('drupal.settings')) {
      platform = 'Drupal';
    } else if (assetUrls.includes('ghost.io') || (h.includes('ghost') && h.includes('casper'))) {
      platform = 'Ghost';
    } else if (h.includes('mage/') || assetUrls.includes('magento')) {
      platform = 'Magento';
    } else if (assetUrls.includes('bigcommerce.com') || h.includes('bigcommerce')) {
      platform = 'BigCommerce';
    }
  }

  // 3. Framework detection — use asset URLs + reliable inline markers
  const inAssets = (p) => assetUrls.includes(p);
  const inHtml   = (p) => h.includes(p);

  const detect = (map) => Object.entries(map)
    .filter(([, patterns]) => patterns.some(p => inAssets(p) || inHtml(p)))
    .map(([name]) => name);

  const frameworks = detect({
    'Next.js':     ['/_next/static/', '__next_data__', 'id="__next"'],
    'Nuxt.js':     ['/_nuxt/', 'window.__nuxt'],
    'Gatsby':      ['___gatsby', '/page-data/'],
    'React':       ['__reactfiber', '__reactroot', 'data-reactroot', 'react-dom.production', 'react-dom.development'],
    'Vue.js':      ['__vue_app__', 'data-v-app', 'vue.runtime.esm', 'vue.esm-browser'],
    'Angular':     ['ng-version=', 'ng-app=', 'angular.min.js', 'angular/core'],
    'Svelte':      ['__svelte', 'svelte/internal'],
    'Remix':       ['__remixContext', '__remixManifest'],
    'Astro':       ['astro-island', 'data-astro-cid'],
    'Bootstrap':   ['bootstrap.min.css', 'bootstrap.bundle.min.js', 'bootstrap.min.js'],
    'Tailwind CSS':['tailwind'],
    'Foundation':  ['foundation.min.css', 'foundation.min.js'],
  });

  const js_libraries = detect({
    'jQuery': ['jquery.min', 'jquery.js'],
    'Lodash': ['lodash.min', 'lodash.js'],
    'Moment.js': ['moment.min', 'moment.js'],
    'Axios': ['axios.min'],
    'Three.js': ['three.min', 'three.js'],
    'D3.js': ['d3.min', 'd3.js'],
    'GSAP': ['gsap', 'tweenmax'],
    'Swiper': ['swiper.min', 'swiper.js'],
    'Slick Carousel': ['slick.min', 'slick-carousel'],
    'Chart.js': ['chart.min', 'chart.js'],
  });

  const analytics = detect({
    'Google Analytics': ['google-analytics.com', 'gtag(', 'analytics.js', 'ga.js'],
    'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
    'Hotjar': ['hotjar.com', 'hjsv'],
    'Mixpanel': ['mixpanel.com'],
    'Microsoft Clarity': ['clarity.ms'],
    'Heap': ['heapanalytics.com'],
    'FullStory': ['fullstory.com'],
    'Amplitude': ['amplitude.com'],
    'Segment': ['segment.com'],
  });

  const payment = detect({
    'Stripe': ['stripe.com/v3', 'stripe.js'],
    'PayPal': ['paypal.com', 'paypalobjects.com'],
    'Braintree': ['braintree-api.com'],
    'Square': ['squareup.com'],
    'Razorpay': ['razorpay.com'],
    'Klarna': ['klarna.com'],
  });

  const email_marketing = detect({
    'Mailchimp': ['mailchimp.com', 'mc.us'],
    'Klaviyo': ['klaviyo.com'],
    'HubSpot': ['hs-scripts.com', 'hubspot.com'],
    'Marketo': ['marketo.net'],
    'ConvertKit': ['convertkit.com'],
    'ActiveCampaign': ['activecampaign.com'],
    'MailerLite': ['mailerlite.com'],
  });

  const security_tools = detect({
    'Cloudflare': ['cloudflare.com', '__cf_bm', 'cf-ray'],
    'reCAPTCHA': ['recaptcha.net', 'recaptcha/api'],
    'hCaptcha': ['hcaptcha.com'],
    'Sucuri': ['sucuri.net'],
    'Wordfence': ['wordfence'],
    'Imperva': ['imperva.com', 'incapsula.com'],
  });

  const fonts = detect({
    'Google Fonts': ['fonts.googleapis.com'],
    'Adobe Fonts': ['use.typekit.net'],
    'Font Awesome': ['font-awesome', 'fontawesome'],
    'Bunny Fonts': ['fonts.bunny.net'],
  });

  let cdn = null;
  if (assetUrls.includes('cloudflare') || h.includes('cf-ray') || h.includes('__cf_bm')) cdn = 'Cloudflare';
  else if (assetUrls.includes('fastly.net')) cdn = 'Fastly';
  else if (assetUrls.includes('cloudfront.net')) cdn = 'CloudFront';
  else if (assetUrls.includes('akamaized.net') || assetUrls.includes('akamai')) cdn = 'Akamai';
  else if (assetUrls.includes('b-cdn.net')) cdn = 'BunnyCDN';
  else if (assetUrls.includes('vercel-insights') || assetUrls.includes('vercel.app') || h.includes('x-vercel-id')) cdn = 'Vercel';

  return { platform, cms_version, frameworks, js_libraries, analytics, payment, email_marketing, security_tools, fonts, cdn, error: null };
}

// ── Social Media ───────────────────────────────────────────────────────────
function detectSocialMedia(html, doc) {
  const allLinks = [...doc.querySelectorAll('a[href]')].map(a => a.getAttribute('href') || '');
  const combined = html + ' ' + allLinks.join(' ');
  const social = {};
  const patterns = {
    facebook: /(?:https?:\/\/)?(?:www\.)?facebook\.com\/(?!sharer|share|plugins|login)([\w.-]+)/i,
    instagram: /(?:https?:\/\/)?(?:www\.)?instagram\.com\/([\w.-]+)/i,
    linkedin: /(?:https?:\/\/)?(?:www\.)?linkedin\.com\/(?:company|in|school)\/([\w.-]+)/i,
    twitter: /(?:https?:\/\/)?(?:www\.)?(?:twitter|x)\.com\/([\w.-]+)/i,
    youtube: /(?:https?:\/\/)?(?:www\.)?youtube\.com\/(?:channel|c|user|@)([\w.-]+)/i,
    tiktok: /(?:https?:\/\/)?(?:www\.)?tiktok\.com\/@([\w.-]+)/i,
    pinterest: /(?:https?:\/\/)?(?:www\.)?pinterest\.com\/([\w.-]+)/i,
    github: /(?:https?:\/\/)?(?:www\.)?github\.com\/([\w.-]+)/i,
  };
  for (const [platform, pat] of Object.entries(patterns)) {
    const m = combined.match(pat);
    if (m) social[platform] = m[0].startsWith('http') ? m[0] : 'https://' + m[0];
  }
  return social;
}

// ── Vulnerability Analysis (client-side) ──────────────────────────────────
function analyzeVulnerabilities(doc, html, url) {
  const vulns = [];
  const isHttps = url.startsWith('https://');

  if (!isHttps) {
    vulns.push({ type: 'No HTTPS', severity: 'Critical', description: 'Website is not using HTTPS encryption', damage: 'All traffic is unencrypted. Passwords, form data, and sessions can be intercepted by attackers.' });
  } else {
    const httpResources = [...doc.querySelectorAll('[src],[href]')]
      .map(el => el.getAttribute('src') || el.getAttribute('href'))
      .filter(s => s && s.startsWith('http://'));
    if (httpResources.length > 0) {
      vulns.push({ type: 'Mixed Content', severity: 'High', description: `${httpResources.length} HTTP resource(s) loaded on HTTPS page`, damage: 'HTTP resources on HTTPS pages can be intercepted and modified by attackers, breaking the security of the page.' });
    }
  }

  const inlineScripts = [...doc.querySelectorAll('script:not([src])')].map(s => s.textContent);
  if (inlineScripts.some(s => s.includes('eval(') || s.includes('document.write('))) {
    vulns.push({ type: 'Dangerous JavaScript', severity: 'Medium', description: 'Page uses eval() or document.write() — can be exploited for XSS if user input reaches these calls', damage: 'Attackers may inject malicious code if user-supplied input is not sanitised before reaching these functions.' });
  }

  doc.querySelectorAll('form').forEach(form => {
    const method = (form.getAttribute('method') || 'get').toLowerCase();
    const hasPassword = form.querySelector('input[type="password"]');
    const hasToken = form.querySelector('input[name*="csrf"], input[name*="token"], input[name*="_token"], input[name*="nonce"]');
    if (hasPassword && method === 'get') {
      vulns.push({ type: 'Password in GET Request', severity: 'Critical', description: 'Login form submits password via GET — passwords appear in URLs and server logs', damage: 'Passwords exposed in browser history, server logs, and HTTP referrer headers.' });
    }
    if (method === 'post' && !hasToken) {
      vulns.push({ type: 'Missing CSRF Protection', severity: 'Medium', description: 'POST form detected without a visible CSRF token', damage: 'Attackers can trick authenticated users into submitting forged requests.' });
    }
  });

  const externalIframes = [...doc.querySelectorAll('iframe[src]')].filter(f => {
    try { return new URL(f.getAttribute('src')).hostname !== new URL(url).hostname; } catch { return false; }
  });
  if (externalIframes.length > 0) {
    vulns.push({ type: 'External iFrames', severity: 'Low', description: `${externalIframes.length} external iframe(s) detected`, damage: 'External iframes can load malicious content or be used for clickjacking attacks.' });
  }

  vulns.push({ type: 'Security Headers Not Checked', severity: 'Medium', description: 'Response headers (HSTS, CSP, X-Frame-Options, etc.) require server-side analysis — use securityheaders.com for a full header scan', damage: 'Missing security headers can expose users to XSS, clickjacking, and downgrade attacks.' });

  const severityScore = { Critical: 30, High: 20, Medium: 10, Low: 5 };
  const summary = { total: vulns.length, critical: 0, high: 0, medium: 0, low: 0, risk_score: 0 };
  vulns.forEach(v => {
    summary.risk_score += severityScore[v.severity] || 0;
    summary[v.severity.toLowerCase()]++;
  });
  summary.risk_score = Math.min(100, summary.risk_score);

  return { vulnerabilities: vulns, summary };
}

// ── Pages / Sitemap ────────────────────────────────────────────────────────
async function getPages(url, doc) {
  try {
    const parsed = new URL(url);
    const base = `${parsed.protocol}//${parsed.hostname}`;
    let pageUrls = [], sitemapFound = false;

    const sparser = new DOMParser();
    const fetchSitemap = async (sitemapUrl, depth = 0) => {
      if (depth > 2) return [];
      try {
        const res = await fetch(`${PROXY_CODETABS}${encodeURIComponent(sitemapUrl)}`);
        if (!res.ok) return [];
        const content = await res.text();
        if (!content.includes('<loc>')) return [];
        const xml = sparser.parseFromString(content, 'text/xml');
        const locs = [...xml.querySelectorAll('loc')].map(l => l.textContent?.trim()).filter(Boolean);
        const urls = [];
        for (const loc of locs) {
          if (loc.endsWith('.xml')) {
            const sub = await fetchSitemap(loc, depth + 1);
            urls.push(...sub);
          } else {
            urls.push(loc);
          }
        }
        return urls;
      } catch { return []; }
    };

    for (const path of ['/sitemap.xml', '/sitemap_index.xml']) {
      const urls = await fetchSitemap(base + path);
      if (urls.length > 0) { sitemapFound = true; pageUrls = urls.slice(0, 50); break; }
    }

    if (!sitemapFound) {
      const seen = new Set();
      doc.querySelectorAll('a[href]').forEach(a => {
        const href = a.getAttribute('href');
        if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.endsWith('.xml')) return;
        try {
          const full = new URL(href, url).href;
          if (new URL(full).hostname === parsed.hostname && !seen.has(full)) {
            seen.add(full); pageUrls.push(full);
          }
        } catch {}
        if (pageUrls.length >= 50) return;
      });
    }

    const pages = [...new Set(pageUrls)].map(u => ({ url: u, status: 200, title: '', word_count: 0 }));
    return { total: pages.length, sitemap_found: sitemapFound, pages, error: null };
  } catch (e) {
    return { total: 0, sitemap_found: false, pages: [], error: e.message };
  }
}

// ── Services & Functionality ───────────────────────────────────────────────
function analyzeServicesFunctionality(doc, html) {
  const nav = [...doc.querySelectorAll('a,h1,h2,h3,nav,button')].map(el => el.textContent).join(' ');
  const combined = (html + ' ' + nav).toLowerCase();
  const hits = kws => kws.filter(k => combined.includes(k)).length;

  const categories = [
    { name: 'E-Commerce & Online Store', icon: '🛒', keywords: ['shop','cart','checkout','product','buy now','add to cart','wishlist','order','shipping','payment','store'] },
    { name: 'SaaS / Software Platform', icon: '💻', keywords: ['dashboard','saas','subscription','free trial','api','integration','pricing plan','workspace','workflow','automation'] },
    { name: 'Healthcare & Medical', icon: '🏥', keywords: ['appointment','doctor','patient','clinic','hospital','medical','health','telemedicine','prescription','therapy'] },
    { name: 'Education & E-Learning', icon: '🎓', keywords: ['course','lesson','tutorial','learn','student','enroll','certificate','quiz','instructor','curriculum','training'] },
    { name: 'Finance & Banking', icon: '💰', keywords: ['loan','investment','banking','insurance','trading','portfolio','fintech','crypto','wallet','mortgage'] },
    { name: 'Real Estate & Property', icon: '🏠', keywords: ['property','listing','rent','lease','mortgage','agent','bedroom','bathroom','square feet','realtor'] },
    { name: 'Marketing & Agency', icon: '📣', keywords: ['seo','branding','campaign','digital marketing','ppc','content marketing','social media management','creative agency'] },
    { name: 'Restaurant & Food', icon: '🍽️', keywords: ['menu','reservation','delivery','order food','cuisine','chef','dining','catering','takeaway','recipe'] },
    { name: 'Legal & Law Services', icon: '⚖️', keywords: ['attorney','lawyer','law firm','legal advice','litigation','counsel','practice area','case','settlement'] },
    { name: 'News & Media', icon: '📰', keywords: ['latest news','breaking','article','editorial','journalist','subscribe','newsletter','magazine','podcast'] },
    { name: 'Travel & Tourism', icon: '✈️', keywords: ['book a trip','hotel','flight','tour','itinerary','destination','travel','vacation','package','accommodation'] },
    { name: 'Technology & IT Services', icon: '🔧', keywords: ['cloud','devops','it support','managed service','infrastructure','cybersecurity','software development','consulting'] },
    { name: 'Creative & Design', icon: '🎨', keywords: ['portfolio','design','branding','illustration','photography','video production','animation','creative'] },
    { name: 'Non-Profit & Charity', icon: '❤️', keywords: ['donate','volunteer','charity','mission','non-profit','foundation','cause','fundraise'] },
    { name: 'Fitness & Wellness', icon: '💪', keywords: ['gym','fitness','workout','yoga','nutrition','personal trainer','wellness','weight loss','exercise'] },
    { name: 'Recruitment & HR', icon: '👔', keywords: ['job','career','hiring','recruiter','resume','talent','hr','vacancy','apply now','position'] },
  ];

  const functionalityChecks = [
    { name: 'User Authentication', icon: '🔐', keywords: ['login','sign in','sign up','register','create account','forgot password','my account'] },
    { name: 'Payment Processing', icon: '💳', keywords: ['checkout','buy now','add to cart','stripe','paypal','credit card','secure payment'] },
    { name: 'Search & Filtering', icon: '🔍', keywords: ['search','filter','sort by','results','find','browse'] },
    { name: 'Booking & Scheduling', icon: '📅', keywords: ['book','schedule','appointment','calendar','availability','reserve','slot'] },
    { name: 'Contact & Lead Forms', icon: '📬', keywords: ['contact us','get in touch','send message','inquiry','request a quote','contact form'] },
    { name: 'Blog & Content Hub', icon: '✍️', keywords: ['blog','articles','posts','read more','categories','tags','author','published'] },
    { name: 'Portfolio & Gallery', icon: '🖼️', keywords: ['gallery','portfolio','our work','case study','showcase','projects'] },
    { name: 'Video & Media', icon: '▶️', keywords: ['watch','video','stream','youtube','vimeo','play','episode','webinar'] },
    { name: 'Live Chat & Support', icon: '💬', keywords: ['live chat','support','helpdesk','intercom','zendesk','chat with us'] },
    { name: 'Reviews & Testimonials', icon: '⭐', keywords: ['review','testimonial','rating','stars','customer says','feedback'] },
    { name: 'Newsletter / Email List', icon: '📧', keywords: ['subscribe','newsletter','email list','stay updated','get notified'] },
    { name: 'Maps & Location', icon: '📍', keywords: ['find us','directions','map','google map','address','location','store locator'] },
    { name: 'Mobile App', icon: '📱', keywords: ['app store','google play','download app','ios','android','mobile app'] },
    { name: 'API & Integrations', icon: '🔗', keywords: ['api','webhook','integration','sdk','developer','rest api','documentation'] },
    { name: 'Analytics & Reporting', icon: '📊', keywords: ['analytics','dashboard','report','metrics','kpi','insights'] },
    { name: 'Membership & Community', icon: '👥', keywords: ['member','community','forum','discussion','group','network','join us'] },
    { name: 'Multi-language Support', icon: '🌐', keywords: ['language','translation','español','français','deutsch','中文'] },
    { name: 'Affiliate / Referral', icon: '🤝', keywords: ['affiliate','referral','partner','commission','earn','reseller'] },
  ];

  const detectedCats = categories
    .map(c => ({ ...c, score: hits(c.keywords) }))
    .filter(c => c.score >= 2)
    .sort((a, b) => b.score - a.score)
    .slice(0, 6);

  return {
    primary_service: detectedCats[0]?.name || 'General Website',
    service_categories: detectedCats,
    functionality: functionalityChecks.filter(f => hits(f.keywords) >= 1),
  };
}

// ── Hosting Info (ip-api.com — free, no key) ───────────────────────────────
async function getHostingInfo(url) {
  try {
    const hostname = new URL(url).hostname;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(`https://ip-api.com/json/${hostname}?fields=status,country,city,isp,org,query`, { signal: controller.signal });
    clearTimeout(timer);
    const json = await res.json();
    if (json.status !== 'success') throw new Error('Lookup failed');
    return { ip_address: json.query, provider: json.isp || json.org, city: json.city, country: json.country, server_software: null, cdn: null, error: null };
  } catch (e) {
    return { ip_address: null, provider: null, city: null, country: null, server_software: null, cdn: null, error: e.message };
  }
}

// ── Domain Info (RDAP — free, no key) ─────────────────────────────────────
async function getDomainInfo(url) {
  try {
    const hostname = new URL(url).hostname.replace(/^www\./, '');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(`https://rdap.org/domain/${hostname}`, { signal: controller.signal });
    clearTimeout(timer);
    const json = await res.json();
    const regDate = json.events?.find(e => e.eventAction === 'registration')?.eventDate;
    const expDate = json.events?.find(e => e.eventAction === 'expiration')?.eventDate;
    const registrar = json.entities?.find(e => e.roles?.includes('registrar'))
      ?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3];
    let daysUntilExpiry = null, expFormatted = null;
    if (expDate) {
      const exp = new Date(expDate);
      expFormatted = exp.toISOString().split('T')[0];
      daysUntilExpiry = Math.floor((exp - Date.now()) / 86400000);
    }
    return {
      registration_date: regDate ? new Date(regDate).toISOString().split('T')[0] : null,
      expiry_date: expFormatted, days_until_expiry: daysUntilExpiry,
      registrar: registrar || null, owner: null, country: null, error: null,
    };
  } catch (e) {
    return { registration_date: null, expiry_date: null, days_until_expiry: null, registrar: null, owner: null, country: null, error: e.message };
  }
}

// ── SSL Info (browser-level check) ────────────────────────────────────────
function getSSLInfo(url) {
  const valid = url.startsWith('https://');
  return {
    valid, issuer: valid ? 'Valid (HTTPS confirmed)' : null,
    cert_type: valid ? 'HTTPS' : null,
    issued_date: null, expiry_date: null, days_remaining: null,
    warning: null, error: valid ? null : 'Site does not use HTTPS',
  };
}

// ── Business Profile ───────────────────────────────────────────────────────
function detectBusinessProfile(doc, html, url) {
  const text = (html + ' ' + (doc.body?.textContent || '')).toLowerCase();
  const niches = [
    { name: 'E-commerce', kws: ['shop','buy','cart','product','order'] },
    { name: 'SaaS', kws: ['dashboard','saas','subscription','api','integration'] },
    { name: 'Blog / Media', kws: ['blog','article','news','post','read more'] },
    { name: 'Restaurant / Food', kws: ['menu','restaurant','order food','delivery','cuisine'] },
    { name: 'Healthcare', kws: ['doctor','patient','clinic','health','medical'] },
    { name: 'Education', kws: ['course','learn','student','enroll','training'] },
    { name: 'Real Estate', kws: ['property','listing','rent','lease','mortgage'] },
    { name: 'Agency / Portfolio', kws: ['portfolio','our work','case study','client','agency'] },
    { name: 'Finance', kws: ['loan','investment','finance','banking','insurance'] },
    { name: 'Legal', kws: ['attorney','lawyer','legal','law firm','counsel'] },
    { name: 'Non-profit', kws: ['donate','volunteer','charity','non-profit','mission'] },
  ];
  let niche = 'General', max = 0;
  for (const n of niches) {
    const s = n.kws.filter(k => text.includes(k)).length;
    if (s > max) { max = s; niche = n.name; }
  }
  const emails = [...new Set((html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])
    .filter(e => !e.includes('.png') && !e.includes('.jpg') && !e.includes('example') && !e.includes('sentry')))].slice(0, 3);
  const phones = [...new Set((html.match(/\+?[\d][\d\s\-().]{7,}\d/g) || []))].slice(0, 3);
  const lang = doc.documentElement?.getAttribute('lang')?.split('-')[0] || null;
  return { niche, language: lang, target_region: null, last_modified: null, error: null, contact_info: { emails, phones } };
}

// ── Links Analysis ─────────────────────────────────────────────────────────
function analyzeLinksClient(doc, url) {
  const parsed = new URL(url);
  const suspiciousTlds = ['.xyz','.tk','.top','.club','.work','.click','.download'];
  const internal = [], external = [], suspicious = [];
  doc.querySelectorAll('a[href]').forEach(a => {
    const href = a.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')) return;
    try {
      const full = new URL(href, url);
      const text = (a.textContent?.trim() || '').slice(0, 80);
      if (full.hostname === parsed.hostname) { internal.push({ url: full.href, text }); }
      else {
        external.push({ url: full.href, text, status: null });
        const reasons = [];
        if (full.protocol === 'http:') reasons.push('Uses HTTP (not HTTPS)');
        if (suspiciousTlds.some(t => full.hostname.endsWith(t))) reasons.push('Suspicious TLD');
        if (full.search.includes('url=') || full.search.includes('redirect=')) reasons.push('Redirect parameter');
        if (reasons.length) suspicious.push({ url: full.href, text, reasons });
      }
    } catch {}
  });
  return { internal_count: internal.length, external_count: external.length, suspicious_count: suspicious.length, suspicious, external: external.slice(0, 20) };
}

// ── Sales Opportunities ────────────────────────────────────────────────────
function generateSalesOpportunities(data) {
  const opps = [];
  const seo = data.seo || {}, ssl = data.ssl_info || {}, tech = data.tech_stack || {}, sf = data.services_functionality || {};
  if (!ssl.valid) opps.push({ icon: '🔒', title: 'No SSL Certificate', priority: 'High', description: 'Website uses HTTP — SSL installation needed for security and SEO.' });
  if (seo.score < 50) opps.push({ icon: '📈', title: 'Poor SEO Score', priority: 'High', description: `SEO score is ${seo.score}/100 — significant improvements needed.` });
  if (!seo.description_ok) opps.push({ icon: '📝', title: 'Missing / Short Meta Description', priority: 'Medium', description: 'No optimised meta description — impacts search click-through rates.' });
  if (!tech.analytics?.length) opps.push({ icon: '📊', title: 'No Analytics Detected', priority: 'Medium', description: 'No analytics tools found — visitor behaviour is not being tracked.' });
  if (!sf.functionality?.some(f => f.name.includes('Live Chat'))) opps.push({ icon: '💬', title: 'No Live Chat', priority: 'Low', description: 'Adding live chat can significantly improve lead conversion rates.' });
  if (!sf.functionality?.some(f => f.name.includes('Newsletter'))) opps.push({ icon: '📧', title: 'No Email Capture', priority: 'Medium', description: 'No newsletter signup detected — missing a key lead generation opportunity.' });
  if (seo.images_missing_alt > 5) opps.push({ icon: '🖼️', title: 'Images Missing Alt Text', priority: 'Low', description: `${seo.images_missing_alt} images lack alt text — impacts accessibility and SEO ranking.` });
  if (!seo.canonical) opps.push({ icon: '🔗', title: 'No Canonical URL', priority: 'Low', description: 'Missing canonical tag can cause duplicate content issues in search engines.' });
  return opps;
}

// ── Main Export ────────────────────────────────────────────────────────────
export async function scrapeWebsite(url) {
  const { html } = await fetchViaProxy(url);
  const doc = parseHTML(html, url);
  const allText = extractAllText(doc);

  const biz = detectBusinessProfile(doc, html, url);

  const [hostingInfo, domainInfo, pagesData] = await Promise.all([
    getHostingInfo(url),
    getDomainInfo(url),
    getPages(url, doc),
  ]);

  const data = {
    url,
    title: doc.title?.trim() || '',
    meta_tags: extractMetaTags(doc),
    headings: extractHeadings(doc),
    paragraphs: extractParagraphs(doc),
    links: extractLinks(doc, url),
    images: extractImages(doc, url),
    tables: extractTables(doc),
    lists: extractLists(doc),
    all_text: allText,
    seo: analyzeSEO(doc, url),
    tech_stack: detectTechStack(html, doc),
    social_media: detectSocialMedia(html, doc),
    vulnerabilities: analyzeVulnerabilities(doc, html, url),
    pages: pagesData,
    services_functionality: analyzeServicesFunctionality(doc, html),
    business_profile: biz,
    contact_info: biz.contact_info,
    domain_info: domainInfo,
    hosting_info: hostingInfo,
    ssl_info: getSSLInfo(url),
    links_analysis: analyzeLinksClient(doc, url),
    pagespeed: { error: 'PageSpeed requires a Google API key in .env' },
  };

  data.sales_opportunities = generateSalesOpportunities(data);
  return data;
}
