import React, { useState } from 'react';
import { ClipLoader } from 'react-spinners';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { scrapeWebsite } from './scraper';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [vulnFilter, setVulnFilter] = useState('All');
  const [imagesToShow, setImagesToShow] = useState(10);
  const [showExportOptions, setShowExportOptions] = useState(false);
  const [exportSections, setExportSections] = useState({
    overview: true, vulnerabilities: true, seo: true, content: true,
    images: true, tech_info: true, pages: true, business: true,
  });
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStep, setScanStep] = useState('');

  const getSelectedSections = () => {
    const sectionMap = {
      content: ['headings', 'paragraphs', 'links', 'tables', 'lists', 'fulltext'],
      tech_info: ['domain_hosting', 'tech_stack', 'ssl', 'social'],
      business: ['business', 'sales'],
    };
    const expanded = [];
    Object.entries(exportSections).forEach(([key, val]) => {
      if (!val) return;
      if (sectionMap[key]) expanded.push(...sectionMap[key]);
      else expanded.push(key);
    });
    return [...new Set(expanded)].join(',');
  };

  const handleScrape = async (e) => {
    e.preventDefault();

    let cleanUrl = url.trim();
    if (!cleanUrl) {
      toast.error('Please enter a URL');
      return;
    }
    if (!/^https?:\/\//i.test(cleanUrl)) {
      cleanUrl = 'https://' + cleanUrl;
      setUrl(cleanUrl);
    }

    setLoading(true);
    setData(null);
    setImagesToShow(10);

    setScanProgress(0);
    setScanStep('Initialising scan...');
    const steps = [
      'Fetching page content...',
      'Detecting tech stack...',
      'Checking SSL certificate...',
      'Looking up domain info...',
      'Scanning hosting details...',
      'Discovering pages...',
      'Analysing links...',
      'Detecting social presence...',
      'Running SEO audit...',
      'Generating sales intelligence...',
    ];
    let stepIndex = 0;
    const progressInterval = setInterval(() => {
      setScanStep(steps[Math.min(stepIndex, steps.length - 1)]);
      setScanProgress(Math.min(88, ((stepIndex + 1) / steps.length) * 88));
      stepIndex++;
      if (stepIndex >= steps.length) clearInterval(progressInterval);
    }, 1800);

    try {
      const result = await scrapeWebsite(cleanUrl);
      setData(result);
      clearInterval(progressInterval);
      setScanProgress(100);
      setScanStep('Scan complete!');
      toast.success('Website scraped successfully!');
    } catch (error) {
      clearInterval(progressInterval);
      toast.error(error.message || 'Failed to scrape website. The site may block external requests.');
    } finally {
      setLoading(false);
      setTimeout(() => { setScanProgress(0); setScanStep(''); }, 1500);
    }
  };

  const handleExportCSV = () => {
    if (!data) return;
    const esc = s => String(s ?? '').replace(/"/g, '""').replace(/\n/g, ' ');
    const sections = getSelectedSections().split(',');
    const rows = [];

    if (sections.includes('overview')) {
      rows.push(`Title,"${esc(data.title)}"`);
      rows.push(`URL,${data.url}`);
      rows.push('');
    }
    if (sections.includes('vulnerabilities') && data.vulnerabilities?.vulnerabilities?.length) {
      rows.push('Vulnerabilities');
      rows.push('Severity,Type,Description');
      data.vulnerabilities.vulnerabilities.forEach(v =>
        rows.push(`"${esc(v.severity)}","${esc(v.type)}","${esc(v.description)}"`)
      );
      rows.push('');
    }
    if (sections.includes('seo') && data.seo) {
      const s = data.seo;
      rows.push('SEO Analysis');
      rows.push(`Score,${s.score ?? 'N/A'}`);
      rows.push(`Title OK,${s.title_ok}`);
      rows.push(`Description OK,${s.description_ok}`);
      rows.push(`H1 Count,${s.h1_count}`);
      rows.push(`Images Missing Alt,${s.images_missing_alt}`);
      rows.push('');
    }
    if (sections.includes('headings') && data.headings?.length) {
      rows.push('Headings');
      rows.push('Level,Text');
      data.headings.forEach(h => rows.push(`H${h.level},"${esc(h.text)}"`));
      rows.push('');
    }
    if (sections.includes('paragraphs') && data.paragraphs?.length) {
      rows.push('Paragraphs');
      data.paragraphs.forEach(p => rows.push(`"${esc(p)}"`));
      rows.push('');
    }
    if (sections.includes('links') && data.links?.length) {
      rows.push('Links');
      rows.push('Text,URL');
      data.links.slice(0, 100).forEach(l => rows.push(`"${esc(l.text)}",${l.url}`));
      rows.push('');
    }
    if (sections.includes('images') && data.images?.length) {
      rows.push('Images');
      rows.push('URL,Alt');
      data.images.forEach(img => rows.push(`"${esc(img.src)}","${esc(img.alt)}"`));
      rows.push('');
    }
    if (sections.includes('pages') && data.pages?.pages?.length) {
      rows.push('Pages');
      data.pages.pages.forEach((p, i) => rows.push(`${i + 1},"${esc(p.url)}"`));
      rows.push('');
    }

    const csv = rows.join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    let domain = 'report';
    try { domain = new URL(data.url).hostname; } catch(e) {}
    link.download = `scana_${domain}_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    toast.success('CSV downloaded!');
  };

  const renderTabContent = () => {
    if (!data) return null;

    const getPageName = (pageUrl) => {
      try {
        let path = pageUrl;
        if (pageUrl && pageUrl.startsWith('http')) {
          path = new URL(pageUrl).pathname;
        }
        if (!path || path === '/') return 'Home';
        const parts = path.replace(/\/$/, '').split('/').filter(Boolean);
        return parts.map(p => p.replace(/[-_]/g, ' ').replace(/\b\w/g, c => c.toUpperCase())).join(' / ');
      } catch {
        return pageUrl || 'Home';
      }
    };

    switch (activeTab) {
      case 'vulnerabilities':
        const vulnData = data.vulnerabilities;
        const summary = vulnData?.summary || { total: 0, critical: 0, high: 0, medium: 0, low: 0, risk_score: 0 };
        let vulnList = vulnData?.vulnerabilities || [];

        if (vulnFilter !== 'All') {
          vulnList = vulnList.filter(v => v.severity === vulnFilter);
        }

        const getRiskClass = (score) => {
          if (score >= 70) return 'critical';
          if (score >= 40) return 'high';
          if (score >= 20) return 'medium';
          return 'low';
        };

        return (
          <div className="tab-content">
            <div className="vuln-header">
              <h3>Vulnerability Scan Results</h3>
              <div className={`risk-score ${getRiskClass(summary.risk_score)}`}>
                <span className="score-value">{summary.risk_score}</span>
                <span className="score-label">Risk Score</span>
              </div>
            </div>

            <div className="vuln-summary">
              <div className="vuln-stat critical">
                <span className="count">{summary.critical}</span>
                <span className="label">Critical</span>
              </div>
              <div className="vuln-stat high">
                <span className="count">{summary.high}</span>
                <span className="label">High</span>
              </div>
              <div className="vuln-stat medium">
                <span className="count">{summary.medium}</span>
                <span className="label">Medium</span>
              </div>
              <div className="vuln-stat low">
                <span className="count">{summary.low}</span>
                <span className="label">Low</span>
              </div>
            </div>

            {vulnData?.vulnerabilities?.length > 0 && (
              <div className="vuln-filter">
                <label htmlFor="severity-filter">Filter by Severity:</label>
                <select
                  id="severity-filter"
                  value={vulnFilter}
                  onChange={(e) => setVulnFilter(e.target.value)}
                  className="severity-select"
                >
                  <option value="All">All Levels</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>
            )}

            {vulnList.length > 0 ? (
              <div className="vulnerabilities-list">
                {vulnList.map((vuln, index) => (
                  <div key={index} className={`vuln-item severity-${vuln.severity.toLowerCase()}`}>
                    <div className="vuln-header-row">
                      <span className={`severity-badge ${vuln.severity.toLowerCase()}`}>
                        {vuln.severity}
                      </span>
                      <span className="vuln-type">{vuln.type}</span>
                    </div>
                    <p className="vuln-description">{vuln.description}</p>

                    {vuln.damage && (
                      <div className="vuln-damage">
                        <strong>Potential Damage:</strong>
                        <p>{vuln.damage}</p>
                      </div>
                    )}

                    {vuln.header && (
                      <span className="vuln-header-name">Header: {vuln.header}</span>
                    )}

                    {vuln.url && (
                      <a href={vuln.url} target="_blank" rel="noopener noreferrer" className="vuln-url">
                        {vuln.path}
                      </a>
                    )}
                  </div>
                ))}
              </div>
            ) : vulnData?.vulnerabilities?.length > 0 ? (
              <div className="no-vulnerabilities">
                <p>No vulnerabilities match the selected filter.</p>
                <button onClick={() => setVulnFilter('All')} className="clear-filter-btn">
                  Show All
                </button>
              </div>
            ) : (
              <div className="no-vulnerabilities">
                <div className="success-icon">✓</div>
                <p>No vulnerabilities found!</p>
                <span>This website appears to be well-secured.</span>
              </div>
            )}
          </div>
        );

      case 'overview':
        return (
          <div className="tab-content">
            <div className="stats-grid">
              <div className="stat-card">
                <h3>Title</h3>
                <p>{data.title || 'No title found'}</p>
              </div>
              <div className="stat-card">
                <h3>Headings</h3>
                <p className="stat-number">{data.headings?.length || 0}</p>
              </div>
              <div className="stat-card">
                <h3>Paragraphs</h3>
                <p className="stat-number">{data.paragraphs?.length || 0}</p>
              </div>
              <div className="stat-card">
                <h3>Links</h3>
                <p className="stat-number">{data.links?.length || 0}</p>
              </div>
              <div className="stat-card">
                <h3>Images</h3>
                <p className="stat-number">{data.images?.length || 0}</p>
              </div>
              <div className="stat-card">
                <h3>Tables</h3>
                <p className="stat-number">{data.tables?.length || 0}</p>
              </div>
            </div>

            {data.meta_tags && Object.keys(data.meta_tags).length > 0 && (
              <div className="section">
                <h3>Meta Tags</h3>
                <div className="meta-tags">
                  {Object.entries(data.meta_tags).map(([key, value], index) => (
                    <div key={index} className="meta-tag">
                      <strong>{key}:</strong> {value}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );

      case 'seo': {
        const seo = data.seo;
        if (!seo) return <div className="tab-content"><p className="no-data">No SEO data available</p></div>;
        const getSeoClass = s => s >= 80 ? 'low' : s >= 50 ? 'medium' : 'high';
        const seoChecks = [
          { label: 'Title', ok: seo.title_ok, detail: seo.title ? `"${seo.title.slice(0, 60)}" (${seo.title_length} chars)` : 'Missing' },
          { label: 'Meta Description', ok: seo.description_ok, detail: seo.description ? `${seo.description_length} chars` : 'Missing' },
          { label: 'Single H1 Tag', ok: seo.h1_ok, detail: `${seo.h1_count} found${seo.h1_texts?.[0] ? ` — "${seo.h1_texts[0].slice(0, 50)}"` : ''}` },
          { label: 'Image Alt Tags', ok: seo.images_missing_alt === 0, detail: `${seo.images_missing_alt} missing of ${seo.images_total}` },
          { label: 'Canonical URL', ok: !!seo.canonical, detail: seo.canonical || 'Not set' },
          { label: 'Open Graph Tags', ok: !!seo.og?.title, detail: seo.og?.title ? `og:title set` : 'Missing' },
          { label: 'Twitter Card', ok: !!seo.twitter?.card, detail: seo.twitter?.card || 'Not set' },
        ];
        return (
          <div className="tab-content">
            <div className="vuln-header">
              <h3>SEO Analysis</h3>
              <div className={`risk-score ${getSeoClass(seo.score)}`}>
                <span className="score-value">{seo.score}</span>
                <span className="score-label">SEO Score</span>
              </div>
            </div>
            <div className="seo-checks">
              {seoChecks.map(({ label, ok, detail }, i) => (
                <div key={i} className={`seo-check-item ${ok ? 'pass' : 'fail'}`}>
                  <span className={`seo-check-icon ${ok ? 'pass' : 'fail'}`}>{ok ? '✓' : '✗'}</span>
                  <div>
                    <strong>{label}</strong>
                    <span className="seo-check-detail">{detail}</span>
                  </div>
                </div>
              ))}
            </div>
            <div className="section">
              <h4>
                Broken Links
                <span className="link-check-info"> (checked {seo.links_checked} same-host links)</span>
              </h4>
              {seo.broken_links?.length > 0 ? (
                <div className="links-list">
                  {seo.broken_links.map((bl, i) => (
                    <div key={i} className="link-item">
                      <a href={bl.url} target="_blank" rel="noopener noreferrer">{bl.url}</a>
                      <span style={{ color: '#ff6b6b', fontSize: '0.85rem' }}>Status: {bl.status}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="no-data">No broken links found ✓</p>
              )}
            </div>
            {(seo.og?.title || seo.og?.description || seo.og?.image) && (
              <div className="section">
                <h4>Open Graph Tags</h4>
                <div className="meta-tags">
                  {Object.entries(seo.og).filter(([, v]) => v).map(([k, v], i) => (
                    <div key={i} className="meta-tag"><strong>og:{k}:</strong> {v}</div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      }

      case 'images':
        return (
          <div className="tab-content">
            <h3>Images ({data.images?.length || 0})</h3>
            {data.images?.length > 0 ? (
              <>
                <div className="images-list">
                  {data.images.slice(0, imagesToShow).map((img, index) => (
                    <div key={index} className="image-item">
                      <div className="image-container">
                        <img
                          src={img.src}
                          alt={img.alt || `Image ${index + 1}`}
                          className="image-thumbnail"
                          loading="lazy"
                          onLoad={(e) => {
                            e.currentTarget.classList.add('loaded');
                            const placeholder = e.currentTarget.parentElement.querySelector('.image-placeholder');
                            if (placeholder) placeholder.style.display = 'none';
                          }}
                          onError={(e) => {
                            e.currentTarget.style.display = 'none';
                            const placeholder = e.currentTarget.parentElement.querySelector('.image-placeholder');
                            if (placeholder) {
                              placeholder.classList.add('failed');
                              placeholder.querySelector('span').textContent = '❌ Failed';
                            }
                          }}
                        />
                        <div className="image-placeholder">
                          <span>📷 Loading...</span>
                        </div>
                      </div>
                      <div className="image-info">
                        <p><strong>Source:</strong> <a href={img.src} target="_blank" rel="noopener noreferrer" style={{ color: '#00d4ff', textDecoration: 'none', wordBreak: 'break-all', fontSize: '0.8rem' }}>{img.src}</a></p>
                        {img.alt && <p><strong>Alt:</strong> {img.alt}</p>}
                      </div>
                    </div>
                  ))}
                </div>
                {imagesToShow < data.images.length && (
                  <button
                    className="load-more-btn"
                    onClick={() => setImagesToShow(prev => prev + 10)}
                  >
                    📥 Load More Images ({imagesToShow} of {data.images.length})
                  </button>
                )}
              </>
            ) : (
              <p className="no-data">No images found</p>
            )}
          </div>
        );

      case 'content': {
        const ContentCard = ({ title, count, children }) => (
          <div className="content-card">
            <div className="content-card-header">
              <h4>{title}</h4>
              {count !== undefined && <span className="content-card-count">{count}</span>}
            </div>
            <div className="content-card-body">{children}</div>
          </div>
        );

        return (
          <div className="tab-content">
            <div className="content-cards">
              <ContentCard title="Headings" count={data.headings?.length || 0}>
                {data.headings?.length > 0 ? (
                  <div className="headings-list">
                    {data.headings.map((heading, i) => (
                      <div key={i} className={`heading-item h${heading.level}`}>
                        <span className="heading-level">H{heading.level}</span>
                        <span className="heading-text">{heading.text}</span>
                      </div>
                    ))}
                  </div>
                ) : <p className="no-data">No headings found</p>}
              </ContentCard>

              <ContentCard title="Paragraphs" count={data.paragraphs?.length || 0}>
                {data.paragraphs?.length > 0 ? (
                  <div className="paragraphs-list">
                    {data.paragraphs.map((para, i) => (
                      <p key={i} className="paragraph-item">{para}</p>
                    ))}
                  </div>
                ) : <p className="no-data">No paragraphs found</p>}
              </ContentCard>

              <ContentCard title="Links" count={data.links?.length || 0}>
                {data.links?.length > 0 ? (
                  <div className="links-list">
                    {data.links.map((link, i) => (
                      <div key={i} className="link-item">
                        <a href={link.url} target="_blank" rel="noopener noreferrer">
                          {link.text || link.url}
                        </a>
                        <span className="link-url">{link.url}</span>
                      </div>
                    ))}
                  </div>
                ) : <p className="no-data">No links found</p>}
              </ContentCard>

              <ContentCard title="Tables" count={data.tables?.length || 0}>
                {data.tables?.length > 0 ? (
                  <div className="tables-list">
                    {data.tables.map((table, tIndex) => (
                      <div key={tIndex} className="table-container">
                        <h4>Table {tIndex + 1}</h4>
                        <table className="data-table">
                          <tbody>
                            {table.map((row, rIndex) => (
                              <tr key={rIndex}>
                                {row.map((cell, cIndex) => (
                                  <td key={cIndex}>{cell}</td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ))}
                  </div>
                ) : <p className="no-data">No tables found</p>}
              </ContentCard>

              <ContentCard title="Lists" count={(data.lists?.ul?.length || 0) + (data.lists?.ol?.length || 0)}>
                {(data.lists?.ul?.length > 0 || data.lists?.ol?.length > 0) ? (
                  <>
                    {data.lists?.ul?.length > 0 && (
                      <div className="lists-section">
                        <h4>Unordered Lists ({data.lists.ul.length})</h4>
                        {data.lists.ul.map((list, lIndex) => (
                          <ul key={lIndex} className="data-list">
                            {list.map((item, iIndex) => <li key={iIndex}>{item}</li>)}
                          </ul>
                        ))}
                      </div>
                    )}
                    {data.lists?.ol?.length > 0 && (
                      <div className="lists-section">
                        <h4>Ordered Lists ({data.lists.ol.length})</h4>
                        {data.lists.ol.map((list, lIndex) => (
                          <ol key={lIndex} className="data-list">
                            {list.map((item, iIndex) => <li key={iIndex}>{item}</li>)}
                          </ol>
                        ))}
                      </div>
                    )}
                  </>
                ) : <p className="no-data">No lists found</p>}
              </ContentCard>

              <ContentCard title="Full Text">
                <div className="full-text">
                  {data.all_text?.split('\n').map((line, i) => (
                    line.trim() && <p key={i}>{line}</p>
                  ))}
                </div>
              </ContentCard>
            </div>
          </div>
        );
      }

      case 'tech_info': {
        const tech = data.tech_stack;
        const dom = data.domain_info || {};
        const host = data.hosting_info || {};
        const sslData = data.ssl_info || {};
        const socialData = data.social_media || {};

        const PillGroup = ({ label, items, pillClass }) => (
          <div className="tech-group">
            <span className="tech-group-label">{label}</span>
            <div className="tech-pills">
              {items && items.length > 0
                ? items.map((item, i) => <span key={i} className={`tech-pill ${pillClass}`}>{item}</span>)
                : <span className="tech-none">None detected</span>
              }
            </div>
          </div>
        );

        const ExpiryBadge = ({ days }) => {
          if (days === null || days === undefined) return null;
          if (days <= 30) return <span className="badge-critical">⚠ {days} days left</span>;
          if (days <= 90) return <span className="badge-warning">⚠ {days} days left</span>;
          return <span className="badge-good">{days} days</span>;
        };

        const socialPlatforms = [
          { key: 'facebook', label: 'Facebook', emoji: '📘' },
          { key: 'instagram', label: 'Instagram', emoji: '📸' },
          { key: 'linkedin', label: 'LinkedIn', emoji: '💼' },
          { key: 'twitter', label: 'Twitter / X', emoji: '🐦' },
          { key: 'youtube', label: 'YouTube', emoji: '▶️' },
          { key: 'tiktok', label: 'TikTok', emoji: '🎵' },
          { key: 'pinterest', label: 'Pinterest', emoji: '📌' },
          { key: 'github', label: 'GitHub', emoji: '🐙' },
        ];
        const foundCount = socialPlatforms.filter(p => socialData[p.key]).length;

        return (
          <div className="tab-content">
            {/* Tech Stack */}
            <div className="tech-info-section">
              <h3 className="tech-info-heading">Tech Stack</h3>
              {tech && !tech.error ? (
                <>
                  {tech.platform && (
                    <div className="tech-platform-banner">
                      <span className="tech-pill platform" style={{ fontSize: '1rem', padding: '8px 20px' }}>
                        {tech.platform}{tech.cms_version ? ` ${tech.cms_version}` : ''}
                      </span>
                    </div>
                  )}
                  {!tech.platform && <p className="no-data" style={{ color: '#a0a0a0' }}>Platform not detected</p>}
                  <div className="tech-groups">
                    <PillGroup label="Frameworks" items={tech.frameworks} pillClass="framework" />
                    <PillGroup label="Analytics" items={tech.analytics} pillClass="analytics" />
                    <PillGroup label="Payment Gateways" items={tech.payment} pillClass="payment" />
                    <PillGroup label="Email / Marketing" items={tech.email_marketing} pillClass="email" />
                    <PillGroup label="Security Tools" items={tech.security_tools} pillClass="security" />
                    <PillGroup label="JS Libraries" items={tech.js_libraries} pillClass="default" />
                    <PillGroup label="Fonts" items={tech.fonts} pillClass="default" />
                  </div>
                </>
              ) : <p className="no-data">⚠️ {tech?.error || 'Tech stack data unavailable'}</p>}
            </div>

            <div className="tech-info-divider" />

            {/* Domain & Hosting */}
            <div className="tech-info-section">
              <h3 className="tech-info-heading">Domain &amp; Hosting</h3>
              {(dom.error || host.error) && (
                <div className="info-error-note">⚠️ Some data may be unavailable: {dom.error || host.error}</div>
              )}
              <div className="info-grid">
                <div className="info-card">
                  <h4>Domain Registration</h4>
                  <div className="info-row"><span className="info-label">Registered</span><span className="info-value">{dom.registration_date || 'N/A'}</span></div>
                  <div className="info-row">
                    <span className="info-label">Expires</span>
                    <span className="info-value">
                      {dom.expiry_date || 'N/A'}
                      {dom.days_until_expiry !== undefined && <ExpiryBadge days={dom.days_until_expiry} />}
                    </span>
                  </div>
                  <div className="info-row"><span className="info-label">Registrar</span><span className="info-value">{dom.registrar || 'N/A'}</span></div>
                  <div className="info-row"><span className="info-label">Owner</span><span className="info-value">{dom.owner || 'Private / Redacted'}</span></div>
                  <div className="info-row"><span className="info-label">Country</span><span className="info-value">{dom.country || 'N/A'}</span></div>
                </div>
                <div className="info-card">
                  <h4>Server &amp; Hosting</h4>
                  <div className="info-row"><span className="info-label">IP Address</span><span className="info-value">{host.ip_address || 'N/A'}</span></div>
                  <div className="info-row"><span className="info-label">Provider</span><span className="info-value">{host.provider || 'N/A'}</span></div>
                  <div className="info-row"><span className="info-label">Location</span><span className="info-value">{[host.city, host.country].filter(Boolean).join(', ') || 'N/A'}</span></div>
                  <div className="info-row"><span className="info-label">Server Software</span><span className="info-value">{host.server_software || 'Not disclosed'}</span></div>
                  <div className="info-row">
                    <span className="info-label">CDN</span>
                    <span className="info-value">
                      {host.cdn ? <span className="badge-good">{host.cdn}</span> : 'None detected'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="tech-info-divider" />

            {/* SSL */}
            <div className="tech-info-section">
              <h3 className="tech-info-heading">SSL Certificate</h3>
              {sslData.error && !sslData.valid ? (
                <div className="ssl-invalid">
                  <div style={{ fontSize: '2rem' }}>🔓</div>
                  <h3 style={{ color: '#ff4444', margin: '8px 0' }}>SSL INVALID / NOT HTTPS</h3>
                  <p style={{ color: '#a0a0a0' }}>{sslData.error}</p>
                </div>
              ) : (
                <div className={sslData.warning === 'expired' ? 'ssl-invalid' : 'ssl-valid'}>
                  <div style={{ fontSize: '2rem' }}>{sslData.valid ? '🔒' : '🔓'}</div>
                  <h3 style={{ color: sslData.valid ? '#00c851' : '#ff4444', margin: '8px 0' }}>
                    {sslData.valid ? '✓ SSL VALID' : '✗ SSL INVALID'}
                  </h3>
                </div>
              )}
              {sslData.warning === 'critical' && (
                <div className="expiry-banner critical">⚠️ Certificate expires in {sslData.days_remaining} days — CRITICAL</div>
              )}
              {sslData.warning === 'warning' && (
                <div className="expiry-banner warning">⚠️ Certificate expires in {sslData.days_remaining} days — renew soon</div>
              )}
              <div className="info-card" style={{ marginTop: '12px' }}>
                {[
                  ['Issuer', sslData.issuer],
                  ['Certificate Type', sslData.cert_type],
                  ['Issued Date', sslData.issued_date],
                  ['Expiry Date', sslData.expiry_date],
                  ['Days Remaining', sslData.days_remaining != null ? `${sslData.days_remaining} days` : null],
                ].map(([label, value], i) => value ? (
                  <div key={i} className="info-row">
                    <span className="info-label">{label}</span>
                    <span className="info-value">{value}</span>
                  </div>
                ) : null)}
              </div>
            </div>

            <div className="tech-info-divider" />

            {/* Social */}
            <div className="tech-info-section">
              <h3 className="tech-info-heading">Social Media</h3>
              <p style={{ color: '#a0a0a0', marginBottom: '16px' }}>{foundCount} / {socialPlatforms.length} platforms detected</p>
              <div className="social-grid">
                {socialPlatforms.map(({ key, label, emoji }) => {
                  const url_found = socialData[key];
                  return (
                    <div key={key} className={`social-card ${url_found ? 'social-found' : 'social-not-found'}`}>
                      <span style={{ fontSize: '1.5rem' }}>{emoji}</span>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: '600', fontSize: '0.9rem' }}>{label}</div>
                        {url_found
                          ? <a href={url_found} target="_blank" rel="noopener noreferrer" className="badge-good" style={{ fontSize: '0.75rem', textDecoration: 'none' }}>✓ Found</a>
                          : <span style={{ color: '#555', fontSize: '0.75rem' }}>✗ Not Found</span>
                        }
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        );
      }

      case 'pages': {
        const pagesData = data.pages || {};
        const pagesList = pagesData.pages || [];
        const sf = data.services_functionality || {};

        const buildFullUrl = (page) => {
          if (!page.url) return data.url;
          if (page.url.startsWith('http')) return page.url;
          return (data.url || '').replace(/\/$/, '') + (page.url.startsWith('/') ? page.url : '/' + page.url);
        };

        const handleCopyPages = () => {
          const names = pagesList.map((page, i) => `${i + 1}. ${getPageName(page.url)}`).join('\n');
          navigator.clipboard.writeText(names).then(() => {
            toast.success('Page names copied to clipboard!');
          });
        };

        return (
          <div className="tab-content">

            {/* ── Service & Functionality Analysis ── */}
            {(sf.service_categories?.length > 0 || sf.functionality?.length > 0) && (
              <div className="sf-section">
                <h3 className="sf-heading">Website Functionality & Service Analysis</h3>

                {sf.primary_service && (
                  <div className="sf-primary">
                    <span className="sf-primary-label">Primary Service Type</span>
                    <span className="sf-primary-value">{sf.primary_service}</span>
                  </div>
                )}

                {sf.service_categories?.length > 0 && (
                  <div className="sf-block">
                    <h4 className="sf-block-title">Service Categories</h4>
                    <div className="sf-cards">
                      {sf.service_categories.map((cat, i) => (
                        <div key={i} className="sf-card service-card">
                          <span className="sf-card-icon">{cat.icon}</span>
                          <span className="sf-card-name">{cat.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {sf.functionality?.length > 0 && (
                  <div className="sf-block">
                    <h4 className="sf-block-title">Detected Functionality</h4>
                    <div className="sf-cards">
                      {sf.functionality.map((fn, i) => (
                        <div key={i} className="sf-card fn-card">
                          <span className="sf-card-icon">{fn.icon}</span>
                          <span className="sf-card-name">{fn.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── Pages List ── */}
            <div className="pages-header">
              <h3>Pages</h3>
              {pagesList.length > 0 && (
                <button className="copy-pages-btn" onClick={handleCopyPages}>
                  Copy Names
                </button>
              )}
            </div>
            <div className="pages-summary">
              <span className="summary-badge">{pagesData.total || 0} Pages Found</span>
              <span className={`summary-badge ${pagesData.sitemap_found ? 'badge-good' : 'badge-critical'}`}>
                Sitemap: {pagesData.sitemap_found ? '✓ Found' : '✗ Not Found'}
              </span>
            </div>
            {pagesData.error && <p className="no-data">⚠️ {pagesData.error}</p>}
            {pagesList.length > 0 ? (
              <div className="pages-name-list">
                {pagesList.map((page, i) => (
                  <a
                    key={i}
                    href={buildFullUrl(page)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="page-name-item"
                  >
                    <span className="page-serial">{i + 1}</span>
                    <span className="page-name-icon">📄</span>
                    <span className="page-name-text">{getPageName(page.url)}</span>
                    <span className="page-name-arrow">→</span>
                  </a>
                ))}
              </div>
            ) : (
              <p className="no-data">No pages discovered</p>
            )}
          </div>
        );
      }

      case 'business': {
        const biz = data.business_profile || {};
        const opps = data.sales_opportunities || [];
        const contact = data.contact_info || {};
        const niches = {
          'E-commerce': '#00c851', 'SaaS': '#00d4ff', 'Agency / Portfolio': '#7b2cbf',
          'Blog / Media': '#ff8800', 'Restaurant / Food': '#ff6b6b', 'Healthcare': '#17a2b8',
          'Education': '#ffc107', 'Real Estate': '#6f42c1', 'Legal': '#6c757d',
          'Finance': '#28a745', 'Non-profit': '#e83e8c', 'General': '#495057'
        };
        const nicheColor = niches[biz.niche] || '#495057';
        const priorityGroups = { High: [], Medium: [], Low: [] };
        opps.forEach(o => { if (priorityGroups[o.priority]) priorityGroups[o.priority].push(o); });

        return (
          <div className="tab-content">
            <h3>Business Profile</h3>

            {biz.niche && (
              <div style={{ marginBottom: '20px' }}>
                <span style={{
                  background: nicheColor + '33', color: nicheColor,
                  border: `1px solid ${nicheColor}66`, padding: '6px 18px',
                  borderRadius: '20px', fontSize: '1rem', fontWeight: '600'
                }}>
                  {biz.niche}
                </span>
              </div>
            )}

            <div className="info-card">
              {[
                ['Language', biz.language?.toUpperCase()],
                ['Target Region', biz.target_region],
                ['Last Modified', biz.last_modified],
              ].map(([label, value], i) => value ? (
                <div key={i} className="info-row">
                  <span className="info-label">{label}</span>
                  <span className="info-value">{value}</span>
                </div>
              ) : null)}
            </div>

            {(contact.emails?.length > 0 || contact.phones?.length > 0) && (
              <div style={{ marginTop: '20px' }}>
                <h4 style={{ marginBottom: '10px', color: '#e0e0e0' }}>Contact Information</h4>
                <div className="info-card">
                  {contact.emails?.map((email, i) => (
                    <div key={`e${i}`} className="info-row">
                      <span className="info-label">📧 Email</span>
                      <span className="info-value">
                        <a href={`mailto:${email}`} style={{ color: '#00d4ff', textDecoration: 'none' }}>{email}</a>
                      </span>
                    </div>
                  ))}
                  {contact.phones?.map((phone, i) => (
                    <div key={`p${i}`} className="info-row">
                      <span className="info-label">📞 Phone</span>
                      <span className="info-value">{phone}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="similaweb-callout">
              <span>📊</span>
              <span>For traffic &amp; ranking data, check <a href="https://www.similarweb.com" target="_blank" rel="noopener noreferrer" style={{ color: '#00d4ff' }}>SimilarWeb.com</a></span>
            </div>

            {data.pagespeed && !data.pagespeed.error && (
              <div style={{ marginTop: '16px' }}>
                <h4 style={{ marginBottom: '10px' }}>PageSpeed Scores</h4>
                <div className="info-card">
                  {[
                    ['Mobile Performance', data.pagespeed.mobile_score !== null ? `${data.pagespeed.mobile_score}/100` : null],
                    ['Desktop Performance', data.pagespeed.desktop_score !== null ? `${data.pagespeed.desktop_score}/100` : null],
                    ['LCP', data.pagespeed.lcp],
                    ['CLS', data.pagespeed.cls],
                    ['TBT', data.pagespeed.fid],
                    ['Accessibility', data.pagespeed.accessibility_score !== null ? `${data.pagespeed.accessibility_score}/100` : null],
                    ['Best Practices', data.pagespeed.best_practices_score !== null ? `${data.pagespeed.best_practices_score}/100` : null],
                  ].filter(([, v]) => v).map(([label, value], i) => (
                    <div key={i} className="info-row">
                      <span className="info-label">{label}</span>
                      <span className="info-value">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {data.pagespeed?.error && (
              <div className="info-error-note" style={{ marginTop: '12px' }}>📊 {data.pagespeed.error}</div>
            )}

            {/* Sales Signals */}
            <div style={{ marginTop: '28px' }}>
              <div className="sales-header">
                <h3>⚡ Sales Signals</h3>
                <span className="sales-count-badge">{opps.length} opportunities detected</span>
              </div>
              {opps.length === 0 ? (
                <div className="no-vulnerabilities">
                  <div className="success-icon">✓</div>
                  <p>No sales opportunities detected</p>
                  <span>This site appears well-optimised</span>
                </div>
              ) : (
                <div>
                  {Object.entries(priorityGroups).map(([level, items]) => {
                    if (!items.length) return null;
                    const colors = { High: '#ff4444', Medium: '#ffcc00', Low: '#00d4ff' };
                    return (
                      <div key={level} className="sales-priority-group">
                        <h4 style={{ color: colors[level], borderBottom: `2px solid ${colors[level]}33`, paddingBottom: '6px', marginBottom: '12px' }}>
                          {level} Priority ({items.length})
                        </h4>
                        {items.map((opp, i) => (
                          <div key={i} className="sales-opp-card">
                            <div className="sales-opp-header">
                              <span className="sales-opp-icon">{opp.icon}</span>
                              <span className="sales-opp-title">{opp.title}</span>
                              <span className={`sales-priority-badge priority-${level.toLowerCase()}`}>{level}</span>
                            </div>
                            <p className="sales-opp-desc">{opp.description}</p>
                          </div>
                        ))}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        );
      }

      default:
        return null;
    }
  };

  return (
    <div className="App">
      <ToastContainer position="top-right" autoClose={3000} />

      <header className="app-header">
        <h1>Scana</h1>
        <p>Scan websites for security vulnerabilities and assess potential risks</p>
      </header>

      <main className="main-content">
        <section className="input-section">
          <form onSubmit={handleScrape} className="scrape-form">
            <div className="input-group">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter website URL (e.g., https://example.com)"
                className="url-input"
                disabled={loading}
              />
              <button
                type="submit"
                className="scrape-btn"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <ClipLoader size={16} color="#fff" />
                    Scraping...
                  </>
                ) : (
                  'Scrape Website'
                )}
              </button>
            </div>
          </form>
          {loading && (
            <div className="scan-progress">
              <div className="progress-bar-outer">
                <div className="progress-bar-fill" style={{ width: `${scanProgress}%` }} />
              </div>
              <p className="progress-step-text">{scanStep}</p>
            </div>
          )}
        </section>

        {data && (
          <section className="results-section">
            <div className="results-header">
              <h2>Scan Data</h2>
              <div className="summary-stats">
                <div className="summary-stat">
                  <span className="summary-stat-value">{data.pages?.total ?? '—'}</span>
                  <span className="summary-stat-label">Pages Found</span>
                </div>
                <div className="summary-stat warn">
                  <span className="summary-stat-value">{data.links_analysis?.suspicious_count ?? 0}</span>
                  <span className="summary-stat-label">Suspicious Links</span>
                </div>
                <div className="summary-stat">
                  <span className="summary-stat-value">{data.seo?.score ?? '—'}</span>
                  <span className="summary-stat-label">SEO Score</span>
                </div>
                <div className="summary-stat warn">
                  <span className="summary-stat-value">{data.vulnerabilities?.summary?.total ?? 0}</span>
                  <span className="summary-stat-label">Security Issues</span>
                </div>
                <div className="summary-stat accent">
                  <span className="summary-stat-value">{data.sales_opportunities?.length ?? 0}</span>
                  <span className="summary-stat-label">Sales Signals</span>
                </div>
              </div>
              <div className="export-buttons">
                <button onClick={handleExportCSV} className="export-btn csv-btn">Export CSV</button>
                <button
                  onClick={() => setShowExportOptions(prev => !prev)}
                  className={`export-btn options-btn ${showExportOptions ? 'active' : ''}`}
                >
                  ⚙ Sections
                </button>
              </div>
            </div>

            {showExportOptions && (
              <div className="export-options-panel">
                <h4>Sections to Export</h4>
                <div className="export-section-controls">
                  <button className="control-btn" onClick={() => setExportSections(s => Object.fromEntries(Object.keys(s).map(k => [k, true])))}>Select All</button>
                  <button className="control-btn" onClick={() => setExportSections(s => Object.fromEntries(Object.keys(s).map(k => [k, false])))}>Clear All</button>
                </div>
                <div className="export-checkboxes">
                  {[
                    { key: 'overview', label: 'Overview' },
                    { key: 'vulnerabilities', label: 'Vulnerabilities' },
                    { key: 'seo', label: 'SEO' },
                    { key: 'content', label: 'Content (Headings, Paragraphs, Links, Tables, Lists, Text)' },
                    { key: 'images', label: 'Images' },
                    { key: 'tech_info', label: 'Tech Info (Stack, Domain, SSL, Social)' },
                    { key: 'pages', label: 'Pages' },
                    { key: 'business', label: 'Business Profile & Sales Signals' },
                  ].map(({ key, label }) => (
                    <label key={key} className="export-checkbox-label">
                      <input
                        type="checkbox"
                        checked={exportSections[key]}
                        onChange={e => setExportSections(prev => ({ ...prev, [key]: e.target.checked }))}
                      />
                      {label}
                    </label>
                  ))}
                </div>
              </div>
            )}

            <div className="tabs">
              {[
                { id: 'overview', label: 'Overview' },
                { id: 'vulnerabilities', label: 'Vulnerabilities' },
                { id: 'seo', label: 'SEO' },
                { id: 'content', label: 'Content' },
                { id: 'tech_info', label: 'Tech Info' },
                { id: 'pages', label: 'Pages & Functionality' },
                { id: 'images', label: 'Images' },
                { id: 'business', label: 'Business Profile' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  data-tab={tab.id}
                  className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
                  onClick={() => setActiveTab(tab.id)}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="tab-content-container">
              {renderTabContent()}
            </div>
          </section>
        )}
      </main>

      <footer className="app-footer">
        <p>Scana &copy; 2024 - Website Security Vulnerability Scanner</p>
      </footer>
    </div>
  );
}

export default App;
