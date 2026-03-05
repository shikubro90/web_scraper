import React, { useState } from 'react';
import axios from 'axios';
import { ClipLoader } from 'react-spinners';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || '';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);
  const [sessionId, setSessionId] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [vulnFilter, setVulnFilter] = useState('All');
  const [imagesToShow, setImagesToShow] = useState(10);
  const [showExportOptions, setShowExportOptions] = useState(false);
  const [exportSections, setExportSections] = useState({
    overview: true, vulnerabilities: true, tech: true, seo: true, headings: true,
    paragraphs: true, links: true, images: true, tables: true, lists: true, fulltext: true,
  });

  const getSelectedSections = () =>
    Object.entries(exportSections).filter(([, v]) => v).map(([k]) => k).join(',');

  const handleScrape = async (e) => {
    e.preventDefault();

    if (!url.trim()) {
      toast.error('Please enter a URL');
      return;
    }

    setLoading(true);
    setData(null);
    setSessionId(null);
    setImagesToShow(10);

    // Auto-prepend https:// if no protocol given
    const normalizedUrl = url.match(/^https?:\/\//i) ? url : `https://${url}`;

    try {
      const response = await axios.post(`${API_URL}/api/scrape`, { url: normalizedUrl });

      if (response.data.success) {
        setData(response.data.data);
        setSessionId(response.data.session_id);
        toast.success('Website scanned successfully!');
      }
    } catch (error) {
      const errorMessage = error.response?.data?.error || 'Failed to scan website';
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleExportCSV = async () => {
    if (!sessionId) return;
    try {
      const response = await axios.get(
        `${API_URL}/api/export/csv/${sessionId}?sections=${getSelectedSections()}`,
        { responseType: 'blob' }
      );
      const blob = new Blob([response.data], { type: 'text/csv' });
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `vulnscan_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(downloadUrl);
      toast.success('CSV downloaded successfully!');
    } catch (error) {
      toast.error('Failed to download CSV');
    }
  };

  const handleExportDOC = async () => {
    if (!sessionId) return;
    try {
      const response = await axios.get(
        `${API_URL}/api/export/doc/${sessionId}?sections=${getSelectedSections()}`,
        { responseType: 'blob' }
      );
      const blob = new Blob([response.data], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `vulnscan_${new Date().toISOString().split('T')[0]}.docx`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(downloadUrl);
      toast.success('DOCX downloaded successfully!');
    } catch (error) {
      toast.error('Failed to download DOCX');
    }
  };

  const renderTabContent = () => {
    if (!data) return null;

    switch (activeTab) {
      case 'vulnerabilities':
        const vulnData = data.vulnerabilities;
        const summary = vulnData?.summary || { total: 0, critical: 0, high: 0, medium: 0, low: 0, risk_score: 0 };
        let vulnList = vulnData?.vulnerabilities || [];

        // Filter vulnerabilities by severity
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

      case 'tech': {
        const t = data.tech;
        if (!t) return <div className="tab-content"><p className="no-data">No tech data available</p></div>;
        const NA_TEXT = 'Not publicly disclosed';
        const TechRow = ({ label, value }) => (
          <div className="tech-row">
            <span className="tech-label">{label}</span>
            <span className={`tech-value ${(!value || value === NA_TEXT) ? 'na' : ''}`}>
              {value || NA_TEXT}
            </span>
          </div>
        );
        const TagList = ({ items }) => items && items.length > 0
          ? <div className="tech-tags">{items.map((item, i) => <span key={i} className="tech-tag">{item}</span>)}</div>
          : <span className="tech-value na">{NA_TEXT}</span>;

        return (
          <div className="tab-content">
            <h3>Website Intelligence Report</h3>

            <div className="tech-grid">
              <div className="tech-card">
                <h4>Technology Stack</h4>
                <div className="tech-rows">
                  <div className="tech-row"><span className="tech-label">Frontend Framework</span><TagList items={t.frontend} /></div>
                  <div className="tech-row"><span className="tech-label">Backend / Server</span><TagList items={t.backend} /></div>
                  <TechRow label="CMS" value={t.cms} />
                  <TechRow label="CDN Provider" value={t.cdn} />
                  <div className="tech-row"><span className="tech-label">JS Libraries</span><TagList items={t.libraries} /></div>
                  <div className="tech-row"><span className="tech-label">Analytics Tools</span><TagList items={t.analytics} /></div>
                </div>
              </div>

              <div className="tech-card">
                <h4>Hosting & Network</h4>
                <div className="tech-rows">
                  <TechRow label="IP Address" value={t.ip} />
                  <TechRow label="Country" value={t.country} />
                  <TechRow label="City" value={t.city} />
                  <TechRow label="ISP / Hosting" value={t.isp} />
                  <TechRow label="Organization" value={t.org} />
                  <TechRow label="HTTP Version" value={t.http_version} />
                </div>
              </div>

              <div className="tech-card">
                <h4>Domain & Registration</h4>
                <div className="tech-rows">
                  <TechRow label="Registrar" value={t.domain_registrar} />
                  <TechRow label="Owner / Org" value={t.domain_owner} />
                  <TechRow label="Created" value={t.domain_created} />
                  <TechRow label="Expires" value={t.domain_expires} />
                  <div className="tech-row">
                    <span className="tech-label">Name Servers</span>
                    {t.domain_nameservers && t.domain_nameservers.length > 0
                      ? <div className="tech-tags">{t.domain_nameservers.map((ns, i) => <span key={i} className="tech-tag">{ns}</span>)}</div>
                      : <span className="tech-value na">{NA_TEXT}</span>}
                  </div>
                </div>
              </div>

              <div className="tech-card">
                <h4>SSL Certificate</h4>
                <div className="tech-rows">
                  <div className="tech-row">
                    <span className="tech-label">Status</span>
                    {t.ssl_valid === true
                      ? <span className="tech-tag" style={{background:'#1a5c3a',color:'#4ade80'}}>Valid</span>
                      : t.ssl_valid === false
                        ? <span className="tech-tag" style={{background:'#5c1a1a',color:'#f87171'}}>Invalid / None</span>
                        : <span className="tech-value na">{NA_TEXT}</span>}
                  </div>
                  <TechRow label="Issuer" value={t.ssl_issuer} />
                  <TechRow label="Expires" value={t.ssl_expires} />
                </div>
              </div>

              <div className="tech-card">
                <h4>Email Security</h4>
                <div className="tech-rows">
                  <TechRow label="Score" value={t.email_security_score} />
                  <div className="tech-row">
                    <span className="tech-label">SPF Record</span>
                    <span className={`tech-value ${t.spf === 'Not configured' ? 'na' : ''}`} style={{wordBreak:'break-all',fontSize:'0.78rem'}}>{t.spf || NA_TEXT}</span>
                  </div>
                  <div className="tech-row">
                    <span className="tech-label">DMARC Record</span>
                    <span className={`tech-value ${t.dmarc === 'Not configured' ? 'na' : ''}`} style={{wordBreak:'break-all',fontSize:'0.78rem'}}>{t.dmarc || NA_TEXT}</span>
                  </div>
                </div>
              </div>

              <div className="tech-card">
                <h4>Web Archive</h4>
                <div className="tech-rows">
                  <TechRow label="First Archived" value={t.wayback_first} />
                </div>
              </div>

              <div className="tech-card">
                <h4>Performance & Features</h4>
                <div className="tech-rows">
                  <TechRow label="Response Time" value={t.response_time_ms ? `${t.response_time_ms} ms` : null} />
                  <TechRow label="Page Size" value={t.page_size_kb ? `${t.page_size_kb} KB` : null} />
                  <div className="tech-row">
                    <span className="tech-label">Mobile Ready</span>
                    <span className={`tech-tag ${t.mobile_ready ? '' : 'tech-tag-warn'}`}>{t.mobile_ready ? 'Yes' : 'No'}</span>
                  </div>
                  <div className="tech-row">
                    <span className="tech-label">Cookie Consent</span>
                    <span className="tech-tag">{t.cookie_banner ? 'Detected' : 'Not detected'}</span>
                  </div>
                </div>
              </div>

              <div className="tech-card tech-card-full">
                <h4>Website Purpose</h4>
                <p className={`tech-purpose ${(!t.purpose || t.purpose === NA_TEXT) ? 'na' : ''}`}>{t.purpose || NA_TEXT}</p>
              </div>

              {t.social_links && t.social_links.length > 0 && (
                <div className="tech-card tech-card-full">
                  <h4>Social Media Presence</h4>
                  <div className="tech-tags">
                    {t.social_links.map((s, i) => (
                      <a key={i} href={s.url} target="_blank" rel="noopener noreferrer" className="tech-tag tech-tag-link">{s.platform}</a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        );
      }

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

      case 'headings':
        return (
          <div className="tab-content">
            <h3>Headings ({data.headings?.length || 0})</h3>
            {data.headings?.length > 0 ? (
              <div className="headings-list">
                {data.headings.map((heading, index) => (
                  <div key={index} className={`heading-item h${heading.level}`}>
                    <span className="heading-level">H{heading.level}</span>
                    <span className="heading-text">{heading.text}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-data">No headings found</p>
            )}
          </div>
        );

      case 'paragraphs':
        return (
          <div className="tab-content">
            <h3>Paragraphs ({data.paragraphs?.length || 0})</h3>
            {data.paragraphs?.length > 0 ? (
              <div className="paragraphs-list">
                {data.paragraphs.map((para, index) => (
                  <p key={index} className="paragraph-item">{para}</p>
                ))}
              </div>
            ) : (
              <p className="no-data">No paragraphs found</p>
            )}
          </div>
        );

      case 'links':
        return (
          <div className="tab-content">
            <h3>Links ({data.links?.length || 0})</h3>
            {data.links?.length > 0 ? (
              <div className="links-list">
                {data.links.map((link, index) => (
                  <div key={index} className="link-item">
                    <a href={link.url} target="_blank" rel="noopener noreferrer">
                      {link.text || link.url}
                    </a>
                    <span className="link-url">{link.url}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-data">No links found</p>
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
                            const el = e.currentTarget;
                            if (!el.dataset.usedProxy) {
                              el.dataset.usedProxy = 'true';
                              el.src = `${API_URL}/api/proxy-image?url=${encodeURIComponent(img.src)}`;
                            } else {
                              el.style.display = 'none';
                              const placeholder = el.parentElement.querySelector('.image-placeholder');
                              if (placeholder) {
                                placeholder.classList.add('failed');
                                placeholder.querySelector('span').textContent = '❌ Failed';
                              }
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

      case 'tables':
        return (
          <div className="tab-content">
            <h3>Tables ({data.tables?.length || 0})</h3>
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
            ) : (
              <p className="no-data">No tables found</p>
            )}
          </div>
        );

      case 'lists':
        return (
          <div className="tab-content">
            <h3>Lists</h3>
            {data.lists?.ul?.length > 0 && (
              <div className="lists-section">
                <h4>Unordered Lists ({data.lists.ul.length})</h4>
                {data.lists.ul.map((list, lIndex) => (
                  <ul key={lIndex} className="data-list">
                    {list.map((item, iIndex) => (
                      <li key={iIndex}>{item}</li>
                    ))}
                  </ul>
                ))}
              </div>
            )}
            {data.lists?.ol?.length > 0 && (
              <div className="lists-section">
                <h4>Ordered Lists ({data.lists.ol.length})</h4>
                {data.lists.ol.map((list, lIndex) => (
                  <ol key={lIndex} className="data-list">
                    {list.map((item, iIndex) => (
                      <li key={iIndex}>{item}</li>
                    ))}
                  </ol>
                ))}
              </div>
            )}
            {(!data.lists?.ul?.length && !data.lists?.ol?.length) && (
              <p className="no-data">No lists found</p>
            )}
          </div>
        );

      case 'fulltext':
        return (
          <div className="tab-content">
            <h3>Full Text Content</h3>
            <div className="full-text">
              {data.all_text?.split('\n').map((line, index) => (
                line.trim() && <p key={index}>{line}</p>
              ))}
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="App">
      <ToastContainer position="top-right" autoClose={3000} />

      <header className="app-header">
        <h1>VulnScan</h1>
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
                    Scanning...
                  </>
                ) : (
                  'Scan Website'
                )}
              </button>
            </div>
          </form>
        </section>

        {data && (
          <section className="results-section">
            <div className="results-header">
              <h2>Scanned Data</h2>
              <div className="export-buttons">
                <button onClick={handleExportCSV} className="export-btn csv-btn">Export CSV</button>
                <button onClick={handleExportDOC} className="export-btn doc-btn">Export DOC</button>
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
                    { key: 'tech', label: 'Tech Info' },
                    { key: 'seo', label: 'SEO' },
                    { key: 'headings', label: 'Headings' },
                    { key: 'paragraphs', label: 'Paragraphs' },
                    { key: 'links', label: 'Links' },
                    { key: 'images', label: 'Images' },
                    { key: 'tables', label: 'Tables' },
                    { key: 'lists', label: 'Lists' },
                    { key: 'fulltext', label: 'Full Text' },
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
                { id: 'tech', label: 'Tech Info' },
                { id: 'seo', label: 'SEO' },
                { id: 'headings', label: 'Headings' },
                { id: 'paragraphs', label: 'Paragraphs' },
                { id: 'links', label: 'Links' },
                { id: 'images', label: 'Images' },
                { id: 'tables', label: 'Tables' },
                { id: 'lists', label: 'Lists' },
                { id: 'fulltext', label: 'Full Text' },
              ].map((tab) => (
                <button
                  key={tab.id}
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
        <p>VulnScan &copy; 2024 - Website Security Vulnerability Scanner</p>
      </footer>
    </div>
  );
}

export default App;
