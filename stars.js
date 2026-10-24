// Public GitHub metadata only. No token is sent to the browser.
window.ArgoStars = {
  connect(projects, onChange) {
    const prefix = 'argo:github-stars:v1:';
    const ttl = 24 * 60 * 60 * 1000;
    const retryDelay = 60 * 60 * 1000;
    const read = key => { try { return JSON.parse(localStorage.getItem(key)); } catch { return null; } };
    const write = (key, data) => { try { localStorage.setItem(key, JSON.stringify(data)); } catch {} };
    const validCount = count => Number.isSafeInteger(count) && count >= 0;
    const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });
    const exact = new Intl.NumberFormat('en');
    const queue = [], queued = new Set();
    let running = 0;
    let pausedUntil = Number(read(prefix + 'pause')) || 0;
    const repoFor = project => project.dataset.repository;
    function paint(project, entry) {
      if (!entry || !validCount(entry.count) || !Number.isFinite(entry.fetchedAt)) return;
      project.dataset.stars = String(entry.count);
      const badge = project.querySelector('.project-stars');
      badge.querySelector('.star-count').textContent = compact.format(entry.count);
      badge.dataset.starSource = 'github';
      badge.title = `${exact.format(entry.count)} GitHub stars · checked ${new Date(entry.fetchedAt).toLocaleString('en')}`;
      badge.setAttribute('aria-label', badge.title);
    }
    for (const project of projects) paint(project, read(prefix + repoFor(project)));
    function enqueue(project) {
      const repo = repoFor(project);
      if (!repo || !/^[\w.-]+\/[\w.-]+$/.test(repo) || queued.has(repo)) return;
      const entry = read(prefix + repo);
      const age = Date.now() - entry?.fetchedAt;
      if (validCount(entry?.count) && age >= 0 && age < ttl) return;
      if (entry?.retryAt > Date.now() || pausedUntil > Date.now()) return;
      queued.add(repo); queue.push(project); pump();
    }
    function pause(response) {
      const reset = Number(response.headers.get('x-ratelimit-reset')) * 1000;
      const retry = Number(response.headers.get('retry-after')) * 1000;
      pausedUntil = Math.max(Date.now() + 60000, Math.min(Date.now() + ttl, reset || (Date.now() + (retry || retryDelay))));
      write(prefix + 'pause', pausedUntil);
    }
    async function refresh(project) {
      const repo = repoFor(project), key = prefix + repo;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      try {
        const response = await fetch(`https://api.github.com/repos/${repo}`, {
          credentials: 'omit', referrerPolicy: 'no-referrer', signal: controller.signal,
          headers: { Accept: 'application/vnd.github+json' }
        });
        if (response.status === 403 || response.status === 429) pause(response);
        if (!response.ok) throw Error('Repository metadata unavailable');
        const data = await response.json();
        if (!validCount(data.stargazers_count)) throw Error('Invalid star count');
        const entry = { count: data.stargazers_count, fetchedAt: Date.now() };
        write(key, entry); paint(project, entry); onChange();
        const remaining = response.headers.get('x-ratelimit-remaining');
        if (remaining !== null && Number(remaining) <= 1) pause(response);
      } catch {
        // Keep the displayed cache/snapshot and avoid retrying on every reload.
        write(key, { ...read(key), retryAt: Date.now() + retryDelay });
      } finally { clearTimeout(timeout); }
    }
    function pump() {
      while (running < 2 && queue.length && pausedUntil <= Date.now()) {
        running++;
        refresh(queue.shift()).finally(() => { running--; pump(); });
      }
    }
    if (typeof IntersectionObserver === 'function') {
      const observer = new IntersectionObserver(entries => {
        for (const entry of entries) if (entry.isIntersecting) { observer.unobserve(entry.target); enqueue(entry.target); }
      }, { rootMargin: '400px' });
      projects.forEach(project => observer.observe(project));
    } else projects.slice(0, 2).forEach(enqueue);
    return { refreshAll: () => projects.forEach(enqueue) };
  }
};
