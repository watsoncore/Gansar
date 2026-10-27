(function () {
  'use strict';
  const translations = {
    ru: {
      close: 'Закрыть', close_preview: 'Закрыть просмотр', media_preview: 'Просмотр', media_open: 'Открыть изображение', media_alt: 'Эмма Уотсон', video_preview: 'Просмотр видео',
      hero_title: 'Исследование криптоадресов', hero_description: 'Анализ криптовалютных адресов, отслеживание движения средств, выявление связей между кошельками и атрибуция сервисов на основе данных блокчейна.', nav_about: 'О проекте', nav_contacts: 'Контакты', nav_support: 'Поддержать', nav_questions: 'Вопросы', nav_label: 'Навигация', go_to_contacts: 'Где нас найти',
      page_title: 'Gansar — О проекте', language_label: 'Язык', about_title: 'О проекте',
      about_description: 'Gansar помогает исследовать криптовалютные адреса, транзакции, финансовые связи и связанные Web3-объекты. Он объединяет публичные блокчейн-данные, графы, атрибуцию сервисов, NFT, Telegram Gifts и доказательства из доступных источников.',
      authors_title: 'Авторы', author_main: 'Основной разработчик', author_second: 'Второй разработчик',
      contacts_title: 'Где нас найти?', contact_channel: 'Наш канал', contact_personal: 'Моя личка в Telegram', open_telegram: 'Открыть в Telegram',
      support_title: 'Поддержать проект', support_note: 'Добровольная поддержка разработки.', copy: 'Копировать', copied: 'Скопировано',
      copied_status: 'Адрес скопирован.', manual_copy: 'Автоматическое копирование недоступно. Полный адрес выделен — нажмите Ctrl+C или используйте меню копирования.',
      faq_title: 'Вопросы', faq_what_q: 'Что такое Gansar?', faq_what_a: 'Это локальный инструмент для исследования криптоадресов и связанных с ними операций, сервисов и Web3-активов. Результат собирается в интерактивный HTML-отчёт.',
      faq_networks_q: 'Какие сети поддерживаются?', faq_networks_a: 'TON, TRON, Ethereum, BNB Chain, Bitcoin, Solana, Dogecoin, Polygon, Arbitrum, Optimism и Avalanche. Возможности и покрытие источников различаются. Basenames разрешает имена Base, но полноценный сбор финансовой истории Base пока не реализован.',
      faq_sources_q: 'Какие данные использует Gansar?', faq_sources_a: 'Gansar анализирует криптовалютные адреса в различных блокчейн-сетях, собирая доступную историю транзакций, переводы средств, взаимодействия с другими кошельками, смарт-контракты и движение активов.\n\nОсобое внимание уделяется экосистеме TON: взаимодействиям с Crypto Bot и xRocket, NFT, коллекционным Telegram-юзернеймам, Telegram Gifts и истории их владения.\n\nИнструмент сопоставляет данные нескольких источников, выявляет финансовые связи, контрагентов и известные сервисы. Все полученные сведения объединяются в единое расследование с возможностью проверки исходных данных.',
      faq_explorer_q: 'Чем Gansar отличается от обычного блокчейн-эксплорера?', faq_explorer_a: 'Gansar ориентирован на глубокий анализ криптовалютных адресов с особым акцентом на блокчейн TON. Инструмент исследует историю транзакций, движение средств, связи между кошельками, взаимодействия с @xRocket и @CryptoBot, а также NFT, коллекционные Telegram-юзернеймы и Telegram Gifts.\n\nВ отличие от обычного эксплорера, Gansar объединяет доступные данные из нескольких источников и проводит максимально глубокий анализ одного адреса, представляя результаты через интерактивный 2D-граф, пространственный 3D-граф и подробное дерево транзакций. Это позволяет изучать не только отдельные операции, но и общую структуру финансовых связей, активов и взаимодействий с сервисами.',
      faq_accuracy_q: 'Насколько точны результаты?', faq_accuracy_a: 'Полнота зависит от доступности и покрытия источников. Подтверждённое состояние, сообщение провайдера и аналитическое предположение различаются. Профиль, имя или аватарка сами по себе не устанавливают личность владельца кошелька.',
      faq_emma_q: 'Почему на странице Эмма Уотсон?', faq_emma_a: 'Эмма Уотсон — мой личный источник вдохновения. Она занимает особое место в моей жизни и мотивирует меня развиваться, создавать новое и работать над своими проектами. Поэтому её образ стал частью Gansar.',
    },
    en: {
      close: 'Close', close_preview: 'Close preview', media_preview: 'Preview', media_open: 'Open image', media_alt: 'Emma Watson', video_preview: 'Video preview',
      hero_title: 'Crypto address investigations', hero_description: 'Analysis of cryptocurrency addresses, tracking of fund movements, identification of connections between wallets, and service attribution based on blockchain data.', nav_about: 'About', nav_contacts: 'Contacts', nav_support: 'Support', nav_questions: 'FAQ', nav_label: 'Navigation', go_to_contacts: 'Where to find us',
      page_title: 'Gansar — About', language_label: 'Language', about_title: 'About',
      about_description: 'Gansar helps investigate cryptocurrency addresses, transactions, financial connections and related Web3 objects. It combines public blockchain data, graphs, service attribution, NFTs, Telegram Gifts and evidence from available sources.',
      authors_title: 'Authors', author_main: 'Lead developer', author_second: 'Second developer',
      contacts_title: 'Where to find us', contact_channel: 'Our channel', contact_personal: 'My Telegram', open_telegram: 'Open in Telegram',
      support_title: 'Support the project', support_note: 'Voluntary support for development.', copy: 'Copy', copied: 'Copied',
      copied_status: 'Address copied.', manual_copy: 'Automatic copying is unavailable. The full address is selected — press Ctrl+C or use the copy menu.',
      faq_title: 'FAQ', faq_what_q: 'What is Gansar?', faq_what_a: 'A local tool for investigating crypto addresses and their transactions, services and Web3 assets. Results are collected in an interactive HTML report.',
      faq_networks_q: 'Which networks are supported?', faq_networks_a: 'TON, TRON, Ethereum, BNB Chain, Bitcoin, Solana, Dogecoin, Polygon, Arbitrum, Optimism and Avalanche. Capabilities and source coverage differ. Basenames resolves Base names, but full financial-history collection for Base is not implemented yet.',
      faq_sources_q: 'Which data does Gansar use?', faq_sources_a: 'Gansar analyzes cryptocurrency addresses across different blockchain networks, collecting available transaction histories, fund transfers, interactions with other wallets, smart contracts and asset movements.\n\nParticular attention is given to the TON ecosystem: interactions with Crypto Bot and xRocket, NFTs, collectible Telegram usernames, Telegram Gifts and their ownership histories.\n\nThe tool cross-references data from multiple sources, identifying financial connections, counterparties and known services. All collected information is brought together in a single investigation, with the ability to verify the original data.',
      faq_explorer_q: 'How does Gansar differ from a regular blockchain explorer?', faq_explorer_a: 'Gansar is designed for in-depth analysis of cryptocurrency addresses, with a particular focus on the TON blockchain. The tool investigates transaction history, fund movements, connections between wallets, interactions with @xRocket and @CryptoBot, as well as NFTs, collectible Telegram usernames and Telegram Gifts.\n\nUnlike a regular explorer, Gansar brings together available data from multiple sources and analyzes a single address in as much depth as possible, presenting the results through an interactive 2D graph, a spatial 3D graph and a detailed transaction tree. This makes it possible to examine both individual operations and the overall structure of financial connections, assets and interactions with services.',
      faq_accuracy_q: 'How accurate are the results?', faq_accuracy_a: 'Completeness depends on source availability and coverage. Verified state, provider reports and analytical hypotheses remain distinct. A profile, name or avatar alone does not identify the person controlling a wallet.',
      faq_emma_q: 'Why is Emma Watson on this page?', faq_emma_a: 'Emma Watson is a personal source of inspiration for me. She holds a special place in my life and motivates me to grow, create new things, and work on my projects. That\'s why her image has become part of Gansar.',
    }
  };
  const mediaKeys = Object.freeze(['background', 'portrait', 'gallery1', 'gallery2', 'motion1', 'motion2', 'kiss']);
  const imageExtensions = new Set(['jpg', 'jpeg', 'png', 'webp', 'gif']);
  const videoExtensions = new Set(['mp4', 'webm']);
  const declared = window.GANSAR_ABOUT_MEDIA?.slots || {};
  const media = Object.freeze(Object.fromEntries(mediaKeys.map(key => [key, declared[key] || {}])));
  const loadedMedia = new Map(), pendingMedia = new Map(), failedMedia = new Set(), copyTimers = new Map(), queue = [];
  const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const dialog = document.getElementById('mediaDialog'), dialogImage = document.getElementById('dialogImage'), closeButton = document.getElementById('closeMedia');
  let dialogVideo = document.getElementById('dialogVideo');
  if (!dialogVideo && dialog) { dialogVideo = document.createElement('video'); dialogVideo.id = 'dialogVideo'; dialogVideo.hidden = true; dialog.appendChild(dialogVideo); }
  let language = 'ru', copyStatusKey = '', previousFocus = null, activeMediaKey = '', activeLoads = 0, previewEpoch = 0, requestedPreviewKey = '';
  const visibleMedia = new Set(), t = key => translations[language][key] || translations.ru[key] || '';
  try { language = localStorage.getItem('gansar_about_language') === 'en' ? 'en' : 'ru'; } catch (_) { /* Local storage is optional in file mode. */ }

  function applyLanguage(next) {
    language = next === 'en' ? 'en' : 'ru';
    document.documentElement.lang = language; document.title = t('page_title');
    document.querySelectorAll('[data-i18n]').forEach(element => { if (t(element.dataset.i18n)) element.textContent = t(element.dataset.copyState === 'done' ? 'copied' : element.dataset.i18n); });
    document.querySelectorAll('[data-i18n-aria]').forEach(element => { if (t(element.dataset.i18nAria)) element.setAttribute('aria-label', t(element.dataset.i18nAria)); });
    document.querySelectorAll('[data-i18n-alt]').forEach(element => { if (t(element.dataset.i18nAlt)) element.alt = t(element.dataset.i18nAlt); });
    document.querySelectorAll('[data-language]').forEach(button => button.setAttribute('aria-pressed', button.dataset.language === language ? 'true' : 'false'));
    const status = document.getElementById('copyStatus'); if (status) status.textContent = copyStatusKey ? t(copyStatusKey) : '';
    for (const row of loadedMedia.values()) if (row.type === 'image') row.element.alt = t('media_alt');
    if (dialogImage) dialogImage.alt = t('media_alt');
    const title = document.getElementById('mediaDialogTitle'); if (title) title.textContent = activeMediaKey && loadedMedia.get(activeMediaKey)?.type === 'video' ? t('video_preview') : t('media_preview');
    try { localStorage.setItem('gansar_about_language', language); } catch (_) { /* No storage requirement. */ }
  }
  function selectAddress(input) {
    input.focus(); input.select();
    try { input.setSelectionRange(0, input.value.length); } catch (_) { /* Manual selection remains available. */ }
  }
  async function copyAddress(button) {
    const input = document.getElementById(button.dataset.copyTarget); if (!input) return;
    let copied = false; button.disabled = true;
    try { if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') { await navigator.clipboard.writeText(input.value); copied = true; } } catch (_) { copied = false; }
    if (!copied) { selectAddress(input); try { copied = typeof document.execCommand === 'function' && document.execCommand('copy') === true; } catch (_) { copied = false; } }
    button.disabled = false;
    if (copyTimers.has(button)) window.clearTimeout(copyTimers.get(button));
    if (copied) {
      button.dataset.copyState = 'done'; button.textContent = t('copied'); copyStatusKey = 'copied_status';
      copyTimers.set(button, window.setTimeout(() => { delete button.dataset.copyState; button.textContent = t('copy'); copyTimers.delete(button); }, 1700));
    } else { delete button.dataset.copyState; button.textContent = t('copy'); copyStatusKey = 'manual_copy'; selectAddress(input); }
    const status = document.getElementById('copyStatus'); if (status) status.textContent = t(copyStatusKey);
  }
  function toggleFaq(details) {
    const summary = details.querySelector('summary'), desired = !(details.dataset.targetOpen ? details.dataset.targetOpen === 'true' : details.open);
    const start = details.getBoundingClientRect().height;
    details._aboutAnimation?.cancel(); details.dataset.targetOpen = String(desired);
    if (motion.matches || typeof details.animate !== 'function') { details.open = desired; delete details.dataset.targetOpen; return; }
    if (desired) details.open = true;
    const end = desired ? details.scrollHeight : summary.getBoundingClientRect().height;
    details.style.overflow = 'hidden';
    const animation = details.animate([{height: start + 'px'}, {height: end + 'px'}], {duration: 260, easing: 'cubic-bezier(.2,.65,.3,1)'});
    details._aboutAnimation = animation;
    animation.onfinish = () => { details.open = desired; details.style.overflow = ''; delete details.dataset.targetOpen; details._aboutAnimation = null; };
    animation.oncancel = () => { details.style.overflow = ''; };
  }

  function validLocalFile(file) {
    return typeof file === 'string' && file.length <= 160 && !/[\\/:?#<>|"\u0000-\u001f]/.test(file) && !file.includes('..') && /\.(?:jpe?g|png|webp|gif|mp4|webm)$/i.test(file);
  }
  function safeCandidates(key) {
    const record = media[key]; if (!record || !Array.isArray(record.files)) return [];
    return [...new Set(record.files.slice(0, 8).filter(validLocalFile))].flatMap(file => {
      const extension = file.split('.').pop().toLowerCase(), type = videoExtensions.has(extension) ? 'video' : imageExtensions.has(extension) ? 'image' : '';
      if (!type || !['auto', type].includes(record.type) || key === 'background' && (type !== 'image' || extension === 'gif')) return [];
      return [{file, extension, type, url: 'assets/' + encodeURIComponent(file), animated: record.animated}];
    });
  }
  function refreshMediaState() {
    for (const key of mediaKeys) {
      const figure = document.querySelector('[data-media-key="' + key + '"]');
      document.body.classList.toggle('has-media-' + key, loadedMedia.has(key));
      if (figure) figure.classList.toggle('has-media', loadedMedia.has(key));
    }
    document.body.classList.toggle('has-background', loadedMedia.has('background'));
    document.querySelectorAll('[data-media-region]').forEach(region => { const children = [...region.querySelectorAll('[data-media-key]')]; region.hidden = !children.some(child => !child.hidden); });
  }
  function releaseVideo(video) {
    if (!video) return;
    try { video.pause(); } catch (_) { /* Cleanup is safe for an uninitialized element. */ }
    video.removeAttribute('src'); try { video.load(); } catch (_) { /* Some file contexts reject load after removal. */ }
  }
  function failSlot(key, element) {
    const row = loadedMedia.get(key); if (row?.element !== element) return;
    loadedMedia.delete(key); failedMedia.add(key); pendingMedia.delete(key); if (row.type === 'video') releaseVideo(element); else element.removeAttribute('src');
    element.remove?.(); const figure = document.querySelector('[data-media-key="' + key + '"]'); if (figure) figure.hidden = true;
    if (activeMediaKey === key) closePreview(); refreshMediaState();
  }
  function probeCandidate(key, candidate) {
    return new Promise(resolve => {
      const element = candidate.type === 'video' ? document.createElement('video') : new Image(); let finished = false;
      const timeout = window.setTimeout(() => finish(false), 8000);
      function finish(success) {
        if (finished) return; finished = true; window.clearTimeout(timeout);
        element.onload = null; element.onerror = null; element.onloadedmetadata = null;
        if (!success) { if (candidate.type === 'video') releaseVideo(element); else element.removeAttribute('src'); resolve(null); return; }
        resolve({key, ...candidate, element});
      }
      if (candidate.type === 'video') {
        element.muted = true; element.loop = true; element.playsInline = true; element.controls = false; element.preload = 'metadata';
        element.onloadedmetadata = () => finish(Boolean(element.videoWidth && element.videoHeight));
      } else {
        element.decoding = 'async'; element.loading = 'eager'; element.alt = t('media_alt');
        element.onload = () => finish(Boolean(element.naturalWidth && element.naturalHeight));
      }
      element.onerror = () => finish(false); element.src = candidate.url;
      if (candidate.type === 'video') { try { element.load(); } catch (_) { finish(false); } }
    });
  }
  async function loadSlot(key) {
    if (loadedMedia.has(key)) return loadedMedia.get(key);
    for (const candidate of safeCandidates(key)) {
      const row = await probeCandidate(key, candidate); if (!row) continue;
      if (key === 'background') {
        const background = document.getElementById('pageBackground'); if (!background) { row.element.removeAttribute('src'); return null; }
        background.style.backgroundImage = 'url("' + row.url + '")'; row.element.removeAttribute('src');
      } else {
        const figure = document.querySelector('[data-media-key="' + key + '"]'), mount = figure?.querySelector('[data-media-slot]');
        if (!figure || !mount) { if (row.type === 'video') releaseVideo(row.element); else row.element.removeAttribute('src'); return null; }
        if (!deferMotion(key,row)) mount.replaceChildren(row.element); row.element.className = 'media-asset'; row.element.dataset.sourceFile = row.file;
        figure.hidden = false; if(!row.deferred) figure.classList.remove('is-deferred'); row.element.onerror = () => failSlot(key, row.element);
      }
      loadedMedia.set(key, row); refreshMediaState();
      if (row.type === 'video') updateVideo(row); return row;
    }
    const figure = document.querySelector('[data-media-key="' + key + '"]'); if (figure) figure.hidden = true;
    refreshMediaState(); return null;
  }
  function pumpQueue() {
    while (activeLoads < 2 && queue.length) {
      const task = queue.shift(); activeLoads++;
      loadSlot(task.key).then(row => { if(!row) failedMedia.add(task.key); pendingMedia.delete(task.key); task.resolve(row); }, () => { failedMedia.add(task.key); pendingMedia.delete(task.key); task.resolve(null); }).finally(() => { activeLoads--; pumpQueue(); });
    }
  }
  function queueSlot(key) {
    if (!mediaKeys.includes(key) || failedMedia.has(key)) return Promise.resolve(null);
    if (loadedMedia.has(key)) return Promise.resolve(loadedMedia.get(key));
    if (pendingMedia.has(key)) return pendingMedia.get(key);
    const promise = new Promise(resolve => { queue.push({key, resolve}); }); pendingMedia.set(key, promise); pumpQueue(); return promise;
  }
  function deferMotion(key, row = loadedMedia.get(key)) {
    if (!motion.matches || media[key]?.animated !== true || row?.type !== 'image') return false;
    const figure = document.querySelector('[data-media-key="' + key + '"]'), mount = figure?.querySelector('[data-media-slot]'); if (!figure || !mount) return false;
    row.element.removeAttribute('src'); row.deferred = true;
    const text = document.createElement('span'); text.className = 'media-deferred'; text.dataset.i18n = 'media_open'; text.textContent = t('media_open');
    mount.replaceChildren(text); figure.hidden = false; figure.classList.add('is-deferred'); return true;
  }
  function updateMotionImage(row) {
    if (row.type !== 'image' || row.key === 'background') return;
    if (deferMotion(row.key,row)) return;
    if (row.deferred) { const figure = document.querySelector('[data-media-key="' + row.key + '"]'), mount = figure?.querySelector('[data-media-slot]'); row.element.src = row.url; mount?.replaceChildren(row.element); figure?.classList.remove('is-deferred'); row.deferred = false; }
  }

  function updateVideo(row) {
    if (row.type !== 'video') return;
    if (!motion.matches && !document.hidden && visibleMedia.has(row.key) && !activeMediaKey) { try { const attempt = row.element.play(); attempt?.catch?.(() => {}); } catch (_) {} }
    else { try { row.element.pause(); } catch (_) {} }
  }
  async function loadGallery() {
    for (const key of mediaKeys.filter(key => key !== 'background')) await queueSlot(key);
  }
  function clearPreviewElements() {
    if (dialogImage) { dialogImage.removeAttribute('src'); dialogImage.hidden = true; }
    if (dialogVideo) { releaseVideo(dialogVideo); dialogVideo.hidden = true; }
  }
  function closePreview() {
    if (!activeMediaKey && !requestedPreviewKey) return;
    previewEpoch++; activeMediaKey = ''; requestedPreviewKey = ''; clearPreviewElements();
    if (typeof dialog.close === 'function' && dialog.open) dialog.close(); else dialog.removeAttribute('open');
    dialog.classList.remove('fallback-dialog'); document.body.classList.remove('media-is-open');
    if (previousFocus && typeof previousFocus.focus === 'function') previousFocus.focus(); previousFocus = null;
    for (const row of loadedMedia.values()) updateVideo(row);
  }
  async function openPreview(key, trigger) {
    if (!mediaKeys.includes(key) || key === 'background') return;
    const epoch = ++previewEpoch; requestedPreviewKey = key;
    const row = loadedMedia.get(key) || await queueSlot(key); if (!row || epoch !== previewEpoch) { if(epoch===previewEpoch) requestedPreviewKey=''; return; }
    requestedPreviewKey = '';
    previousFocus = trigger || document.activeElement; activeMediaKey = key; clearPreviewElements();
    const title = document.getElementById('mediaDialogTitle'); if (title) title.textContent = t(row.type === 'video' ? 'video_preview' : 'media_preview');
    if (row.type === 'video') {
      dialogVideo.hidden = false; dialogVideo.controls = true; dialogVideo.muted = true; dialogVideo.loop = true; dialogVideo.playsInline = true; dialogVideo.src = row.url;
      if (!motion.matches) { try { const attempt = dialogVideo.play(); attempt?.catch?.(() => {}); } catch (_) {} }
    } else { dialogImage.hidden = false; dialogImage.alt = t('media_alt'); dialogImage.src = row.url; }
    for (const video of loadedMedia.values()) if (video.type === 'video') video.element.pause();
    if (typeof dialog.showModal === 'function') { try { dialog.showModal(); } catch (_) { dialog.setAttribute('open', ''); dialog.classList.add('fallback-dialog'); } }
    else { dialog.setAttribute('open', ''); dialog.classList.add('fallback-dialog'); }
    document.body.classList.add('media-is-open'); closeButton.focus();
  }
  function probeLogos() {
    const names = new Set(['ton.svg', 'tron.svg', 'bitcoin.svg', 'ethereum.svg', 'solana.svg', 'cryptobot.svg', 'xrocket.svg']);
    document.querySelectorAll('[data-crypto-logo]').forEach(image => {
      const value = image.dataset.cryptoLogo || '', file = value.replace(/^assets\/crypto\//, '');
      image.hidden = true; if (!names.has(file) || value !== 'assets/crypto/' + file) return;
      image.onload = () => { image.hidden = !(image.naturalWidth && image.naturalHeight); };
      image.onerror = () => { image.hidden = true; image.removeAttribute('src'); };
      image.src = value;
    });
  }
  function setupSectionEntrance() {
    if (motion.matches || typeof IntersectionObserver !== 'function') return;
    const seen = new WeakSet();
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries) {
        if (!entry.isIntersecting || seen.has(entry.target)) continue;
        seen.add(entry.target); observer.unobserve(entry.target);
        if (!motion.matches) entry.target.animate(
          [{opacity: .75, transform: 'translateY(4px)'}, {opacity: 1, transform: 'translateY(0)'}],
          {duration: 280, easing: 'ease-out'}
        );
      }
    }, {threshold: .08});
    document.querySelectorAll('.section-flow').forEach(section => {
      if (typeof section.animate === 'function') observer.observe(section);
    });
  }

  document.querySelectorAll('[data-language]').forEach(button => button.addEventListener('click', () => {
    applyLanguage(button.dataset.language);
    const main = document.querySelector('main');
    if (!motion.matches && typeof main?.animate === 'function') main.animate(
      [{opacity: .9}, {opacity: 1}], {duration: 170, easing: 'ease-out'}
    );
  }));
  document.querySelectorAll('[data-copy-target]').forEach(button => button.addEventListener('click', () => copyAddress(button)));
  document.querySelectorAll('.faq-item').forEach(details => details.querySelector('summary').addEventListener('click', event => { event.preventDefault(); toggleFaq(details); }));
  document.querySelectorAll('[data-media-open]').forEach(button => button.addEventListener('click', () => openPreview(button.dataset.mediaOpen, button)));
  dialogImage?.addEventListener('error', closePreview); dialogVideo?.addEventListener('error', closePreview);
  closeButton?.addEventListener('click', closePreview);
  dialog?.addEventListener('cancel', event => { event.preventDefault(); closePreview(); });
  dialog?.addEventListener('click', event => { if (event.target !== dialog) return; const b = dialog.getBoundingClientRect(); if (event.clientX < b.left || event.clientX > b.right || event.clientY < b.top || event.clientY > b.bottom) closePreview(); });
  document.addEventListener('keydown', event => {
    if (!activeMediaKey && !requestedPreviewKey) return;
    if (event.key === 'Escape') { event.preventDefault(); closePreview(); }
    else if (event.key === 'Tab') {
      const focusable = [closeButton, ...(dialogVideo && !dialogVideo.hidden && dialogVideo.controls ? [dialogVideo] : [])];
      if (focusable.length === 1) { event.preventDefault(); closeButton.focus(); }
      else if (event.shiftKey && document.activeElement === focusable[0]) { event.preventDefault(); focusable[focusable.length - 1].focus(); }
      else if (!event.shiftKey && document.activeElement === focusable[focusable.length - 1]) { event.preventDefault(); focusable[0].focus(); }
    }
  });
  document.addEventListener('visibilitychange', () => { for (const row of loadedMedia.values()) updateVideo(row); if (document.hidden && activeMediaKey && dialogVideo) dialogVideo.pause(); });
  motion.addEventListener?.('change', () => { for (const row of loadedMedia.values()) { updateVideo(row); updateMotionImage(row); } });
  window.addEventListener('pagehide', event => {
    closePreview(); clearPreviewElements();
    for (const row of loadedMedia.values()) if (row.type === 'video') {
      if (event.persisted) row.element.pause(); else releaseVideo(row.element);
    }
  });
  window.addEventListener('pageshow', event => {
    if (event.persisted) for (const row of loadedMedia.values()) updateVideo(row);
  });
  applyLanguage(language); probeLogos(); queueSlot('background'); setupSectionEntrance();
  if (typeof IntersectionObserver === 'function') {
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries) {
        const key = entry.target.dataset.mediaKey; if (!mediaKeys.includes(key)) continue;
        if (entry.isIntersecting) visibleMedia.add(key);
        else visibleMedia.delete(key);
        const row = loadedMedia.get(key); if (row) updateVideo(row);
      }
    }, {rootMargin: '160px'});
    document.querySelectorAll('[data-media-key]').forEach(figure => observer.observe(figure));
  } else { for (const key of mediaKeys) visibleMedia.add(key); }
  // Discovery is bounded and sequential: hidden figures cannot intersect until
  // their own file is known. Visibility observation controls video playback.
  loadGallery();
})();
