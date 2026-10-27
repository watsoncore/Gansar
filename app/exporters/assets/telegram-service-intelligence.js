/* Isolated presentation of existing Crypto Bot / xRocket evidence. No attribution. */
(() => {
  'use strict';
  const root = document.getElementById('telegram-service-intelligence');
  if (!root) return;
  const $ = id => document.getElementById(id);
  const svg = $('tsiSvg'), stage = $('tsiStage');
  if (!svg || !stage) return;
  const names = {cryptobot: 'Crypto Bot', xrocket: 'xRocket'};
  const handles = {cryptobot: '@CryptoBot', xrocket: '@xRocket'};
  const colors = {cryptobot: '#64d47d', xrocket: '#64d47d'};
  const values = input => Array.isArray(input) ? input : input && typeof input === 'object' ? Object.values(input) : [];
  const text = value => value == null ? '' : String(value);
  const short = value => text(value).length > 24 ? text(value).slice(0, 10) + '…' + text(value).slice(-7) : text(value);
  const address = key => text(key).replace(/^[a-z]+:/, '');
  // Canonical keys and proof addresses stay raw; these helpers only present them.
  const presentation = () => window.GansarTonPresentation;
  const rawAccount = value => /^(?:ton:)?-?\d+:[0-9a-fA-F]{64}$/.test(text(value));
  const displayAddress = key => {
    const original = address(key), shown = presentation()?.address(original);
    return shown && !rawAccount(shown) ? shown : rawAccount(original) ? 'UNKNOWN' : original;
  };
  const displayShort = (key, head = 10, tail = 7) => {
    const shown = displayAddress(key);
    return presentation()?.short(shown, head, tail) || (shown.length > head + tail + 1 ? shown.slice(0, head) + '…' + shown.slice(-tail) : shown);
  };
  const displayText = value => presentation()?.text(value) ?? (rawAccount(value) ? 'UNKNOWN' : text(value));
  const displayDecimal = value => presentation()?.decimal(value) ?? text(value);
  const displayHref = validatedOriginal => validatedOriginal && (presentation()?.href(validatedOriginal) || validatedOriginal);
  const unique = items => [...new Set(items.filter(Boolean))];
  const assetText = key => {
    const [chain,kind,...contract] = text(key).split(':');
    if (kind === 'native') return ({ton:'TON',btc:'BTC',tron:'TRX',eth:'ETH',bsc:'BNB',polygon:'POL',arbitrum:'ETH',optimism:'ETH',avalanche:'AVAX'})[chain] || chain.toUpperCase();
    return tokenSymbols.get(key) || ('Token ' + short(contract.join(':')));
  };
  const identity = value => { let hash = 2166136261; for (const char of text(value)) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619); return (hash >>> 0).toString(36); };
  let publicUrls = new Set();
  const url = value => { try { const u = new URL(value); return ['https:', 'http:'].includes(u.protocol) && (publicUrls.has(value) || publicUrls.has(u.href)) ? u.href : null; } catch (_) { return null; } };
  const el = (tag, cls, label, parent) => { const node = document.createElement(tag); if (cls) node.className = cls; if (label != null) node.textContent = label; if (parent) parent.append(node); return node; };
  const sv = (tag, attrs, parent) => { const node = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, value); if (parent) parent.append(node); return node; };
  const button = (label, parent, action, cls = '') => { const b = el('button', 'tsi-button ' + cls, label, parent); b.type = 'button'; b.addEventListener('click', action); return b; };
  let payload;
  try { payload = typeof integratedNftPayload !== 'undefined' ? integratedNftPayload : JSON.parse($('nft-payload')?.textContent || '{}'); } catch (_) { payload = {}; }
  publicUrls = new Set(payload.public_urls || []);
  let artwork = {};
  try { artwork = JSON.parse($('tsiArtwork')?.textContent || '{}'); } catch (_) { /* neutral named fallback */ }
  const image = service => { const value = artwork[service]?.url; return typeof value === 'string' && /^data:image\/(png|jpeg|webp|gif|svg\+xml);/i.test(value) ? value : null; };
  const services = payload.services || {}, inference = services.inferential_intelligence || {};
  const proofs = new Map(values(services.evidence).map(row => [row.evidence_id, row]));
  const accountRecords = services.addresses || {};
  const targetKey = services.target_key;
  const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
  const tonKey = value => typeof value === 'string' && /^ton:-?\d+:[0-9a-f]{64}$/.test(value);
  const timestamp = value => typeof value === 'string' && /T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));
  // Keep the source decimal string exact; Number would round large amounts.
  const positiveAmount = value => typeof value === 'string' && /^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value) && /[1-9]/.test(value);
  const nativeUnits = value => typeof value === 'string' && /^\d+$/.test(value) ? BigInt(value) : Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
  const amountUnits = value => positiveAmount(value) && (value.split('.')[1] || '').length <= 9 ? BigInt(value.split('.')[0]) * 1000000000n + BigInt((value.split('.')[1] || '').padEnd(9, '0')) : null;
  // Additional account-chain gates bind every displayed transfer to retained
  // provider fields. A ticker, backend status flag or DTO alone is insufficient.
  const chainOf = key => text(key).split(':', 1)[0];
  const evmChains = new Set(['eth','bsc','polygon','arbitrum','optimism','avalanche']);
  const hashKey = value => {
    if (typeof value !== 'string') return '';
    if (/^(?:0x)?[a-fA-F0-9]{64}$/.test(value)) return value.replace(/^0x/,'').toLowerCase();
    if (!/^[A-Za-z0-9+/_-]{43}=?$/.test(value)) return '';
    try { const bytes=atob(value.replace(/-/g,'+').replace(/_/g,'/'));return bytes.length===32?[...bytes].map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(''):''; } catch (_) { return ''; }
  };
  const sameHash = (left, right) => Boolean(hashKey(left) && hashKey(left) === hashKey(right));
  const accountKey = value => {
    if (typeof value !== 'string') return false;
    const chain = chainOf(value), account = address(value);
    if (chain === 'ton') return tonKey(value);
    if (evmChains.has(chain)) return /^0x[0-9a-f]{40}$/.test(account);
    if (chain === 'tron') return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(account);
    if (chain === 'btc') return /^(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[ac-hj-np-z02-9]{11,71})$/.test(account);
    return false;
  };
  const integer = value => {
    if (typeof value === 'number') return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
    if (typeof value !== 'string' || value.length > 120 || !/^(?:\d+|0x[0-9a-fA-F]+)$/.test(value)) return null;
    try { return BigInt(value); } catch (_) { return null; }
  };
  const exactUnits = (value, decimals) => {
    const places = typeof decimals === 'string' && /^\d+$/.test(decimals) ? Number(decimals) : decimals;
    if (!Number.isSafeInteger(places) || places < 0 || places > 36 || !positiveAmount(value)) return null;
    const [whole, fraction = ''] = value.split('.');
    if (fraction.length > places && /[1-9]/.test(fraction.slice(places))) return null;
    return BigInt(whole) * 10n ** BigInt(places) + BigInt(fraction.slice(0, places).padEnd(places, '0') || '0');
  };
  const sameAmount = (wire, places, decimal) => integer(wire) !== null && exactUnits(decimal, places) !== null && integer(wire) === exactUnits(decimal, places);
  const tokenSymbols = new Map();
  const canonicalParty = (chain, value) => {
    const original = value && typeof value === 'object' ? value.address : value;
    if (typeof original !== 'string') return null;
    if (chain === 'ton') return targetAddressKey(original,'ton');
    if (chain === 'tron' && /^41[0-9a-fA-F]{40}$/.test(original)) {
      // Compare the exact 21-byte payload of a retained canonical address.
      // No address is generated from an unknown input or checksum guessed.
      const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
      for (const key of Object.keys(accountRecords)) {
        if (!key.startsWith('tron:') || !accountKey(key)) continue;
        let value=0n;for(const char of address(key))value=value*58n+BigInt(alphabet.indexOf(char));
        const hex=value.toString(16).padStart(50,'0');
        if(hex.length===50 && hex.slice(0,42)===original.toLowerCase())return key;
      }
      return null;
    }
    const key = chain + ':' + (evmChains.has(chain) ? original.toLowerCase() : original);
    return accountKey(key) ? key : null;
  };
  function boundSource(operation, proof) {
    const facts = proof?.facts, reference = facts?.raw_reference;
    const source = services.source_observations?.[reference?.source_observation_id];
    if (!facts || !reference || !Object.prototype.hasOwnProperty.call(reference,'context_key') || !source || !source.raw) return null;
    const chain = operation.blockchain, context = reference.context_key === null ? targetKey : reference.context_key;
    if (!scopedRecord(context) || ![operation.from_key, operation.to_key].includes(context) || source.context_key !== reference.context_key) return null;
    if (proof.relation !== 'inference_operation_observation' || proof.blockchain !== chain || facts.blockchain !== chain || source.blockchain !== chain) return null;
    if (!proof.source || source.source !== proof.source || facts.source_family !== proof.source || proof.url !== operation.source_url || source.url !== proof.url || facts.source_url !== proof.url || !url(proof.url)) return null;
    if (!sameHash(proof.transaction_hash, operation.transaction_hash) || !sameHash(source.transaction_hash, operation.transaction_hash)) return null;
    if (!['operation_id','transaction_hash','from_key','to_key','asset_key','amount_decimal','timestamp'].every(field => facts[field] === operation[field]) || facts.transaction_edge === false || facts.success === false) return null;
    if (source.raw.simulated === true || source.raw.emulated === true) return null;
    return source.raw;
  }
  function accountWireMatches(operation, raw) {
    const chain = operation.blockchain, asset = operation.asset_key, provider = raw.rpc_transaction || raw.provider_record || {};
    if (provider.simulated === true || provider.emulated === true) return false;
    // A real TX with an invented DTO time must not fabricate ordered routes.
    const wireTime = chain === 'ton' ? integer(raw.transfer?.transaction_now)
      : chain === 'tron' ? integer(provider.block_timestamp ?? provider.timestamp ?? provider.block_ts)
      : integer((raw.provider_record || {}).timeStamp ?? (raw.provider_record || {}).timestamp);
    let timeOK = wireTime !== null && wireTime * (chain === 'tron' ? 1n : 1000n) === BigInt(Date.parse(operation.timestamp));
    const block=raw.rpc_block, receiptTime=raw.receipt || raw.transaction_receipt || raw.rpc_receipt;
    if (!timeOK && evmChains.has(chain) && block && receiptTime && sameHash(block.hash,receiptTime.blockHash) && integer(block.number)!==null && integer(block.number)===integer(receiptTime.blockNumber)) {
      const at=integer(block.timestamp);timeOK=at!==null && at*1000n===BigInt(Date.parse(operation.timestamp));
    }
    if (!timeOK) return false;
    const ends = (from, to) => canonicalParty(chain,from) === operation.from_key && canonicalParty(chain,to) === operation.to_key;
    const remember = value => { if (typeof value === 'string' && value.length <= 32 && value.trim()) tokenSymbols.set(asset,value.trim()); return true; };
    if (chain === 'ton' && asset.startsWith('ton:token:')) {
      const transfer = raw.transfer || {}, meta = raw.metadata || {};
      if (!sameHash(transfer.transaction_hash,operation.transaction_hash) || transfer.transaction_aborted !== false || !ends(transfer.source,transfer.destination) || canonicalParty('ton',transfer.jetton_master) !== 'ton:' + asset.slice('ton:token:'.length)) return false;
      const item = [meta,...(Array.isArray(meta.token_info) ? meta.token_info : [])].find(row => row?.valid === true && row.type === 'jetton_masters');
      const places = item?.extra?.decimals ?? item?.decimals;
      return Boolean(item && sameAmount(transfer.amount, places, operation.amount_decimal) && remember(item.symbol || meta.symbol));
    }
    if (chain === 'tron') {
      if (!sameHash(provider.transaction_id || provider.txID || provider.hash, operation.transaction_hash) || provider.revert === true || provider.confirmed === false) return false;
      const ok = provider.contractRet === 'SUCCESS' || provider.finalResult === 'SUCCESS' || Array.isArray(provider.ret) && provider.ret.length && provider.ret.every(row=>row.contractRet === 'SUCCESS');
      if (!ok) return false;
      if (asset === 'tron:native') {
        const detail = provider.contractData || {};
        if (provider.contractType === 1 && ends(provider.ownerAddress || detail.owner_address,provider.toAddress || detail.to_address) && sameAmount(detail.amount ?? provider.amount,6,operation.amount_decimal)) return true;
        return (provider.raw_data?.contract || []).slice(0,32).some(wire=>wire?.type==='TransferContract' && ends(wire.parameter?.value?.owner_address,wire.parameter?.value?.to_address) && sameAmount(wire.parameter?.value?.amount,6,operation.amount_decimal));
      }
      const token = provider.tokenInfo || provider.token_info || {}, master = provider.contract_address || token.address || token.tokenId;
      return asset.startsWith('tron:token:') && canonicalParty(chain,master) === 'tron:' + asset.slice('tron:token:'.length) && text(provider.event_type || provider.type).toLowerCase() === 'transfer' && ends(provider.from_address || provider.from, provider.to_address || provider.to) && sameAmount(provider.quant ?? provider.value, token.tokenDecimal ?? token.decimals, operation.amount_decimal) && remember(token.tokenAbbr || token.symbol);
    }
    if (evmChains.has(chain)) {
      const receipt = raw.receipt || raw.transaction_receipt || raw.rpc_receipt || {};
      const receiptOK = sameHash(receipt.transactionHash,operation.transaction_hash) && integer(receipt.status) === 1n;
      const providerOK = sameHash(provider.hash || provider.transactionHash,operation.transaction_hash);
      const executionOK = receiptOK || provider.isError === '0' || provider.txreceipt_status === '1';
      if (asset === chain + ':native') return providerOK && executionOK && !text(raw.type).startsWith('internal') && provider.traceId == null && ends(provider.from,provider.to) && sameAmount(provider.value,18,operation.amount_decimal);
      if (!asset.startsWith(chain + ':token:')) return false;
      const master = asset.slice((chain + ':token:').length).toLowerCase();
      if (providerOK && executionOK && canonicalParty(chain,provider.contractAddress || provider.address) === chain + ':' + master && ends(provider.from,provider.to) && sameAmount(provider.value,provider.tokenDecimal ?? raw.decimals,operation.amount_decimal)) return remember(provider.tokenSymbol || raw.token_symbol);
      if (receiptOK) for (const log of Array.isArray(receipt.logs) ? receipt.logs : []) {
        const topics = log?.topics || [];
        if (log?.removed === true || topics.length !== 3 || topics[0]?.toLowerCase() !== '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef' || canonicalParty(chain,log.address) !== chain + ':' + master || !sameHash(log.transactionHash,operation.transaction_hash)) continue;
        if (!topics.slice(1).every(value=>/^0x[0-9a-fA-F]{64}$/.test(value))) continue;
        if (ends('0x'+topics[1].slice(-40),'0x'+topics[2].slice(-40)) && sameAmount(log.data,raw.decimals ?? raw.token_decimal,operation.amount_decimal)) return remember(raw.token_symbol || raw.provider_record?.tokenInfo?.symbol);
      }
    }
    return false;
  }
  function validatedAccountOperation(operation) {
    if (!scopedTarget || !operation || operation.transaction_edge === false || operation.success === false || !hashKey(operation.transaction_hash) || !operation.operation_id || !accountKey(operation.from_key) || !accountKey(operation.to_key) || operation.from_key === operation.to_key || chainOf(operation.from_key) !== operation.blockchain || chainOf(operation.to_key) !== operation.blockchain || !positiveAmount(operation.amount_decimal) || !timestamp(operation.timestamp) || !url(operation.source_url)) return null;
    const bound = (operation.evidence_ids || []).map(ref=>proofs.get(ref)).filter(proof=>{const raw=boundSource(operation,proof);return raw && accountWireMatches(operation,raw);});
    return bound.length ? {physicalId:operation.blockchain+':'+operation.operation_id,proofRefs:bound.map(proof=>proof.evidence_id),blockchain:operation.blockchain} : null;
  }
  function validatedOperation(operation) {
    if (!operation) return null;
    const scoped = {...operation,blockchain:operation.blockchain || chainOf(operation.from_key)};
    return scoped.blockchain === 'ton' && scoped.asset_key === 'ton:native' ? validatedNativeOperation(scoped) : validatedAccountOperation(scoped);
  }

  const scopedRecord = key => accountKey(key) && accountRecords[key]?.blockchain === chainOf(key) && accountRecords[key]?.address === address(key);
  function targetAddressKey(value, chain = chainOf(targetKey)) {
    if (chain !== 'ton') return canonicalParty(chain,value);
    if (typeof value === 'string' && tonKey('ton:' + value.trim().toLowerCase())) return 'ton:' + value.trim().toLowerCase();
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{48}$/.test(value)) return null;
    try {
      const bytes = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));
      if (bytes.length !== 36 || ![0x11, 0x51].includes(bytes[0] & 0x7f)) return null;
      let crc = 0;
      for (const byte of bytes.slice(0, 34)) { crc ^= byte << 8; for (let bit = 0; bit < 8; bit++) crc = crc & 0x8000 ? (crc << 1 ^ 0x1021) & 0xffff : crc << 1 & 0xffff; }
      if (bytes[34] !== crc >> 8 || bytes[35] !== (crc & 255)) return null;
      return 'ton:' + (bytes[1] > 127 ? bytes[1] - 256 : bytes[1]) + ':' + [...bytes.slice(2, 34)].map(byte => byte.toString(16).padStart(2, '0')).join('');
    } catch (_) { return null; }
  }
  const contextTargets = services.investigation_context?.target_keys;
  const reportTargetKey = targetAddressKey(typeof reportTargetAddress !== 'undefined' ? reportTargetAddress : payload.report?.target_address);
  const scopedTarget = scopedRecord(targetKey) && targetAddressKey(services.target_address) === targetKey && reportTargetKey === targetKey && (!Array.isArray(contextTargets) || contextTargets.includes(targetKey));
  const relationMap = new Map();
  for (const row of [...values(services.relationships), ...values(inference.relationships)]) {
    if (row && names[row.service_id] && row.relationship_id && !relationMap.has(row.relationship_id)) relationMap.set(row.relationship_id, row);
  }
  const relations = [...relationMap.values()];
  const model = {nodes: new Map(), edges: new Map(), operations: new Map(), routes: new Map(), anchors: new Map(), candidates: new Map(), rejected: 0, rejectedRelations: 0};
  const relationAnchors = new Map();
  const publication = (proof, service) => {
    const official=proof?.source==='official_service_publication' && proof.relation==='official_published_address_role';
    const labelled=proof?.source==='public_service_address_label' && proof.relation==='published_exact_address_label';
    if (!scopedTarget || !(official||labelled) || proof.upstream!==service || !url(proof.url)) return false;
    const key=proof.blockchain+':'+proof.address,record=accountRecords[key],facts=proof.facts;
    if (!scopedRecord(key) || proof.blockchain!==chainOf(targetKey) || !facts?.role || !digest(facts.capture_sha256) || official&&!timestamp(facts.source_published_at) || labelled&&!timestamp(proof.observed_at)) return false;
    return values(record.attributions).some(claim=>claim.method===(official?'cryptobot_xrocket_exact_publication':'cryptobot_xrocket_exact_public_label') && claim.status===(official?'CONFIRMED':'PROBABLE') && claim.claim_category===(official?'CONFIRMED SERVICE ADDRESS':'PUBLICLY LABELLED SERVICE ADDRESS') && claim.service_id===service && claim.blockchain===proof.blockchain && claim.address===proof.address && claim.source_url===proof.url && claim.evidence_ids?.includes(proof.evidence_id));
  };
  for (const rel of relations) {
    const candidateRelation = rel.category === 'POSSIBLE SERVICE INFRASTRUCTURE';
    const knownMethod = rel.method === (candidateRelation ? 'cryptobot_xrocket_collected_infrastructure_discovery' : 'cryptobot_xrocket_evidence_projection');
    const knownStatus = candidateRelation || rel.category === 'INDIRECT SERVICE CONNECTION' ? rel.status === 'POSSIBLE' : (['DIRECT SERVICE INTERACTION','CONFIRMED SERVICE ADDRESS','PUBLICLY LABELLED SERVICE ADDRESS'].includes(rel.category) && ['CONFIRMED','PROBABLE'].includes(rel.status));
    if (!knownMethod || !knownStatus || (!candidateRelation && targetAddressKey(rel.target_address) !== targetKey)) { model.rejectedRelations++; continue; }
    for (const ref of rel.evidence_ids || []) {
      const proof = proofs.get(ref);
      if (publication(proof, rel.service_id)) {
        const key = proof.blockchain + ':' + proof.address;
        const cited = rel.service_address || rel.candidate?.official_anchor_address;
        if (cited === proof.address && (!['DIRECT SERVICE INTERACTION','CONFIRMED SERVICE ADDRESS','PUBLICLY LABELLED SERVICE ADDRESS'].includes(rel.category) || rel.status===(proof.source==='official_service_publication'?'CONFIRMED':'PROBABLE'))) { model.anchors.set(key, {service: rel.service_id, proof, key, status:proof.source==='official_service_publication'?'CONFIRMED':'PROBABLE'}); relationAnchors.set(rel.relationship_id, key); }
      }
    }
    if (!relationAnchors.has(rel.relationship_id)) model.rejectedRelations++;
  }
  function node(key, service) {
    if (!scopedRecord(key)) return null;
    if (!model.nodes.has(key)) model.nodes.set(key, {key, address: address(key), chain: key.split(':')[0], services: new Set(), refs: new Set(), relations: new Set(), x: 0, y: 0, vx: 0, vy: 0, pinned: false});
    const item = model.nodes.get(key); if (service) item.services.add(service); return item;
  }
  function nativeExecution(native) {
    const desc=native?.description || {}, phases=[native?.compute_phase,native?.action_phase,desc.compute_ph,desc.action];
    if (!native || native.success===false || native.aborted===true || desc.aborted===true || phases.some(p=>p && (p.success===false || p.no_funds===true || p.valid===false))) return false;
    return native.success===true || desc.aborted===false && desc.compute_ph?.success===true && desc.action?.success===true;
  }
  function validatedNativeOperation(operation) {
    if (!scopedTarget || !operation || operation.transaction_edge === false || operation.success === false || !/^ton:message:[0-9a-f]{64}$/.test(operation.operation_id || '') || !digest(operation.transaction_hash) || !tonKey(operation.from_key) || !tonKey(operation.to_key) || operation.from_key === operation.to_key || operation.asset_key !== 'ton:native' || !positiveAmount(operation.amount_decimal) || !timestamp(operation.timestamp) || !url(operation.source_url) || operation.blockchain != null && operation.blockchain !== 'ton') return null;
    const refs = (operation.evidence_ids || []).filter(ref => proofs.has(ref));
    const bound = refs.map(ref => proofs.get(ref)).filter(proof => {
      const facts = proof?.facts, reference = facts?.raw_reference;
      if (!facts || facts.transaction_edge === false || facts.success !== true || proof.relation !== 'inference_operation_observation' || proof.blockchain !== 'ton' || facts.blockchain !== 'ton' || !proof.source || proof.source !== facts.source_family || proof.url !== operation.source_url || facts.source_url !== operation.source_url || proof.transaction_hash !== operation.transaction_hash) return false;
      if (!['operation_id', 'transaction_hash', 'from_key', 'to_key', 'asset_key', 'amount_decimal', 'timestamp'].every(key => facts[key] === operation[key]) || !digest(facts.message_hash) || operation.operation_id !== 'ton:message:' + facts.message_hash || operation.message_hash != null && operation.message_hash !== facts.message_hash) return false;
      const observation = services.source_observations?.[reference?.source_observation_id], native = observation?.raw?.transaction;
      if (!reference || !Object.prototype.hasOwnProperty.call(reference, 'context_key') || !observation || observation.context_key !== reference.context_key || observation.source !== proof.source || observation.url !== proof.url || observation.blockchain !== 'ton' || observation.transaction_hash !== operation.transaction_hash || !native || !sameHash(native.hash,operation.transaction_hash) || !nativeExecution(native) || native.aborted === true || native.emulated === true || native.simulated === true || observation.raw.emulated === true || observation.raw.simulated === true) return false;
      if (native.description?.aborted === true || !Number.isSafeInteger(native.utime ?? native.now) || (native.utime ?? native.now) * 1000 !== Date.parse(operation.timestamp)) return false;
      const account = typeof native.account === 'object' ? native.account?.address : native.account;
      const accountKey = canonicalParty('ton',account), contextKey = reference.context_key === null ? targetKey : reference.context_key;
      if (!scopedRecord(contextKey) || accountKey !== contextKey || ![operation.from_key, operation.to_key].includes(accountKey)) return false;
      // Verify the existing native message identity/endpoints; protocol and
      // asset interpretation remain the already validated backend's job.
      return [native.in_msg, ...(Array.isArray(native.out_msgs) ? native.out_msgs : [])].some(message => {
        const source = typeof message?.source === 'object' ? message.source?.address : message?.source;
        const destination = typeof message?.destination === 'object' ? message.destination?.address : message?.destination;
        return sameHash(message?.hash,facts.message_hash) && canonicalParty('ton',source) === operation.from_key && canonicalParty('ton',destination) === operation.to_key && message.bounced !== true && nativeUnits(message.value) !== null && nativeUnits(message.value) === amountUnits(operation.amount_decimal);
      });
    });
    return bound.length ? {physicalId: bound[0].facts.message_hash, proofRefs: bound.map(proof => proof.evidence_id), blockchain: bound[0].facts.blockchain} : null;
  }
  function addOperation(operation, rel, kind) {
    const verified = validatedOperation(operation);
    if (!verified) { model.rejected++; return null; }
    const refs = verified.proofRefs;
    const from = node(operation.from_key, rel.service_id), to = node(operation.to_key, rel.service_id);
    if (!from || !to || from === to) return null;
    const pid = verified.physicalId, edgeKey = [from.key, to.key, operation.asset_key].join('|');
    const previous = model.operations.get(pid);
    if (previous && !['from_key', 'to_key', 'asset_key', 'amount_decimal', 'timestamp'].every(key => previous[key] === operation[key])) { model.rejected++; return null; }
    if (!model.edges.has(edgeKey)) model.edges.set(edgeKey, {id: 'tsi-edge-' + identity(edgeKey), from, to, asset: operation.asset_key, operations: new Map(), services: new Set(), kinds: new Set(), relationIds: new Set()});
    const edge = model.edges.get(edgeKey);
    edge.services.add(rel.service_id); edge.kinds.add(kind); edge.relationIds.add(rel.relationship_id);
    if (!previous) model.operations.set(pid, {...operation, success: true, blockchain: verified.blockchain, physicalId: pid, proofRefs: refs, edgeId: edge.id});
    else previous.proofRefs = unique([...previous.proofRefs, ...refs]);
    edge.operations.set(pid, model.operations.get(pid));
    for (const item of [from, to]) { refs.forEach(ref => item.refs.add(ref)); item.relations.add(rel.relationship_id); }
    return pid;
  }
  function addRoute(edges, rel, kind, original) {
    if (!Array.isArray(edges) || !edges.length) return null;
    const invalid = edges.filter(op => !validatedOperation(op)).length;
    if (invalid) { model.rejected += invalid; return null; }
    if (edges.some((op, i) => i && (edges[i - 1].to_key !== op.from_key || edges[i - 1].asset_key !== op.asset_key || Date.parse(edges[i - 1].timestamp) > Date.parse(op.timestamp)))) { model.rejected++; return null; }
    const ids = edges.map(op => addOperation(op, rel, kind));
    if (ids.some(id => !id)) return null;
    const key = [rel.service_id, ...ids].join('|');
    if (model.routes.has(key)) { model.routes.get(key).kinds.add(kind); return model.routes.get(key); }
    const route = {id: 'tsi-route-' + identity(key), service: rel.service_id, kinds: new Set([kind]), physicalIds: ids,
      nodes: [edges[0].from_key, ...edges.map(op => op.to_key)], status: original?.status || rel.status,
      refs: unique([...(rel.evidence_ids || []), ...(original?.evidence_ids || [])]), relation: rel, original};
    model.routes.set(key, route); return route;
  }
  function rememberCandidate(candidate) {
    const prior=model.candidates.get(candidate.address_key);
    if(!prior){model.candidates.set(candidate.address_key,{...candidate,candidate_groups:[candidate]});return;}
    if(prior.candidate_groups.some(row=>row.candidate_id===candidate.candidate_id))return;
    const groups=[...prior.candidate_groups,candidate],sequences=[...new Map(groups.flatMap(row=>row.observed_sequences||[]).map(row=>[row.sequence_id,row])).values()];
    const operations=[...new Map(groups.flatMap(row=>row.role_operations||[]).map(row=>[row.operation_id,row])).values()];
    const hashes=unique(operations.map(row=>row.transaction_hash));
    model.candidates.set(candidate.address_key,{...prior,candidate_groups:groups,roles:unique(groups.flatMap(row=>row.roles||[])),
      observed_sequences:sequences,role_operations:operations,evidence_ids:unique(groups.flatMap(row=>row.evidence_ids||[])),
      first_observed:groups.map(row=>row.first_observed).sort()[0],last_observed:groups.map(row=>row.last_observed).sort().at(-1),
      observations:{...prior.observations,independent_transaction_count:hashes.length,physical_message_count:operations.filter(row=>row.message_hash).length},
      alternative_explanations:unique(groups.flatMap(row=>row.alternative_explanations||[]))});
  }
  for (const rel of relations) {
    if (!relationAnchors.has(rel.relationship_id)) continue;
    const kind = rel.category === 'POSSIBLE SERVICE INFRASTRUCTURE' ? 'possible' : rel.category === 'INDIRECT SERVICE CONNECTION' ? 'indirect' : 'direct';
    // Analytical associations never become monetary source→anchor edges.
    if (rel.transaction_edge !== false && rel.scope !== 'service_role_hypothesis' && rel.category !== 'POSSIBLE SERVICE INFRASTRUCTURE' && Array.isArray(rel.edges) && rel.edges.length && [rel.edges[0].from_key, rel.edges.at(-1).to_key].includes(relationAnchors.get(rel.relationship_id)) && [rel.edges[0].from_key, rel.edges.at(-1).to_key].includes(targetKey)) addRoute(rel.edges, rel, kind, rel);
    if (rel.candidate) {
      const candidate = rel.candidate;
      if (rel.category !== 'POSSIBLE SERVICE INFRASTRUCTURE' || candidate.status !== 'POSSIBLE' || candidate.service_id !== rel.service_id || !accountKey(candidate.address_key) || candidate.address !== address(candidate.address_key)) { model.rejectedRelations++; continue; }
      const anchorKey = relationAnchors.get(rel.relationship_id);
      const routes = (candidate.service_routes || []).filter(route => Array.isArray(route.edges) && route.edges.length && route.edges.every(op => validatedOperation(op)) && [route.edges[0].from_key, route.edges.at(-1).to_key].includes(anchorKey) && route.edges.some(op => [op.from_key, op.to_key].includes(candidate.address_key)));
      if (!routes.length) { model.rejectedRelations++; continue; }
      for (const op of candidate.role_operations || []) if ([op.from_key, op.to_key].includes(candidate.address_key)) addOperation(op, rel, 'possible');
      for (const route of routes) if (addRoute(route.edges, rel, route.edges.length > 1 ? 'indirect' : 'direct', route)) rememberCandidate(candidate);
    }
  }
  // Insert after account/native proof helpers, before hasValidResults. Never call addOperation/node here.
  const utxoUnits = value => typeof value === 'string' && /^(?:0(?:\.0+)?)$/.test(value) ? 0n : exactUnits(value, 8);
  function utxoRowsMatch(rows, nativeRows, input) {
    if (!Array.isArray(rows) || !Array.isArray(nativeRows) || rows.length !== nativeRows.length || !rows.length) return false;
    return rows.every((row, index) => {
      const wire = input ? nativeRows[index]?.prevout : nativeRows[index];
      if (!row || !wire || wire.value == null || integer(wire.value) === null || utxoUnits(row.value_decimal) !== integer(wire.value)) return false;
      const party = wire.scriptpubkey_address == null ? null : canonicalParty('btc', wire.scriptpubkey_address);
      if (wire.scriptpubkey_address != null && !party || row.address_key !== party || typeof wire.scriptpubkey !== 'string' || row.script !== wire.scriptpubkey) return false;
      return input ? Boolean(hashKey(row.prev_tx_hash) && hashKey(row.prev_tx_hash) === hashKey(nativeRows[index].txid) && Number.isSafeInteger(row.prev_index) && row.prev_index >= 0 && row.prev_index === nativeRows[index].vout)
        : Number.isSafeInteger(row.index) && row.index === index;
    });
  }
  function validateUtxoConnection(row) {
    if (!scopedTarget || !scopedRecord(targetKey) || !targetKey.startsWith('btc:') || !row || row.target_key !== targetKey || row.blockchain !== 'btc' || !names[row.service_id] || !hashKey(row.transaction_hash) || !row.relationship_id || row.transaction_edge !== false || row.allocation !== 'UNKNOWN' || row.ownership !== 'UNKNOWN' || row.service_address_control !== 'UNKNOWN' || row.endpoint_role !== 'AMBIGUOUS') return null;
    if (row.category !== 'OFFICIALLY CITED CONSOLIDATION TRANSACTION' || row.status !== 'CONFIRMED' || row.claim_scope !== 'historical_published_transaction_only' || !timestamp(row.timestamp) || !timestamp(row.source_published_at) || !url(row.source_url) || !url(row.service_publication_url)) return null;
    if (![...values(row.inputs), ...values(row.outputs)].some(item => item?.address_key === targetKey)) return null;
    const nativeRefs = values(row.evidence_ids).filter(ref => {
      const proof = proofs.get(ref), facts = proof?.facts, pointer = facts?.raw_reference;
      const source = services.source_observations?.[pointer?.source_observation_id], raw = source?.raw, native = raw?.provider_record;
      if (!proof || !facts || !pointer || !Object.prototype.hasOwnProperty.call(pointer, 'context_key') || !source || !native) return false;
      const context = pointer.context_key === null ? targetKey : pointer.context_key;
      if (!scopedRecord(context) || source.context_key !== pointer.context_key || ![...values(row.inputs), ...values(row.outputs)].some(item => item?.address_key === context)) return false;
      if (proof.relation !== 'utxo_bipartite_observation' || proof.blockchain !== 'btc' || facts.blockchain !== 'btc' || source.blockchain !== 'btc' || !proof.source || source.source !== proof.source || source.url !== proof.url || proof.url !== row.source_url) return false;
      if (![proof.transaction_hash, facts.transaction_hash, source.transaction_hash, native.txid].every(value => hashKey(value) && hashKey(value) === hashKey(row.transaction_hash)) || facts.transaction_key !== 'btc:tx:' + hashKey(row.transaction_hash)) return false;
      if (native.status?.confirmed !== true || facts.success !== true || raw.simulated === true || raw.emulated === true || native.simulated === true || native.emulated === true || facts.allocation !== 'UNKNOWN' || facts.ownership !== 'UNKNOWN') return false;
      if (facts.timestamp !== row.timestamp || !Number.isSafeInteger(native.status.block_time) || native.status.block_time * 1000 !== Date.parse(row.timestamp)) return false;
      return utxoRowsMatch(row.inputs, native.vin, true) && utxoRowsMatch(row.outputs, native.vout, false)
        && utxoRowsMatch(facts.inputs, native.vin, true) && utxoRowsMatch(facts.outputs, native.vout, false);
    });
    const publicationRefs = values(row.publication_evidence_ids).filter(ref => {
      const proof = proofs.get(ref), facts = proof?.facts;
      if (!proof || proof.relation !== 'official_published_service_transaction' || proof.source !== 'official_service_transaction_publication' || proof.upstream !== row.service_id || proof.blockchain !== 'btc' || !hashKey(proof.transaction_hash) || hashKey(proof.transaction_hash) !== hashKey(row.transaction_hash) || proof.url !== row.service_publication_url || !facts || !digest(facts.capture_sha256)) return false;
      if (facts.claim_scope !== 'published_transaction_only' || facts.role !== 'officially_published_historical_deposit_consolidation' || facts.source_published_at !== row.source_published_at || facts.endpoint_role !== 'AMBIGUOUS' || facts.current_address_control !== 'UNKNOWN') return false;
      try {
        const link = new URL(proof.url), channel = row.service_id === 'cryptobot' ? 'CryptoBotEN' : 'xrocketnews';
        return link.protocol === 'https:' && link.hostname === 't.me' && !link.username && !link.password && !link.port && !link.search && !link.hash && new RegExp('^/' + channel + '/[0-9]+$').test(link.pathname);
      } catch (_) { return false; }
    });
    return nativeRefs.length && publicationRefs.length ? {...row, proofRefs: unique([...nativeRefs, ...publicationRefs])} : null;
  }
  const validatedUtxoConnections = [...new Map(values(services.telegram_service_intelligence?.utxo_connections)
    .map(validateUtxoConnection).filter(Boolean).map(row => [row.service_id + ':' + hashKey(row.transaction_hash), row])).values()];
  const validatedUtxoConnectionCount = validatedUtxoConnections.length;
  function appendUtxoConnections(parent) {
    let count = 0;
    for (const row of validatedUtxoConnections) {
      if (root.querySelector('[data-tsi-filter="' + row.service_id + '"]')?.checked === false) continue;
      count++;
      const card = el('details', 'tsi-tx-row', null, parent);
      card.dataset.tsiUtxo = row.relationship_id;
      el('summary', '', names[row.service_id] + ' · BTC · опубликованный исторический TX', card);
      card.addEventListener('toggle', () => {
        if (!card.open || card.dataset.loaded) return;
        card.dataset.loaded = '1';
        field(card, 'Что подтверждено', 'Оператор опубликовал именно этот исторический TX; адрес цели присутствует в его нативных inputs/outputs.');
        field(card, 'TX', row.transaction_hash, true);
        field(card, 'UTC', row.timestamp);
        field(card, 'Публикация', row.source_published_at);
        field(card, 'Владелец / контроль адреса', 'UNKNOWN');
        field(card, 'Распределение input → output / роли выходов', 'UNKNOWN · конкретный денежный маршрут между кошельками не установлен');
        for (const [label, rows, input] of [['Inputs', row.inputs, true], ['Outputs', row.outputs, false]]) {
          const list = el('details', '', null, card);
          el('summary', '', label + ' · ' + rows.length, list);
          for (const item of rows) {
            const record = el('div', 'tsi-detail-field', null, list);
            field(record, 'Адрес', item.address_key ? address(item.address_key) : 'Script без адреса', true);
            field(record, 'Точное значение BTC', item.value_decimal);
            if (input) field(record, 'Предыдущий outpoint', item.prev_tx_hash + ':' + item.prev_index, true);
            else field(record, 'Индекс выхода', item.index);
            field(record, 'Script', item.script, true);
          }
        }
        for (const [label, href] of [['Источник нативного TX ↗', row.source_url], ['Публикация оператора ↗', row.service_publication_url]]) {
          const link = el('a', 'tsi-link', label, card); link.href = url(href); link.target = '_blank'; link.rel = 'noopener noreferrer';
        }
        const proof = el('details', '', null, card); el('summary', '', 'Сохранённые доказательства', proof); evidenceList(row.proofRefs, proof);
      });
    }
    return count;
  }

  const hasValidResults = model.operations.size > 0 || model.anchors.size > 0 || validatedUtxoConnections.length > 0;
  if ((model.operations.size || model.anchors.size) && scopedTarget) node(targetKey);
  for (const [key, anchor] of model.anchors) { const item = node(key, anchor.service); item.anchor = anchor; item.refs.add(anchor.proof.evidence_id); }
  for (const item of model.nodes.values()) {
    item.candidate = model.candidates.get(item.key); item.target = item.key === targetKey;
    item.referenceOnly = Boolean(item.anchor) && ![...model.operations.values()].some(op => op.from_key === item.key || op.to_key === item.key);
    item.kind = item.anchor ? 'anchor' : item.candidate ? 'possible' : item.target ? 'target' : 'intermediate';
    item.radius = 16; // Equal footprint: shapes encode role, not economic importance.
  }
  const state = {selected: null, hover: null, paused: false, visible: true, reduced: matchMedia('(prefers-reduced-motion: reduce)').matches,
    width: 800, height: 570, tx: 400, ty: 285, scale: 1, tick: 0, quiet: 0, physics: true, frame: 0, particles: [], camera: null,
    visibleNodes: [], visibleEdges: [], visibleRoutes: [], filters: {}, dragged: null};
  const edgeById = new Map([...model.edges.values()].map(edge => [edge.id, edge]));
  const routeById = new Map([...model.routes.values()].map(route => [route.id, route]));
  const svgDefs = sv('defs', {}, svg);
  const arrow = sv('marker', {id: 'tsiArrow', viewBox: '0 0 8 8', refX: '7', refY: '4', markerWidth: '5', markerHeight: '5', orient: 'auto', markerUnits: 'userSpaceOnUse'}, svgDefs);
  sv('path', {d: 'M0,1 L7,4 L0,7', fill: 'none', stroke: '#7390a5', 'stroke-width': '1'}, arrow);
  const viewport = sv('g', {'class': 'tsi-viewport'}, svg), edgeLayer = sv('g', {'class': 'tsi-edge-layer'}, viewport), particleLayer = sv('g', {'class': 'tsi-particle-layer'}, viewport), nodeLayer = sv('g', {'class': 'tsi-node-layer'}, viewport);
  const domNodes = new Map(), domEdges = new Map();
  function mark(service, parent, cls = '') {
    const wrap = el('span', 'tsi-service-mark ' + cls, null, parent), src = image(service);
    if (src) { const img = el('img', '', null, wrap); img.addEventListener('error', () => { wrap.replaceChildren(); wrap.textContent = names[service]; wrap.classList.add('tsi-mark-fallback'); }, {once: true}); img.src = src; img.alt = names[service]; img.loading = 'lazy'; }
    else { wrap.textContent = names[service]; wrap.classList.add('tsi-mark-fallback'); }
    return wrap;
  }
  function kindName(item) { return item.anchor ? item.anchor.status+' HISTORICAL ADDRESS LABEL' : item.candidate ? 'POSSIBLE INFRASTRUCTURE' : item.target ? 'Исследуемый адрес' : 'Промежуточный адрес · UNKNOWN'; }
  function setFilters() { for (const input of root.querySelectorAll('[data-tsi-filter]')) state.filters[input.dataset.tsiFilter] = input.checked; }
  function enabled(service, kinds) { return state.filters[service] !== false && [...kinds].some(kind => state.filters[kind] !== false); }
  function computeVisible() {
    setFilters();
    const eligible = [...model.edges.values()].filter(edge => [...edge.services].some(service => enabled(service, edge.kinds)) && (state.filters.anchors !== false || !edge.from.anchor && !edge.to.anchor));
    const used = new Set(eligible.flatMap(edge => [edge.from.key, edge.to.key]));
    for (const n of model.nodes.values()) if ((n.anchor && state.filters.anchors !== false || n.target || n.candidate && state.filters.possible !== false) && [...n.services].some(service => state.filters[service] !== false)) used.add(n.key);
    const selectedNodes = state.selected?.type === 'node' ? [state.selected.id] : state.selected?.type === 'route' ? routeById.get(state.selected.id)?.nodes || [] : [];
    const ranked = [...model.nodes.values()].filter(n => used.has(n.key)).sort((a, b) => Number(selectedNodes.includes(b.key)) - Number(selectedNodes.includes(a.key)) || Number(b.target) - Number(a.target) || Number(Boolean(b.anchor)) - Number(Boolean(a.anchor)) || Number(Boolean(b.candidate)) - Number(Boolean(a.candidate)) || a.key.localeCompare(b.key));
    state.visibleNodes = ranked.slice(0, 120); const keys = new Set(state.visibleNodes.map(n => n.key));
    state.visibleEdges = eligible.filter(edge => keys.has(edge.from.key) && keys.has(edge.to.key)).slice(0, 360);
    state.displayLimited = ranked.length > 120 || eligible.filter(edge => keys.has(edge.from.key) && keys.has(edge.to.key)).length > 360;
    const visibleIds = new Set(state.visibleEdges.flatMap(edge => [...edge.operations.keys()]));
    state.visibleRoutes = [...model.routes.values()].filter(route => enabled(route.service, route.kinds) && route.physicalIds.every(id => visibleIds.has(id)));
    if (!model.nodes.size && validatedUtxoConnections.length) $('tsiNetworkCount').textContent = 'BTC · '+validatedUtxoConnections.length+' исторический TX · allocation UNKNOWN';
    else $('tsiNetworkCount').textContent = state.visibleNodes.length + ' / ' + model.nodes.size + ' узлов · ' + state.visibleEdges.length + ' связей' + (state.displayLimited ? ' · лимит отображения 120 / 360' : '');
    if ($('tsiEmpty')) $('tsiEmpty').hidden = model.operations.size > 0 || validatedUtxoConnections.length > 0;
    if ($('tsiWorkspace')) $('tsiWorkspace').hidden = !hasValidResults;
    if ($('tsiStatus') && (model.rejected || model.rejectedRelations)) $('tsiStatus').title = 'Не показаны записи без полной привязки к источнику: операции ' + model.rejected + ', отношения ' + model.rejectedRelations;
  }
  function layout(reset = false) {
    const nodes = state.visibleNodes.length ? state.visibleNodes : [...model.nodes.values()];
    const count = nodes.length, width = Math.max(230, state.width), height = state.height;
    const span = width * .68, depth = Math.min(height * .62, 390), placed = new Set();
    const routes = [...state.visibleRoutes].sort((a,b)=>b.nodes.length-a.nodes.length);
    function place(n,x,y) { if (!n || placed.has(n.key)) return; if (!n.pinned && (reset || !n.placed)) { n.x=x;n.y=y;n.ax=x;n.ay=y;n.vx=n.vy=0;n.placed=true; } placed.add(n.key); }
    if (reset) for (const n of nodes) {n.pinned=false;n.placed=false;}
    routes.forEach((r,index)=>r.nodes.forEach((key,i)=>place(model.nodes.get(key),-span/2+span*i/Math.max(1,r.nodes.length-1),index ? (index%2 ? -1:1)*Math.ceil(index/2)*Math.min(90,depth/4):0)));
    const core=nodes.find(n=>n.candidate)||nodes.find(n=>n.target)||nodes[0];
    if (core) place(core,0,0);
    const left=[],right=[];
    for (const n of nodes) if (!placed.has(n.key)) {
      const incoming=state.visibleEdges.some(e=>e.from===n && placed.has(e.to.key));
      (incoming?left:right).push(n);
    }
    for (const [side,list] of [[-1,left],[1,right]]) {
      const rows=Math.max(1,Math.min(count<=10?3:9,list.length)),columns=Math.ceil(list.length/rows);
      list.forEach((n,i)=>{const col=Math.floor(i/rows),row=i%rows,rowsHere=Math.min(rows,list.length-col*rows);
        const x=side*(span*(count<=10?.22:.22)+col*Math.min(100,span*.22/Math.max(1,columns-1)));
        const y=rowsHere===1 ? (count<=10?-depth*.42:0) : -depth/2+depth*row/(rowsHere-1);
        place(n,x,y);});
    }
    for (const e of state.visibleEdges) e.restLength=Math.max(65,Math.hypot(e.to.x-e.from.x,e.to.y-e.from.y));
    wake();
  }

  function wake() { state.tick = 0; state.quiet = 0; state.physics = !state.reduced && state.visibleNodes.length > 1; state.physicsDeadline = performance.now() + 6500; state.lastPhysicsTime = 0; requestFrame(); }
  function requestFrame() { if (!state.frame && state.visible && !document.hidden) state.frame = requestAnimationFrame(frame); }
  function geometry(edge) {
    const dx=edge.to.x-edge.from.x,dy=edge.to.y-edge.from.y,d=Math.max(1,Math.hypot(dx,dy)),ux=dx/d,uy=dy/d;
    const a={x:edge.from.x+ux*19,y:edge.from.y+uy*19},b={x:edge.to.x-ux*21,y:edge.to.y-uy*21};
    // Only opposing/parallel transfers bend; single physical links stay straight.
    const parallel=state.visibleEdges.some(e=>e!==edge && (e.from===edge.to&&e.to===edge.from||e.from===edge.from&&e.to===edge.to));
    const bend=parallel?12:0;
    return {a,b,c:{x:(a.x+b.x)/2-uy*bend,y:(a.y+b.y)/2+ux*bend}};
  }

  function drawPositions() {
    viewport.setAttribute('transform', `translate(${state.tx} ${state.ty}) scale(${state.scale})`);
    const labelBoxes=[];
    for (const n of state.visibleNodes) {
      const dom = domNodes.get(n.key); if (!dom) continue;
      dom.setAttribute('transform', `translate(${n.x} ${n.y})`);
      // Keep meaningful labels readable when fitting a wide network on mobile.
      // Minor participants remain inspectable, with labels revealed on zoom/focus.
      const label = dom.querySelector('.tsi-node-label'), sub = dom.querySelector('.tsi-node-role');
      let detailed = state.visibleNodes.length <= 12 || state.scale >= .9 || n.kind !== 'intermediate' || state.selected?.id === n.key || state.hover === n.key;
      if(label&&detailed){const pixels=Math.max(10*state.scale,9),width=label.textContent.length*pixels*.58,x=n.x*state.scale,y=n.y*state.scale+16*state.scale+17;
        const box={left:x-width/2,right:x+width/2,top:y-10,bottom:y+13};
        if(n.kind==='intermediate'&&state.selected?.id!==n.key&&state.hover!==n.key&&labelBoxes.some(b=>box.left<b.right+4&&box.right>b.left-4&&box.top<b.bottom+3&&box.bottom>b.top-3))detailed=false;
        else labelBoxes.push(box);
      }
      if (label) { label.style.display = detailed ? '' : 'none'; label.style.fontSize = `${Math.max(10, 9 / state.scale)}px`; label.setAttribute('y', n.radius + 17 / state.scale); }
      if (sub) { sub.style.display = detailed ? '' : 'none'; sub.style.fontSize = `${Math.max(8, 7 / state.scale)}px`; sub.setAttribute('y', n.radius + 30 / state.scale); }
    }
    for (const e of state.visibleEdges) { const {a, b, c} = geometry(e), d = `M${a.x},${a.y} Q${c.x},${c.y} ${b.x},${b.y}`; const dom = domEdges.get(e.id); dom?.querySelectorAll('path').forEach(path => path.setAttribute('d', d)); }
  }
  function physics() {
    const nodes=state.visibleNodes;
    for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){
      const a=nodes[i],b=nodes[j];let dx=b.x-a.x,dy=b.y-a.y,d=Math.hypot(dx,dy);if(d<.1){dx=1;dy=.5;d=1.1;}
      const force=Math.min(1.6,800/Math.max(100,d*d))+Math.max(0,58-d)*.026;
      a.vx-=dx/d*force;a.vy-=dy/d*force;b.vx+=dx/d*force;b.vy+=dy/d*force;
    }
    for(const e of state.visibleEdges){const dx=e.to.x-e.from.x,dy=e.to.y-e.from.y,d=Math.max(1,Math.hypot(dx,dy)),f=(d-(e.restLength||120))*.002;e.from.vx+=dx/d*f;e.from.vy+=dy/d*f;e.to.vx-=dx/d*f;e.to.vy-=dy/d*f;}
    let energy=0;
    for(const n of nodes){if(n.pinned||state.dragged===n){n.vx=n.vy=0;continue;}n.vx=(n.vx+((n.ax||0)-n.x)*.004)*.78;n.vy=(n.vy+((n.ay||0)-n.y)*.004)*.78;n.x+=Math.max(-4,Math.min(4,n.vx));n.y+=Math.max(-4,Math.min(4,n.vy));energy+=Math.abs(n.vx)+Math.abs(n.vy);}
    state.tick++;state.quiet=energy<.05*Math.max(1,nodes.length)?state.quiet+1:0;if(state.tick>300||state.quiet>22)state.physics=false;
  }

  function frame(now) {
    state.frame = 0;
    if (!state.visible || document.hidden) return;
    const wasPhysics = state.physics;
    if (state.physics && !state.paused && !state.reduced) {
      // Bounded fixed-step simulation stays consistent on slower GPU/browser
      // frames, then sleeps completely instead of continuously polling.
      const steps = state.lastPhysicsTime ? Math.min(4, Math.max(1, Math.round((now - state.lastPhysicsTime) / 16.67))) : 1;
      state.lastPhysicsTime = now;
      for (let i = 0; i < steps && state.physics; i++) physics();
      if (now >= state.physicsDeadline) state.physics = false;
    }
    if (wasPhysics && !state.physics && !state.manipulated) fit(true);
    if (state.camera) { const c = state.camera, t = Math.min(1, (now - c.start) / 280), ease = 1 - Math.pow(1 - t, 3); state.tx = c.from[0] + (c.to[0] - c.from[0]) * ease; state.ty = c.from[1] + (c.to[1] - c.from[1]) * ease; state.scale = c.from[2] + (c.to[2] - c.from[2]) * ease; if (t === 1) state.camera = null; }
    drawPositions();
    state.particles = state.particles.filter(p => {
      const progress = (now - p.start) / 1900;
      if (progress >= 1 || state.paused || state.reduced) { p.dom.remove(); return false; }
      if (progress >= 0) { const {a, b, c} = geometry(p.edge), k = 1 - progress; p.dom.setAttribute('cx', k * k * a.x + 2 * k * progress * c.x + progress * progress * b.x); p.dom.setAttribute('cy', k * k * a.y + 2 * k * progress * c.y + progress * progress * b.y); p.dom.style.opacity = String(Math.min(1, progress * 8, (1 - progress) * 8)); }
      return true;
    });
    $('tsiStatus').textContent = state.paused ? 'Анимация приостановлена' : state.reduced ? 'Уменьшение движения' : state.physics ? 'Стабилизация сети' : 'Сеть стабилизирована';
    if (state.camera || state.particles.length || state.physics && !state.paused && !state.reduced) requestFrame();
  }
  function camera(tx, ty, scale, animate = true) {
    if (!animate || state.reduced) { state.tx = tx; state.ty = ty; state.scale = scale; state.camera = null; drawPositions(); }
    else { state.camera = {from: [state.tx, state.ty, state.scale], to: [tx, ty, scale], start: performance.now()}; requestFrame(); }
  }
  function fit(animate = true) {
    if(!state.visibleNodes.length)return;
    const xs=state.visibleNodes.map(n=>n.x),ys=state.visibleNodes.map(n=>n.y),minX=Math.min(...xs)-55,maxX=Math.max(...xs)+55,minY=Math.min(...ys)-38,maxY=Math.max(...ys)+48;
    const scale=Math.max(.16,Math.min(1.35,(state.width-25)/(maxX-minX),(state.height-38)/(maxY-minY)));
    camera(state.width/2-(minX+maxX)/2*scale,state.height/2-(minY+maxY)/2*scale,scale,animate);
  }

  function highlights() {
    const keys = new Set(), edgeIds = new Set(), selected = state.selected, focus = state.hover || (selected?.type === 'node' ? selected.id : null);
    if (focus) { keys.add(focus); for (const e of state.visibleEdges) if (e.from.key === focus || e.to.key === focus) { keys.add(e.from.key); keys.add(e.to.key); edgeIds.add(e.id); } }
    else if (selected?.type === 'route') { const r = routeById.get(selected.id); r?.nodes.forEach(key => keys.add(key)); r?.physicalIds.forEach(id => edgeIds.add(model.operations.get(id)?.edgeId)); }
    else if (selected?.type === 'edge') { const e = edgeById.get(selected.id); if (e) { keys.add(e.from.key); keys.add(e.to.key); edgeIds.add(e.id); } }
    const active = keys.size > 0;
    for (const n of state.visibleNodes) { const dom = domNodes.get(n.key); dom?.classList.toggle('is-dim', active && !keys.has(n.key)); dom?.classList.toggle('is-selected', selected?.type === 'node' && selected.id === n.key); dom?.classList.toggle('is-neighbor', active && keys.has(n.key)); dom?.classList.toggle('is-pinned', n.pinned); }
    for (const e of state.visibleEdges) { const dom = domEdges.get(e.id); dom?.classList.toggle('is-dim', active && !edgeIds.has(e.id)); dom?.classList.toggle('is-selected', edgeIds.has(e.id)); }
    for (const route of root.querySelectorAll('[data-tsi-route]')) route.classList.toggle('is-selected', selected?.type === 'route' && selected.id === route.dataset.tsiRoute);
  }
  function renderGraph() {
    edgeLayer.replaceChildren(); nodeLayer.replaceChildren(); domNodes.clear(); domEdges.clear();
    if (!model.nodes.size && validatedUtxoConnections.length) { const note=sv('text',{x:state.width/2,y:state.height/2,'text-anchor':'middle',fill:'#94ac9a','font-size':'12'},nodeLayer);note.textContent='BTC: участие в историческом TX · данные в инспекторе'; }
    for (const edge of state.visibleEdges) {
      const group = sv('g', {'class': 'tsi-edge-group', 'data-tsi-edge': edge.id, tabindex: '0', role: 'button', 'aria-label': 'Показать ' + edge.operations.size + ' переводов'}, edgeLayer);
      sv('path', {'class': 'tsi-edge', fill: 'none', stroke: '#66859c', 'stroke-width': '1.05', 'stroke-opacity': '.56', 'marker-end': 'url(#tsiArrow)'}, group);
      sv('path', {'class': 'tsi-edge-hit', fill: 'none', stroke: 'transparent', 'stroke-width': '15', 'pointer-events': 'stroke'}, group);
      group.addEventListener('click', event => { event.stopPropagation(); if (!state.suppressClick) select('edge', edge.id); });
      group.addEventListener('keydown', event => { if (event.key === 'Enter') select('edge', edge.id); }); domEdges.set(edge.id, group);
    }
    for (const n of state.visibleNodes) {
      const color=n.candidate?'#d3b36a':n.target||n.anchor?'#64d47d':'#94ac9a';
      const group=sv('g',{'class':'tsi-node is-'+n.kind,'data-tsi-node':n.key,tabindex:'0',role:'button','aria-label':kindName(n)+': '+displayAddress(n.key)},nodeLayer);
      if(n.candidate){sv('path',{'class':'tsi-node-core',d:'M-15,-8 L0,-16 L15,-8 L15,8 L0,16 L-15,8 Z',stroke:color,'stroke-dasharray':'3 2'},group);if(n.target)sv('path',{d:'M-20,-9V-20H-11 M11,-20H20V-9 M20,9V20H11 M-11,20H-20V9',fill:'none',stroke:color,'stroke-width':'.8'},group);}
      else if(n.anchor||n.target) {sv('rect',{'class':'tsi-node-core',x:-16,y:-14,width:32,height:28,rx:n.anchor?4:0,stroke:color},group);if(n.target)sv('path',{d:'M-20,-9V-18H-11 M11,-18H20V-9 M20,9V18H11 M-11,18H-20V9',fill:'none',stroke:color,'stroke-width':'.8'},group);}
      else sv('path',{'class':'tsi-node-core',d:'M0,-12 L15,0 L0,12 L-15,0 Z',stroke:color},group);
      sv('circle',{'class':'tsi-pin',cx:18,cy:-17,r:2},group);
      const src=n.anchor&&image(n.anchor.service);
      if(src)sv('image',{href:src,x:-11,y:-11,width:22,height:22,preserveAspectRatio:'xMidYMid meet','pointer-events':'none'},group);
      const label=sv('text',{'class':'tsi-node-label',x:0,y:31,'text-anchor':'middle'},group);label.textContent=n.anchor?names[n.anchor.service]:(state.visibleNodes.length>12?displayShort(n.key,7,4):displayShort(n.key));
      const sub=sv('text',{'class':'tsi-node-role',x:0,y:43,'text-anchor':'middle'},group);sub.textContent=n.anchor?n.anchor.status:n.candidate?(n.target?'цель · POSSIBLE':'POSSIBLE'):n.target?'цель':'';
      group.addEventListener('pointerenter', event => { state.hover = n.key; highlights(); const tip = $('tsiTooltip'); if (tip) { tip.textContent = displayAddress(n.key) + '\n' + kindName(n) + '\n' + [...n.services].map(s => names[s]).join(' · '); tip.hidden = false; tip.style.left = Math.min(stage.clientWidth - 250, Math.max(8, event.clientX - stage.getBoundingClientRect().left + 12)) + 'px'; tip.style.top = Math.max(8, event.clientY - stage.getBoundingClientRect().top - 50) + 'px'; } });
      group.addEventListener('pointerleave', () => { state.hover = null; if ($('tsiTooltip')) $('tsiTooltip').hidden = true; highlights(); });
      group.addEventListener('click', event => { event.stopPropagation(); if (!state.suppressClick) select('node', n.key); });
      group.addEventListener('dblclick', event => { event.stopPropagation(); select('node', n.key); camera(state.width / 2 - n.x * 1.45, state.height / 2 - n.y * 1.45, 1.45); });
      group.addEventListener('keydown', event => { if (event.key === 'Enter') select('node', n.key); }); domNodes.set(n.key, group);
    }
    drawPositions(); highlights();
  }
  function evidenceList(refs, parent) {
    const records=unique(refs).map(ref=>proofs.get(ref)).filter(Boolean),list=el('div','tsi-proof-list',null,parent);let count=0;
    if(!records.length){el('p','', 'Нет сохранённых доказательств.',list);return;}
    const more=button('Ещё доказательства',list,append);
    function append(){const end=Math.min(records.length,count+12);for(;count<end;count++){
      const proof=records[count],row=el('details','tsi-proof');list.insertBefore(row,more);el('summary','',proof.source||proof.relation||'Evidence',row);
      row.addEventListener('toggle',()=>{if(!row.open||row.dataset.loaded)return;row.dataset.loaded='1';el('code','tsi-proof-id',proof.evidence_id,row);if(proof.observed_at)field(row,'Получено',proof.observed_at);const href=displayHref(url(proof.url));if(href){const a=el('a','tsi-link','Публичный источник ↗',row);a.href=href;a.target='_blank';a.rel='noopener noreferrer';}el('pre','',JSON.stringify(proof.facts||proof,null,2),row);});
    }more.hidden=count>=records.length;more.textContent='Ещё доказательства · '+(records.length-count);}
    append();
  }
  function field(parent, label, value, mono = false) { if (value == null || value === '') return; const wrap = el('div', 'tsi-detail-field', null, parent); el('span', 'tsi-field-label', label, wrap); el(mono ? 'code' : 'span', mono ? 'tsi-address' : '', displayText(value), wrap); }
  async function copy(value, control) {
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value);
      else { const area = el('textarea', '', value, root); area.style.cssText = 'position:fixed;left:-9999px'; area.value = value; area.select(); const ok = document.execCommand('copy'); area.remove(); if (!ok) throw new Error('clipboard unavailable'); }
      control.textContent = 'Скопировано';
    } catch (_) { control.textContent = 'Выделите адрес для копирования'; }
  }
  function transactionList(operations,parent) {
    const all=unique(operations.map(op=>op.physicalId)).map(id=>model.operations.get(id)).filter(Boolean).sort((a,b)=>a.timestamp.localeCompare(b.timestamp));
    let count=0;const more=button('Ещё операции',parent,append);
    function append(){const end=Math.min(all.length,count+8);for(;count<end;count++){const op=all[count],index=count,row=el('details','tsi-tx-row');parent.insertBefore(row,more);row.open=all.length<=2;el('summary','',`${index+1}. ${displayDecimal(op.amount_decimal)} ${assetText(op.asset_key)} · ${op.timestamp.slice(0,16).replace('T',' ')}`,row);
      field(row,'TX',op.transaction_hash,true);field(row,'Операция',op.operation_id,true);field(row,'Отправитель',displayAddress(op.from_key),true);field(row,'Получатель',displayAddress(op.to_key),true);field(row,'Сеть',op.blockchain);field(row,'Направление','Отправитель → получатель');field(row,'Источник',proofs.get(op.proofRefs[0])?.source);field(row,'UTC',op.timestamp);field(row,'Статус',op.success===true?'SUCCESS':'UNKNOWN');field(row,'Область подтверждения',op.execution_scope || 'Наблюдение источника; зачисление получателю отдельно не доказано');
      const href=displayHref(url(op.source_url));if(href){const a=el('a','tsi-link','Источник TX ↗',row);a.href=href;a.target='_blank';a.rel='noopener noreferrer';}
      const proof=el('details','',null,row);el('summary','',`Доказательства · ${(op.proofRefs||op.evidence_ids||[]).length}`,proof);evidenceList(op.proofRefs||op.evidence_ids||[],proof);
    }more.hidden=count>=all.length;more.textContent='Ещё операции · '+(all.length-count);}append();
  }

  function inspector() {
    const panel=$('tsiInspector');panel.replaceChildren();panel.scrollTop=0;let refs=[],operations=[],alternatives=[];
    if(!state.selected){el('h3','tsi-detail-title',`Маршруты · ${state.visibleRoutes.length}`,panel);const list=el('div','',null,panel);list.id='tsiPaths';renderPaths();return;}
    button('← Маршруты '+state.visibleRoutes.length,panel,()=>select(null));
    const selection=state.selected,head=el('div','tsi-detail-head',null,panel);
    if(selection.type==='node'){
      const n=model.nodes.get(selection.id);if(!n)return;if(n.anchor)mark(n.anchor.service,head);el('h3','tsi-detail-title',n.anchor?names[n.anchor.service]:n.target?'Исследуемый адрес':'Адрес маршрута',head);
      el('code','tsi-address',displayAddress(n.key),panel);button('Copy',panel,e=>copy(displayAddress(n.key),e.currentTarget)).dataset.tsiCopy=n.key;
      button(n.pinned?'Открепить':'Закрепить',panel,()=>{n.pinned=!n.pinned;highlights();inspector();wake();}).dataset.tsiPin=n.key;
      field(panel,'Роль',kindName(n));field(panel,n.anchor?'Метка сервиса':'Сервисы взаимодействий',[...n.services].map(x=>names[x]).join(', '));field(panel,'Контроль','UNKNOWN');field(panel,'Сеть',n.chain);
      operations=[...model.operations.values()].filter(op=>op.from_key===n.key||op.to_key===n.key);refs=[...n.refs];
      field(panel,'Вход / выход',operations.filter(op=>op.to_key===n.key).length+' / '+operations.filter(op=>op.from_key===n.key).length+' операций');
      if(n.candidate){field(panel,'Оператор / контроль','UNKNOWN · роль POSSIBLE не устанавливает владельца');field(panel,'Гипотеза',(n.candidate.roles||[]).join(', '));field(panel,'Период',[n.candidate.first_observed,n.candidate.last_observed].filter(Boolean).join(' → '));const o=n.candidate.observations||{};field(panel,'TX / messages',`${o.independent_transaction_count??'UNKNOWN'} / ${o.physical_message_count??'UNKNOWN'}`);alternatives=n.candidate.alternative_explanations||[];
        for(const group of n.candidate.candidate_groups||[n.candidate])field(panel,'Роль · '+names[group.service_id],(group.roles||[]).join(', ')+' · POSSIBLE · '+(group.asset_key==='multiple_observed_assets'?(group.observations?.payout_asset_keys||[]).map(assetText).join(', '):assetText(group.asset_key)));
        if((n.candidate.candidate_groups||[n.candidate]).some(group=>group.role_operations_display_truncated))field(panel,'Покрытие инспектора','Показана часть операций и маршрутов; все собранные данные сохранены в расследовании. Полнота истории не установлена.');
        const sequences=n.candidate.observed_sequences||[];
        if(sequences.length){const detail=el('details','',null,panel);el('summary','',`Наблюдаемые последовательности · ${sequences.length}`,detail);
          for(const sequence of sequences){const row=el('details','tsi-tx-row',null,detail);el('summary','',sequence.outgoing.timestamp.slice(0,10)+' · '+displayDecimal(sequence.outgoing.amount_decimal)+' '+assetText(sequence.asset_key),row);
            field(row,'Интервал',sequence.delay_seconds+' секунд');field(row,'Входящий TX',sequence.incoming.transaction_hash,true);field(row,'Исходящий TX',sequence.outgoing.transaction_hash,true);
            field(row,'Входящая сумма',sequence.incoming.amount_decimal);field(row,'Исходящая сумма',sequence.outgoing.amount_decimal);field(row,'Разница',sequence.amount_difference);
            field(row,'Смежность account TX',sequence.account_transactions_adjacent?'Подтверждена prev hash/LT':'Не установлена');
            field(row,'Баланс после исходящего TX',sequence.account_state_out?.end_balance_base_units!=null?displayDecimal((BigInt(sequence.account_state_out.end_balance_base_units)/1000000000n).toString()+'.'+(BigInt(sequence.account_state_out.end_balance_base_units)%1000000000n).toString().padStart(9,'0'))+' TON':'UNKNOWN');
            field(row,'Балансовое равенство',sequence.balance_conservation_verified===true?'Проверено по retained native state / fees':'UNKNOWN');field(row,'Тождество средств / владелец','UNKNOWN');evidenceList(sequence.evidence_ids||[],row);}
        }
      }
      else if(operations.length){const times=operations.map(op=>op.timestamp).sort();field(panel,'Период',times[0]+' → '+times.at(-1));}
      if(n.anchor){field(panel,'Публикация',n.anchor.proof.facts?.source_published_at);field(panel,'Роль адреса',n.anchor.proof.facts?.role);if(n.referenceOnly)field(panel,'Контекст','Справочная историческая метка адреса ('+n.anchor.status+'); переводы в доступной выборке не установлены.');}
      for(const id of n.relations){const r=relationMap.get(id);refs.push(...(r?.evidence_ids||[]));if(!alternatives.length)alternatives=r?.alternative_explanations||[];}
      field(panel,'Отношения',unique([...n.relations].map(id=>relationMap.get(id)?.category)).join(' · '));field(panel,'Достоверность связи',unique([...n.relations].map(id=>relationMap.get(id)?.status)).join(' · '));
    }else if(selection.type==='edge'){
      const e=edgeById.get(selection.id);if(!e)return;el('h3','tsi-detail-title',e.operations.size===1?'Транзакция':`${e.operations.size} физических переводов`,head);operations=[...e.operations.values()];refs=unique(operations.flatMap(op=>op.proofRefs||[]));
    }else{
      const r=routeById.get(selection.id);if(!r)return;el('h3','tsi-detail-title',`${names[r.service]} · ${r.physicalIds.length} перехода`,head);field(panel,'Отношение',r.relation.category);field(panel,'Статус',r.status);if(r.relation.label_temporal_scope==='label_postdates_observed_operation')field(panel,'Историческая применимость','Метка опубликована позднее этой операции; прежний контроль адреса не подтверждён');operations=r.physicalIds.map(id=>model.operations.get(id));refs=r.refs;alternatives=r.relation.alternative_explanations||[];
    }
    if(operations.length){const rows=el('details','',null,panel);rows.open=selection.type!=='node';el('summary','',`Операции · ${operations.length}`,rows);transactionList(operations,rows);}
    const proof=el('details','',null,panel);el('summary','',`Доказательства · ${unique(refs).length}`,proof);evidenceList(refs,proof);
    if(alternatives.length){const detail=el('details','',null,panel);el('summary','',`Альтернативы · ${alternatives.length}`,detail);const list=el('ul','',null,detail);alternatives.forEach(x=>el('li','',x,list));}
    el('p','', 'Исторические операции; контроль UNKNOWN. Косвенный путь не доказывает тождество средств.',panel);
  }

  function select(type, id) {
    state.selected = type ? {type, id} : null; state.hover = null;
    $('tsiSelectionLabel').textContent = type === 'node' ? displayShort(id) : type === 'edge' ? 'Перевод / группа переводов' : type === 'route' ? 'Выбран исторический маршрут' : 'Вся наблюдаемая сеть';
    if ($('tsiClearSelection')) $('tsiClearSelection').hidden = !type;
    if (type === 'node' && !state.visibleNodes.some(n => n.key === id)) { computeVisible(); renderGraph(); }
    state.particles.forEach(p => p.dom.remove()); state.particles = [];
    if (type === 'route' && !state.reduced && !state.paused) { const route = routeById.get(id); (route?.physicalIds || []).slice(0, 6).forEach((pid, i) => { const edge = edgeById.get(model.operations.get(pid)?.edgeId); if (edge) state.particles.push({edge, start: performance.now() + i * 180, dom: sv('circle', {'class': 'tsi-particle', r: 2.4, fill: colors[route.service], opacity: '0', 'pointer-events': 'none'}, particleLayer)}); }); requestFrame(); }
    inspector(); highlights();
  }
  function renderPaths() {
    const parent=$('tsiPaths');if(!parent)return;parent.replaceChildren();
    for(const r of state.visibleRoutes){const b=button('',parent,()=>select('route',r.id),'tsi-route-row');b.dataset.tsiRoute=r.id;el('strong','',`${r.physicalIds.length} переход${r.physicalIds.length===1?'':'а'} · ${names[r.service]}`,b);el('span','',r.nodes.map(key=>displayShort(key)).join(' → '),b);const ops=r.physicalIds.map(id=>model.operations.get(id));el('span','',ops.map(op=>displayDecimal(op.amount_decimal)+' '+assetText(op.asset_key)).join(' → '),b);el('span','',ops[0].timestamp.slice(0,10)+' · '+r.status,b);}
    appendUtxoConnections(parent);
    if(!state.visibleRoutes.length && !validatedUtxoConnections.length)el('p','', 'Нет маршрутов в выбранных фильтрах.',parent);
  }

  function renderSummary() {
    const host=$('tsiServices');host.replaceChildren();
    for(const service of Object.keys(names)){const found=[...model.nodes.values()].some(n=>n.services.has(service)) || validatedUtxoConnections.some(row=>row.service_id===service);root.querySelector(`[data-tsi-filter="${service}"]`).checked=found;const b=button('',host,()=>{
      for(const input of root.querySelectorAll('[data-tsi-filter]'))if(names[input.dataset.tsiFilter])input.checked=input.dataset.tsiFilter===service;
      root.querySelectorAll('[data-tsi-service]').forEach(x=>x.setAttribute('aria-pressed',String(x.dataset.tsiService===service)));
      state.selected=null;state.manipulated=false;computeVisible();layout(true);refresh();fit();
    });b.dataset.tsiService=service;b.setAttribute('aria-pressed',String(found));b.title=handles[service]+(found?'':' · в отчёте не найдено');if(!found)b.classList.add('is-empty');mark(service,b);el('span','',names[service],b);}
  }

  function refresh() {
    computeVisible();const count=state.visibleNodes.length;root.style.setProperty('--tsi-height',count<=3?'390px':count<=10?'500px':'640px');
    layout();if(state.reduced){for(let i=0;i<100;i++)physics();state.physics=false;}renderGraph();inspector();wake();
  }

  function resize() {
    const rect=stage.getBoundingClientRect();if(!rect.width)return;const changed=Math.abs(state.width-rect.width)>25;
    state.width=rect.width;state.height=rect.height||500;svg.setAttribute('viewBox',`0 0 ${state.width} ${state.height}`);
    if(changed&&!state.manipulated)layout(true);fit(false);
  }

  function point(event) { const box = svg.getBoundingClientRect(); return {x: (event.clientX - box.left) * state.width / Math.max(1, box.width), y: (event.clientY - box.top) * state.height / Math.max(1, box.height)}; }
  let gesture = null;
  svg.addEventListener('pointerdown', event => {
    if (event.button !== 0) return; const hit = event.target.closest('[data-tsi-node]'), n = hit && model.nodes.get(hit.dataset.tsiNode), p = point(event);
    state.manipulated = true;
    gesture = {id: event.pointerId, x: p.x, y: p.y, tx: state.tx, ty: state.ty, n, edge: event.target.closest('[data-tsi-edge]')?.dataset.tsiEdge, nodeX: n?.x, nodeY: n?.y, moved: false};
    state.camera = null; state.dragged = n || null; svg.setPointerCapture(event.pointerId); if (n) event.preventDefault();
  });
  svg.addEventListener('pointermove', event => {
    if (!gesture || gesture.id !== event.pointerId) return; const p = point(event), dx = p.x - gesture.x, dy = p.y - gesture.y;
    if (Math.hypot(dx, dy) > 3) gesture.moved = true;
    if (gesture.n) { gesture.n.x = gesture.nodeX + dx / state.scale; gesture.n.y = gesture.nodeY + dy / state.scale; gesture.n.ax = gesture.n.x; gesture.n.ay = gesture.n.y; gesture.n.vx = gesture.n.vy = 0; wake(); }
    else { state.tx = gesture.tx + dx; state.ty = gesture.ty + dy; }
    drawPositions();
  });
  function endGesture(event) {
    if (!gesture || gesture.id !== event.pointerId) return;
    state.suppressClick = gesture.moved;
    if (!gesture.moved && gesture.n) {
      const n = gesture.n, now = performance.now(); select('node', n.key);
      if (state.lastNodeClick?.key === n.key && now - state.lastNodeClick.time < 380) {
        camera(state.width / 2 - n.x * 1.45, state.height / 2 - n.y * 1.45, 1.45); state.lastNodeClick = null;
      } else state.lastNodeClick = {key: n.key, time: now};
    } else if (!gesture.moved && gesture.edge) select('edge', gesture.edge);
    if (svg.hasPointerCapture(event.pointerId)) svg.releasePointerCapture(event.pointerId);
    gesture = null; state.dragged = null; setTimeout(() => { state.suppressClick = false; }, 0); wake();
  }
  svg.addEventListener('pointerup', endGesture); svg.addEventListener('pointercancel', endGesture);
  svg.addEventListener('wheel', event => { event.preventDefault(); state.manipulated = true; const p = point(event), scale = Math.max(.12, Math.min(4.5, state.scale * Math.exp(-event.deltaY * .0013))), ratio = scale / state.scale; state.camera = null; state.tx = p.x - (p.x - state.tx) * ratio; state.ty = p.y - (p.y - state.ty) * ratio; state.scale = scale; drawPositions(); }, {passive: false});
  for (const input of root.querySelectorAll('[data-tsi-filter]')) input.addEventListener('change', refresh);
  $('tsiFit')?.addEventListener('click', () => { state.manipulated = true; fit(); });
  $('tsiReset')?.addEventListener('click', () => { state.manipulated = false; layout(true); select(null); refresh(); fit(); });
  $('tsiClearSelection')?.addEventListener('click', () => select(null));
  $('tsiPause')?.addEventListener('click', event => { state.paused = !state.paused; event.currentTarget.textContent = state.paused ? 'Продолжить' : 'Пауза'; event.currentTarget.setAttribute('aria-pressed', String(state.paused)); if (!state.paused) wake(); else requestFrame(); });
  $('tsiSearch')?.addEventListener('input', event => {
    const q = event.target.value.trim().toLowerCase(), results = $('tsiSearchResults'); results?.replaceChildren(); if (!q || !results) return;
    const matches = state.visibleNodes.filter(n => n.key.toLowerCase().includes(q) || displayAddress(n.key).toLowerCase().includes(q) || [...n.services].some(s => names[s].toLowerCase().includes(q))).slice(0, 8);
    if (!matches.length) el('p', 'tsi-empty-note', 'Среди отображённых узлов совпадений нет.', results);
    for (const n of matches) { const b = button(displayShort(n.key) + ' · ' + kindName(n), results, () => { select('node', n.key); camera(state.width / 2 - n.x * 1.35, state.height / 2 - n.y * 1.35, 1.35); results.replaceChildren(); }, 'tsi-search-result'); b.title = displayAddress(n.key); }
  });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) requestFrame(); });
  if (typeof IntersectionObserver !== 'undefined') new IntersectionObserver(entries => { state.visible = entries[0].isIntersecting; if (state.visible) requestFrame(); }, {rootMargin: '150px'}).observe(root);
  if (typeof ResizeObserver !== 'undefined') new ResizeObserver(resize).observe(stage);
  const reducedQuery = matchMedia('(prefers-reduced-motion: reduce)'); reducedQuery.addEventListener?.('change', event => { state.reduced = event.matches; requestFrame(); });
  function readSnapshot() { return {utxoConnections:validatedUtxoConnections.map(row=>({transactionHash:row.transaction_hash,service:row.service_id,allocation:row.allocation,ownership:row.ownership})), nodeCount: model.nodes.size, edgeCount: model.edges.size, routeCount: model.routes.size, physicalTransfers: model.operations.size,
    visibleNodes: state.visibleNodes.map(n => ({key: n.key, x: n.x, y: n.y, pinned: n.pinned, kind: n.kind, logo: Boolean(n.anchor && image(n.anchor.service))})),
    visibleEdges: state.visibleEdges.map(e => ({id: e.id, from: e.from.key, to: e.to.key, physicalCount: e.operations.size, transactionHashes: unique([...e.operations.values()].map(op => op.transaction_hash))})),
    visibleRoutes: state.visibleRoutes.map(r => ({id: r.id, nodes: [...r.nodes], physicalIds: [...r.physicalIds], service: r.service})),
    operationDetails:[...model.operations.values()].map(op=>({transactionHash:op.transaction_hash,asset:assetText(op.asset_key),assetKey:op.asset_key,amount:op.amount_decimal,chain:op.blockchain})),anchorStatuses:[...model.anchors.values()].map(a=>({key:a.key,status:a.status})), anchors: [...model.anchors.keys()], candidates: [...model.candidates.keys()], selection: state.selected && {...state.selected},
    camera: {x: state.tx, y: state.ty, scale: state.scale}, paused: state.paused, reducedMotion: state.reduced, physicsActive: state.physics, physicsTick: state.tick, animationFramePending: Boolean(state.frame), sectionVisible: state.visible, particles: state.particles.length, rejectedIncompleteOperations: model.rejected, rejectedUnboundRelations: model.rejectedRelations, truncatedDisplay: Boolean(state.displayLimited)}; }
  window.GansarTelegramIntelligence = {readSnapshot, get state() { return readSnapshot(); }, selectNode: key => { if (model.nodes.has(key)) select('node', key); }, selectRoute: id => { if (routeById.has(id)) select('route', id); }, selectEdge: id => { if (edgeById.has(id)) select('edge', id); }, fit, reset: () => { layout(true); select(null); refresh(); fit(); }};
  renderSummary(); computeVisible(); resize(); refresh(); resize(); select(null); requestFrame();
})();
