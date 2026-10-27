"""Non-mutating, lossless provider-provenance pooling; no network imports."""
import hashlib,json
from app.utils.security import sanitize_observation

def source_observation_id(value):
    clean=sanitize_observation(value)
    digest=hashlib.sha256(json.dumps(clean,sort_keys=True,default=str,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    return 'source-observation:'+digest,clean

def compact_service_provenance(data):
    """Pool repeated complete observations, keeping each proof's original order.

    Saved old payloads and already pooled payloads are both supported. The input
    report/snapshot is never mutated. Every public source/raw field survives in
    ``source_observations`` exactly once per identical observation; only secrets
    undergo the normal existing renderer redaction.
    """
    pool=dict(data.get('source_observations')or{});evidence=[]
    for row in data.get('evidence',[]):
        facts=row.get('facts')or{}
        if not isinstance(facts,dict)or not isinstance(facts.get('source_provenance'),list):
            evidence.append(row);continue
        refs=[]
        for observation in facts['source_provenance']:
            identifier,clean=source_observation_id(observation)
            pool.setdefault(identifier,clean);refs.append(identifier)
        evidence.append({**row,'facts':{**{key:value for key,value in facts.items()if key!='source_provenance'},'source_provenance_refs':refs}})
    return {**data,'evidence':evidence,'source_observations':pool}
