"""Complete source records survive pooling without multiplying raw JSON."""
import copy,json,unittest
from app.attribution.provenance import compact_service_provenance

class ProvenancePooling(unittest.TestCase):
    def test_duplicates_pool_once_and_each_proof_recovers_original_order(self):
        observation={'source':'synthetic_provider','url':'https://example.org/tx','raw_digest':'a'*64,
            'raw':{'transaction':{'hash':'b'*64,'in_msg':{'body':'observed-boc'},'decoded':{'public_field':'preserved'}}}}
        second={'source':'second_provider','url':'https://second.example/tx','raw':{'native':'different'}}
        data={'addresses':{},'evidence':[{'evidence_id':'e1','facts':{'source_provenance':[observation,second,observation]}},
             {'evidence_id':'e2','facts':{'source_provenance':[observation]}},{'evidence_id':'e3','facts':{'unrelated':123}}]}
        before=copy.deepcopy(data);pooled=compact_service_provenance(data)
        self.assertEqual(data,before);self.assertEqual(len(pooled['source_observations']),2)
        for original,compact in zip(data['evidence'][:2],pooled['evidence'][:2]):
            restored=[pooled['source_observations'][ref]for ref in compact['facts']['source_provenance_refs']]
            self.assertEqual(restored,original['facts']['source_provenance'])
        self.assertEqual(pooled['evidence'][2],data['evidence'][2])
    def test_existing_pooled_payload_is_idempotent(self):
        data={'evidence':[{'evidence_id':'e1','facts':{'source_provenance':[{'source':'fixture','raw':{'a':1}}]}}]}
        once=compact_service_provenance(data);twice=compact_service_provenance(once)
        self.assertEqual(once,twice)
    def test_raw_amplification_reduces_without_drop(self):
        observation={'source':'fixture','raw':{'payload':'x'*20000,'fields':list(range(200))}}
        data={'evidence':[{'evidence_id':str(n),'facts':{'source_provenance':[observation]}}for n in range(100)]}
        pooled=compact_service_provenance(data)
        self.assertLess(len(json.dumps(pooled)),len(json.dumps(data))/10)
        self.assertEqual(len(pooled['evidence']),100);self.assertEqual(len(pooled['source_observations']),1)

if __name__=='__main__':unittest.main()
