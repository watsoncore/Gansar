"""Presentation-only storage codec; synthetic controls never enter real reports."""
from pathlib import Path
import base64, gzip, hashlib, json, subprocess, unittest, zlib
from unittest.mock import patch
from app.exporters import payload_transport
from app.exporters.html_exporter import _browser_json
from app.exporters.payload_transport import pack_json, TAG

ROOT=Path(__file__).resolve().parents[1]


class PayloadTransportTests(unittest.TestCase):
    def test_small_values_remain_the_original_json_format(self):
        value=_browser_json({'value':'Привет </script>', 'n':2**70})
        self.assertEqual(pack_json(value),value)

    def test_large_payload_preserves_exact_guarded_utf8_bytes(self):
        value=_browser_json({'records':[{'text':'Привет 💎 </script>&', 'amount':'0.000000000000000001',
            'tx':'storage-codec-unit-control','integer':2**80} for _ in range(2500)]})
        packed=pack_json(value,threshold=1024)
        envelope=json.loads(packed)[TAG]
        raw=gzip.decompress(base64.b64decode(envelope['data']))
        self.assertEqual(raw,value.encode('utf-8'))
        self.assertEqual(envelope['bytes'],len(raw))
        self.assertEqual(envelope['crc32'],zlib.crc32(raw))
        self.assertLess(len(packed),len(value)//10)
        self.assertNotIn('<',packed)

    def test_literal_provider_storage_property_is_escaped_even_when_small(self):
        literal={TAG:{'version':1,'encoding':'gzip-base64','bytes':2147483647,'data':'untrusted'}}
        packed=pack_json(_browser_json(literal))
        self.assertNotEqual(json.loads(packed),literal)
        restored=json.loads(gzip.decompress(base64.b64decode(json.loads(packed)[TAG]['data'])))
        self.assertEqual(restored,literal)

    def test_string_table_roundtrip_keeps_literal_nul_keys_and_exact_values(self):
        values=[hashlib.sha256(('codec-unit-'+str(i)).encode()).hexdigest() for i in range(800)]
        original={'records':values*12,'literal':['\0','\0\0','\0'+'123','\0bad'],
            '__proto__':{'constructor':'own-value'},'\0key':{'untrusted':{TAG:{'not':'a codec command'}}}}
        with patch.object(payload_transport,'PACK_THRESHOLD',1024):
            packed=pack_json(_browser_json(original),threshold=1024)
        self.assertEqual(json.loads(packed)[TAG]['version'],2)
        script=r'''
const fs=require('fs'),vm=require('vm');
const c={fflate:require(process.cwd()+'/app/exporters/assets/vendor/fflate-0.8.3.min.js'),
  atob:s=>Buffer.from(s,'base64').toString('binary'),TextDecoder,Uint8Array,Uint32Array,DataView};
vm.createContext(c);vm.runInContext(fs.readFileSync('app/exporters/assets/payload-transport.js','utf8'),c);
const d=c.gansarReadStoredJson(fs.readFileSync(0,'utf8'));
process.stdout.write(JSON.stringify(d));
'''
        result=subprocess.run(['node','-e',script],input=packed,text=True,capture_output=True,cwd=ROOT,check=True)
        self.assertEqual(json.loads(result.stdout),original)

    def test_bundled_javascript_roundtrip_and_corruption_rejection(self):
        original={'__proto__':{'owner':'synthetic-codec-control'},'constructor':'own-key',
            'records':['Привет 💎 </script>&']*10000,'n':str(2**80)}
        packed=pack_json(_browser_json(original),threshold=1024)
        script=r'''
const fs=require('fs'),vm=require('vm');
const root=process.cwd(),input=JSON.parse(fs.readFileSync(0,'utf8'));
const context={fflate:require(root+'/app/exporters/assets/vendor/fflate-0.8.3.min.js'),
  atob:s=>Buffer.from(s,'base64').toString('binary'),TextDecoder,Uint8Array,Uint32Array,DataView};
vm.createContext(context);vm.runInContext(fs.readFileSync(root+'/app/exporters/assets/payload-transport.js','utf8'),context);
const decoded=context.gansarReadStoredJson(input);
let bad=structuredClone(input);bad.__gansar_json_storage__.crc32^=1;
let rejected=false;try{context.gansarReadStoredJson(bad)}catch{rejected=true}
let nested=context.gansarReadStoredJson({provider:{__gansar_json_storage__:{data:'untrusted'}}});
process.stdout.write(JSON.stringify({decoded,rejected,nested}));
'''
        result=subprocess.run(['node','-e',script],input=packed,text=True,capture_output=True,cwd=ROOT,check=True)
        actual=json.loads(result.stdout)
        self.assertEqual(actual['decoded'],original)
        self.assertTrue(actual['rejected'])
        self.assertEqual(actual['nested']['provider'][TAG]['data'],'untrusted')


if __name__=='__main__': unittest.main()
