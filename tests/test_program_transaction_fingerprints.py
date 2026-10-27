"""Protocol-role evidence; fixtures deliberately do not attest wallet UIs."""
import copy
import unittest
from app.models.report import Transaction
from app.attribution.program_transaction_fingerprints import analyze_solana_transaction, analyze_tron_transaction, SQUADS
from app.sources.tron_trongrid import _tron_address

SOL='11111111111111111111111111111111'
MEMBER='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
HASH='a'*64

def b58(data):
    from app.utils.detect import BASE58_ALPHABET
    n=int.from_bytes(data,'big');out=''
    while n:n,r=divmod(n,58);out=BASE58_ALPHABET[r]+out
    return '1'*(len(data)-len(data.lstrip(b'\0')))+out

def solana():
    provider={'version':0,'transaction':{'signatures':['public-signature'], 'message':{
        'accountKeys':[MEMBER,SOL,SQUADS],'header':{'numRequiredSignatures':1},
        'instructions':[{'programIdIndex':2,'accounts':[1,0,0,0], 'data':b58(bytes.fromhex('c208a15799a419ab'))}]}},
        'meta':{'err':None,'fee':5000}}
    return Transaction(chain='solana',tx_hash='public-signature',from_address=MEMBER,to_address=SOL,
        source='fixture',raw={'provider_record':provider})

def tron(kind='DelegateResourceContract'):
    provider={'txID':HASH,'ret':[{'contractRet':'SUCCESS'}], 'raw_data':{'contract':[{
        'type':kind,'Permission_id':3,'parameter':{'value':{'owner_address':'41'+'11'*20,
        'receiver_address':'41'+'22'*20, 'balance':1000000,'resource':'ENERGY'}}}]}}
    return Transaction(chain='tron',tx_hash=HASH,source='fixture',raw={'type':'transfer','provider_record':provider})

class SolanaRoles(unittest.TestCase):
    def test_unrecognized_or_oversized_data_is_not_decoded(self):
        from unittest.mock import patch
        tx=solana();ix=tx.raw['provider_record']['transaction']['message']['instructions'][0]
        ix['data']='z'*65536
        with patch('app.attribution.program_transaction_fingerprints._base58_decode',side_effect=AssertionError('must not decode')):
            result=analyze_solana_transaction(tx)
        self.assertFalse(result['implementation_observations'])
        self.assertEqual(result['checks'][-1]['instruction_data_omitted'],1)
    def test_squads_subject_is_multisig_not_fee_payer(self):
        result=analyze_solana_transaction(solana());row=result['implementation_observations'][0]
        self.assertEqual(row['subject_address'],SOL)
        self.assertEqual(row['fields']['fee_payer'],MEMBER)
        self.assertFalse(row['signing_application_confirmed'])
    def test_wrong_program_discriminator_and_hash_do_not_confirm(self):
        for modification in ('program','discriminator','hash'):
            tx=solana();p=tx.raw['provider_record'];ix=p['transaction']['message']['instructions'][0]
            if modification=='program':p['transaction']['message']['accountKeys'][2]=MEMBER
            if modification=='discriminator':ix['data']=b58(b'12345678')
            if modification=='hash':tx.tx_hash='other'
            self.assertFalse(analyze_solana_transaction(tx)['implementation_observations'])
    def test_failed_or_unknown_meta_only_attempt(self):
        for meta in ({'err':{'InstructionError':[0,'InvalidArgument']}},{}):
            tx=solana();tx.raw['provider_record']['meta']=meta
            result=analyze_solana_transaction(tx)
            self.assertFalse(result['implementation_observations'])
            self.assertTrue(result['construction_fingerprints'])
    def test_lookup_loaded_keys_and_inner_instruction(self):
        tx=solana();p=tx.raw['provider_record'];message=p['transaction']['message']
        ix=message['instructions'].pop();message['accountKeys']=message['accountKeys'][:2]
        p['meta'].update(loadedAddresses={'writable':[],'readonly':[SQUADS]},innerInstructions=[{'index':0,'instructions':[ix]}])
        row=analyze_solana_transaction(tx)['implementation_observations'][0]
        self.assertEqual(row['fields']['instruction_position'],'inner:0:0')
    def test_parsed_account_keys_do_not_duplicate_loaded(self):
        tx=solana();p=tx.raw['provider_record'];message=p['transaction']['message']
        message['accountKeys']=[{'pubkey':key,'source':'transaction'} for key in message['accountKeys']]
        p['meta']['loadedAddresses']={'writable':[],'readonly':[MEMBER]}
        self.assertEqual(len(analyze_solana_transaction(tx)['implementation_observations']),1)
    def test_no_ui_brand_from_compute_or_fee(self):
        tx=solana();tx.raw['provider_record']['transaction']['message']['instructions']=[]
        result=analyze_solana_transaction(tx)
        self.assertFalse(result['implementation_observations']);self.assertFalse(result['investigative_leads'])
    def test_missing_provider_is_unavailable(self):
        tx=solana();tx.raw={}
        self.assertEqual(analyze_solana_transaction(tx)['checks'][0]['status'],'unavailable')

class TronRoles(unittest.TestCase):
    def test_native_collector_exporter_and_graph_do_not_make_resource_payment(self):
        from app.models.report import AddressReport
        from app.sources.tron_trongrid import TronGridSource
        from app.exporters.html_exporter import _tx_kind
        from app.graph.builder import build_graph_payload
        provider=tron().raw['provider_record']
        address=_tron_address('41'+'11'*20)
        report=AddressReport(target_address=address,detected_chains=['tron'])
        TronGridSource(1)._parse_native_transactions(address,report,[provider])
        tx=report.transactions[0]
        self.assertEqual(tx.raw['type'],'resource');self.assertEqual(_tx_kind(tx),'resource_event')
        edges=build_graph_payload(report)['edges']
        self.assertFalse(any(edge.get('type')=='transfer' for edge in edges))
    def test_resource_not_funds_and_permission_is_explicit(self):
        result=analyze_tron_transaction(tron());row=result['construction_fingerprints'][0]
        self.assertFalse(row['fields']['fund_flow_inferred'])
        self.assertEqual(row['fields']['permission_id'],3)
        self.assertEqual(row['fields']['balance_sun'],1000000)
        self.assertFalse(row['signing_application_confirmed'])
    def test_default_bandwidth(self):
        tx=tron('UnDelegateResourceContract')
        del tx.raw['provider_record']['raw_data']['contract'][0]['parameter']['value']['resource']
        self.assertEqual(analyze_tron_transaction(tx)['construction_fingerprints'][0]['fields']['resource'],'BANDWIDTH')
    def test_permission_update_threshold_is_not_ui(self):
        tx=tron('AccountPermissionUpdateContract');value=tx.raw['provider_record']['raw_data']['contract'][0]['parameter']['value']
        value['owner']={'threshold':2,'keys':[{'address':'41'+'33'*20,'weight':2}]}
        row=analyze_tron_transaction(tx)['implementation_observations'][0]
        self.assertEqual(row['fields']['configuration'][0]['threshold'],2)
        self.assertIn('not current',row['fields']['scope'])
        self.assertNotIn('multisig',row['implementation'].lower())
    def test_missing_hash_or_failed_update_cannot_confirm(self):
        tx=tron('AccountPermissionUpdateContract');tx.raw['provider_record']['ret']=[{'contractRet':'REVERT'}]
        self.assertFalse(analyze_tron_transaction(tx)['implementation_observations'])
        tx.tx_hash='wrong';self.assertFalse(analyze_tron_transaction(tx)['construction_fingerprints'])
    def test_summary_provider_not_parsed_as_native(self):
        tx=tron();tx.raw['provider_record']={'hash':HASH,'contractType':57}
        self.assertEqual(analyze_tron_transaction(tx)['checks'][0]['status'],'unavailable')
    def test_contracts_bounded_and_raw_not_mutated(self):
        tx=tron();snapshot=copy.deepcopy(tx.raw)
        analyze_tron_transaction(tx);self.assertEqual(tx.raw,snapshot)
        self.assertTrue(_tron_address('41'+'11'*20).startswith('T'))
