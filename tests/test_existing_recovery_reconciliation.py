"""Settlement of already approved duties must not authorize another attempt."""
import json
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest
from web3 import Web3

from core.do_dkg_journal import RecoveryJournal
from core.do_dkg_recovery import RecoveryController, RecoveryNeedsAction


def record_call(**values):
    return NS(call=lambda:tuple(values.values()),abi={'outputs':[{'type':'tuple',
        'components':[{'name':key} for key in values]}]})


@pytest.fixture
def existing(tmp_path):
    owner='0x'+'11'*20;coordinator='0x'+'22'*20;file=bytes.fromhex('33'*32)
    material=bytes.fromhex('44'*32);context=bytes.fromhex('55'*32)
    journal=RecoveryJournal(tmp_path/'journal.sqlite3')
    journal.create('original',chain_id=31338,coordinator=coordinator,owner=owner,
        file_id=Web3.to_hex(file),kind='fresh',intent={'n':3,'t':2,'public_key':None},
        max_attempts=2,max_debit_wei=10**18)
    journal.begin_attempt('original',1,dict(epoch=1,version=1,
        receivers=[owner]*3,dealer_indices=[1,2,3]))
    journal.bind_material('original',1,Web3.to_hex(material),Web3.to_hex(context))
    sender=Mock();sender.account=NS(address=owner);sender.submit.return_value={'status':1}
    job=NS(fileId=file,epoch=1,version=1,contextHash=context,registryId=material,readyAt=0)
    chain=NS(state=1,dataOwner=owner,acceptBy=100,workDeadline=100,acceptedCount=2)
    contracts=Mock();contracts.coordinator.address=coordinator;contracts.w3.eth.chain_id=31338
    contracts.w3.eth.get_block.return_value={'timestamp':200}
    contracts.attempt.return_value=(job,chain)
    contracts.controller.functions.getParticipants.return_value.call.return_value=[owner]*3
    contracts.coordinator.functions.getAttemptWork.return_value.call.return_value=(0,0,0)
    contracts.manager.functions.pendingDisputes.return_value.call.return_value=0
    contracts.manager.functions.excludedDealers.return_value.call.return_value=0
    contracts.registry.functions.acceptanceTimedOut.return_value.call.return_value=True
    candidates=Mock(side_effect=AssertionError('No new committee may be selected'))
    worker=RecoveryController(contracts,journal,sender,'original',candidates)
    return NS(worker=worker,c=contracts,job=job,chain=chain,journal=journal,sender=sender,
              candidates=candidates,material=material)


def test_acceptance_timeout_is_settled_then_stops_without_replacement(existing):
    before=existing.journal.snapshot('original')
    assert existing.worker.reconcile_existing().phase=='settling'
    existing.sender.submit.assert_called_once()
    assert existing.sender.submit.call_args.args[2]=='1:close'
    existing.chain.state=5
    assert existing.worker.reconcile_existing().phase=='settled'
    after=existing.journal.snapshot('original')
    assert after['attempts'][0]['outcome']=='failed'
    assert after['status']=='needs_action'
    assert len(after['attempts'])==len(before['attempts'])==1
    assert (after['max_attempts'],after['max_debit'])==(before['max_attempts'],before['max_debit'])
    existing.candidates.assert_not_called()


def test_expired_accepted_work_uses_existing_expiry_procedure(existing):
    existing.chain.state=2
    assert existing.worker.reconcile_existing().phase=='settling'
    assert existing.sender.submit.call_args.args[2]=='1:close'
    existing.candidates.assert_not_called()


def test_original_upload_keeps_approved_retry_after_settlement_without_funding_it(existing):
    before=existing.journal.snapshot('original')
    existing.chain.state=5
    assert existing.worker.reconcile_existing(allow_retry=True).phase=='retry'
    after=existing.journal.snapshot('original')
    assert after['status']=='running' and after['attempts'][0]['outcome']=='failed'
    assert len(after['attempts'])==1
    assert (after['max_attempts'],after['max_debit'])==(before['max_attempts'],before['max_debit'])
    existing.candidates.assert_not_called();existing.sender.submit.assert_not_called()


def test_retry_option_never_overrides_owner_pause(existing):
    existing.journal.set_status('original','needs_action','Owner paused it')
    assert existing.worker.reconcile_existing(allow_retry=True).phase=='needs_action'
    existing.sender.submit.assert_not_called();existing.candidates.assert_not_called()


def test_cancelled_operation_still_requires_review_with_retry_option(existing):
    existing.chain.state=5
    existing.c.registry.functions.acceptanceTimedOut.return_value.call.return_value=False
    with pytest.raises(RecoveryNeedsAction):existing.worker.reconcile_existing(allow_retry=True)
    existing.sender.submit.assert_not_called()


def test_unresolved_dispute_prevents_premature_work_expiry(existing):
    existing.chain.state=2
    existing.c.manager.functions.pendingDisputes.return_value.call.return_value=1
    existing.c.manager.functions.getDispute.side_effect=lambda _:record_call(
        exists=True,resolved=False,deadline=300)
    assert existing.worker.reconcile_existing().phase=='complaints'
    existing.sender.submit.assert_not_called()


def test_owner_pause_does_not_authorize_new_settlement_transaction(existing):
    existing.journal.set_status('original','needs_action','Paused by owner')
    assert existing.worker.reconcile_existing().phase=='needs_action'
    existing.sender.submit.assert_not_called()
    existing.sender.recover.assert_called_once_with(signed_only=True)


@pytest.mark.parametrize('field,value',[('chain_id',31339)])
def test_wrong_network_is_rejected_before_replaying_any_envelope(existing,field,value):
    existing.c.w3.eth.chain_id=value
    with pytest.raises(RecoveryNeedsAction):existing.worker.reconcile_existing()
    existing.sender.recover.assert_not_called()
    existing.sender.submit.assert_not_called()


def test_funded_context_mismatch_cannot_be_settled(existing):
    existing.job.fileId=bytes.fromhex('ff'*32)
    with pytest.raises(RecoveryNeedsAction):existing.worker.reconcile_existing()
    existing.sender.submit.assert_not_called()


def test_paged_journal_scan_cannot_hide_an_open_attempt(existing):
    j=existing.journal
    rows=j.unfinished_operations(limit=1)
    assert len(rows)==1 and 'raw' not in rows[0]
    assert j.unfinished_operations(after_rowid=rows[0]['cursor'],limit=1)==[]
    args=dict(chain_id=31338,coordinator=existing.c.coordinator.address,
              owner=existing.sender.account.address)
    assert j.has_open_attempts(**args)
    assert not j.has_open_attempts(**args,skip_file_id='33'*32)
    assert not j.has_open_attempts(**{**args,'chain_id':31339})
    j.finish_attempt('original',1,'cancelled')
    assert not j.has_open_attempts(**args)
