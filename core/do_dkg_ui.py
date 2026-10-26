"""GUI adapter for explicitly selected recovery-v1 operations.

No config or wallet is loaded at import. All contract work runs off the Tk
thread; review happens before creating a durable, spend-authorized operation.
"""
from dataclasses import fields
import json
import re
from secrets import SystemRandom, token_hex
import threading

from .do_dkg_contracts import DkgRecoveryContracts, record
from .do_dkg_journal import RecoveryJournal
from .do_dkg_paths import wallet_journal_path
from .do_dkg_recovery import RecoveryController, RecoveryTerms
from .do_dkg_tx import RecoverySender
from .do_dkg_withdraw import WithdrawalController,quote_withdrawal

_scheduled = False
_scheduled_root = None
_cursor = 0
_synced = set()
_progress_attempt = None
_preparing = False


def parse_ftu(text, *, positive=False):
    value = str(text).strip()
    if len(value) > 80 or not re.fullmatch(r'(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?', value):
        raise ValueError('Enter an FTU amount with at most 18 decimal places')
    # Decimal's default precision would round large amounts before conversion.
    whole, _, fraction = value.partition('.')
    result = int(whole)*10**18 + int((fraction+'0'*18)[:18])
    if result >= 2**256 or (positive and result == 0):
        raise ValueError('The FTU amount must fit the transaction limit and be positive')
    return result


def ftu_text(value):
    if value is None:
        return ''
    whole, fraction = divmod(int(value), 10**18)
    return str(whole) if not fraction else f'{whole}.{fraction:018d}'.rstrip('0')


def _env():
    from . import do_config as C, do_state as S, do_log as L, do_records as R, do_progress as P
    return C, S, L, R, P


def _contracts(op=None):
    C, _, _, _, _ = _env()
    if op:
        binding, intent = op['binding'], op['intent']
        if isinstance(binding, str): binding = json.loads(binding)
        if isinstance(intent, str): intent = json.loads(intent)
        return DkgRecoveryContracts(C.w3, binding['coordinator'], expected_chain_id=binding['chain_id'],
            expected_acl=intent['deployment']['acl'], expected_staking=intent['deployment']['staking'])
    settings = C.config.DKG_RECOVERY
    chain_id = settings.get('chain_id', C.config.CHAIN_ID)
    staking = settings.get('staking_manager_address') or C.config.STAKING_MANAGER_ADDRESS
    if type(chain_id) is not int or not staking:
        raise ValueError('Configure the recovery chain ID and staking contract before starting')
    return DkgRecoveryContracts(C.w3, C.config.ZKDKG_COORDINATOR_V2_ADDRESS, expected_chain_id=chain_id,
        expected_acl=C.config.ACL_ADDRESS, expected_staking=staking)


def _candidates(contracts, maximum):
    count = contracts.guardians.functions.getGuardianCount().call()
    for index in SystemRandom().sample(range(count), min(count, maximum)):
        yield contracts.guardians.functions.getGuardianAt(index).call()


def _sender(contracts, account, journal, intent):
    limits = intent['transaction_limits']
    return RecoverySender(contracts.w3, account, journal, allowed_targets=intent['allowed_contracts'],
        max_gas=limits['max_gas'], max_gas_price_wei=limits['max_gas_price_wei'])


def _fetch_result(contracts, snapshot):
    file_id = snapshot['binding']['file_id']
    key = record(contracts.coordinator.functions.getV2Key(file_id))
    if not key.exists or not key.finalized or key.dataOwner.lower() != snapshot['binding']['owner']:
        raise RuntimeError('The finalized key is unavailable for this wallet')
    from .do_v2_crypto import baby_is_on_curve
    if not baby_is_on_curve((key.publicKeyX,key.publicKeyY)):
        raise RuntimeError('The finalized key is not on the expected curve')
    guardians = contracts.acl.functions.getGuardiansForFile(file_id).call()
    fees, refunds, compensation, gas, uncovered = 0, 0, 0, 0, 0
    for attempt in snapshot['attempts']:
        if attempt['material'] and contracts.attempt(attempt['material']):
            book = contracts.accounting(attempt['material'], key.dataOwner)
            fees += book['earned_fees_wei']
            compensation += book['compensation_wei']
            if attempt['outcome'] != 'succeeded':
                uncovered += max(0,book['earned_fees_wei']-book['compensation_wei'])
            opening = snapshot.get('_openings', {}).get(attempt['number'])
            if opening and book['settled']:
                refunds += max(0, opening['budget']-book['earned_fees_wei'])
    for action in snapshot['actions']:
        if action['receipt']:
            receipt = json.loads(action['receipt'])
            gas += receipt['gasUsed']*receipt['effectiveGasPrice']
    return key, guardians, {'earned': fees, 'refund_credit': refunds, 'compensation_credit': compensation, 'gas': gas,'uncovered':uncovered}


def _save_result(result, snapshot, account):
    C, S, L, R, P = _env()
    if C.DO_ACCOUNT is None or C.DO_ACCOUNT.address != account.address:
        return
    origin=snapshot['binding'].get('coordinator')
    if origin and origin.lower()!=C.config.ZKDKG_COORDINATOR_V2_ADDRESS.lower():
        L.log_state(('dkg-origin',snapshot['id']),True,
            'Guardian key completed on its original deployment; switch to that deployment to use its saved result')
        _synced.add((str(C.BASE_DIR),snapshot['id']))
        return
    file_id = snapshot['binding']['file_id']
    key, guardians, accounting = result
    data = {'mode': 'ZKDKG_V2', 'curve': 'BabyJubjub', 'fileId': file_id, 'dataOwner': key.dataOwner,
        't': key.t, 'n': key.n, 'PKx': key.publicKeyX, 'PKy': key.publicKeyY,
        'keyEpoch': key.keyEpoch, 'shareVersion': key.shareVersion}
    R.save_pk_cache(data, write_legacy=False)
    labels = snapshot['intent'].get('labels', {})
    if labels.get('policy_name'):
        R.save_policy_record(labels['policy_name'], file_id, guardians, key.t)
    active = str(S.ACTIVE_FILE_ID_HEX or '').lower().removeprefix('0x') == file_id[2:]
    if active:
        S.PKX_VALUE, S.PKY_VALUE, S.KEY_EPOCH = key.publicKeyX, key.publicKeyY, key.keyEpoch
        S.LAST_PKX_VALUE, S.LAST_PKY_VALUE = key.publicKeyX, key.publicKeyY
        if not S.auto_upload_pending:
            P.finish('Guardian key ready')
        from .do_actions import _resume_auto_upload_after_key
        _resume_auto_upload_after_key()
    L.log_state(('dkg-recovery-complete', snapshot['id']), True,
        f'Guardian key finalized: epoch {key.keyEpoch}, share version {key.shareVersion}')
    if accounting is not None:
        L.log_state(('dkg-recovery-cost',snapshot['id']),tuple(accounting.values()),
            f'DKG fee credits: {ftu_text(accounting["earned"])} FTU; refund credit: {ftu_text(accounting["refund_credit"])} FTU; '
            f'compensation credit: {ftu_text(accounting["compensation_credit"])} FTU; transaction fees: {ftu_text(accounting["gas"])} FTU. '
            f'Failed-attempt fee credits not covered by compensation: {ftu_text(accounting.get("uncovered",0))} FTU. '
            'Escrow credits require a separate withdrawal; they are not confirmed wallet receipts.')
    _synced.add((str(C.BASE_DIR), snapshot['id']))


def _apply_progress(progress, snapshot):
    global _progress_attempt
    _, S, L, _, P = _env()
    L.log_state(('dkg-recovery', snapshot['id']), (progress.phase, progress.attempt, progress.completed, progress.total),
        f'DKG attempt {progress.attempt}/{snapshot["max_attempts"]}: {progress.message}'
        + (f' ({progress.completed}/{progress.total})' if progress.total else ''))
    active = str(S.ACTIVE_FILE_ID_HEX or '').lower().removeprefix('0x') == snapshot['binding']['file_id'][2:]
    if not active:
        return
    if progress.phase == 'needs_action':
        S.auto_upload_pending = False
        S.auto_quiet_info = False
        P.finish(progress.message, ok=False)
        return
    marker = (snapshot['id'], progress.attempt)
    if marker != _progress_attempt:
        if not P.is_running() or not S.auto_upload_pending:
            P.start('Guardian key', [('acceptances', .2), ('guardian commitments', .4), ('guardian shares', .4)])
        else:
            P.step('guardian commitments',0,1,'Starting the next bounded Guardian attempt')
            P.step('guardian shares',0,1,'Starting the next bounded Guardian attempt')
        _progress_attempt = marker
    note = f'Attempt {progress.attempt}/{snapshot["max_attempts"]}'
    if progress.phase == 'accepting':
        P.step('acceptances', progress.completed, progress.total, note)
    elif progress.phase == 'materials':
        P.step('acceptances', 1, 1, note)
        P.step('guardian commitments', progress.completed, progress.total, note)
    elif progress.phase == 'shares':
        P.step('acceptances', 1, 1, note)
        P.step('guardian commitments', 1, 1, note)
        P.step('guardian shares', progress.completed, progress.total, note)
    else:
        L.set_status(progress.message, 'waiting')


def start_reconciler():
    """Resume only recorded operations with their original approved limits."""
    global _scheduled, _scheduled_root
    C, S, L, _, _ = _env()
    if (_scheduled and _scheduled_root is S.root) or S.root is None or C.DKG_ATTEMPT_PROTOCOL != 1:
        return
    _scheduled = True
    _scheduled_root = S.root
    root = S.root

    def later(delay=3000):
        if S.root is root:
            try: root.after(delay, poll)
            except Exception: pass

    def work(account):
        global _cursor
        try:
            journal = RecoveryJournal(wallet_journal_path(account.address))
            pending_ops={row['operation'] for row in journal.pending_actions() if row['status']=='signed'}
            rows = [row for row in journal.operations() if row['status']=='running' or
                row['id'] in pending_ops or
                (row['status']=='succeeded' and (str(C.BASE_DIR),row['id']) not in _synced)]
            if not rows:
                root.after(0, later)
                return
            selected = rows[_cursor % len(rows)]
            _cursor += 1
            snapshot = journal.snapshot(selected['id'])
            if snapshot['binding']['owner'] != account.address.lower():
                raise ValueError('The recovery journal belongs to a different wallet')
            contracts = _contracts(snapshot)
            sender = _sender(contracts, account, journal, snapshot['intent'])
            withdrawal=snapshot['binding']['kind']=='withdrawal'
            if snapshot['status'] == 'running':
                if withdrawal:
                    controller=WithdrawalController(contracts,journal,sender,selected['id'])
                else:
                    maximum = snapshot['intent']['terms']['max_candidate_checks']
                    controller = RecoveryController(contracts, journal, sender, selected['id'], lambda: _candidates(contracts, maximum))
                progress = controller.step()
                snapshot = journal.snapshot(selected['id'])
            else:
                sender.recover(signed_only=True)
                snapshot=journal.snapshot(selected['id'])
                progress = None
            result = None
            if withdrawal and snapshot['status']=='succeeded':
                progress=WithdrawalController(contracts,journal,sender,selected['id']).result()
            elif snapshot['status']=='succeeded':
                snapshot['_openings'] = {attempt['number']:journal.stage_value(selected['id'],attempt['number'],'opening')
                                          for attempt in snapshot['attempts']}
                result = _fetch_result(contracts,snapshot)
            def apply():
                try:
                    if C.DO_ACCOUNT is not None and C.DO_ACCOUNT.address == account.address:
                        if withdrawal and progress:
                            if progress.phase=='withdrawn':
                                L.log_state(('dkg-withdrawn',snapshot['id']),True,
                                    f'DKG escrow withdrawal confirmed: {ftu_text(int(progress.message))} FTU received by your wallet')
                                _synced.add((str(C.BASE_DIR),snapshot['id']))
                            else:L.log_state(('dkg-withdrawal',snapshot['id']),progress.phase,progress.message)
                        elif progress: _apply_progress(progress, snapshot)
                        if result: _save_result(result, snapshot, account)
                except Exception as error:
                    L.log_every(('dkg-cache', type(error).__name__), 'DKG completed state retained; local display update will retry', seconds=60)
                later()
            root.after(0, apply)
        except Exception as error:
            def failed(kind=type(error).__name__):
                L.log_every(('dkg-recovery-rpc',kind), f'DKG recovery waiting ({kind}); saved limits and transactions retained', seconds=60)
                later(5000)
            try: root.after(0, failed)
            except Exception: pass

    def poll():
        global _scheduled
        if S.root is not root:
            if _scheduled_root is root:
                _scheduled = False
            return
        if C.DO_ACCOUNT is None or not C.ACCOUNT_READY:
            later()
            return
        threading.Thread(target=work, args=(C.DO_ACCOUNT,), daemon=True, name='dkg-recovery').start()
    later(100)


def start(kind):
    """Collect UI selection, prepare a read-only quote, then show one review."""
    C, S, L, _, _ = _env()
    if S.root is None:
        return
    S.root.after(0, lambda: _prepare(kind))


def _prepare(kind):
    global _preparing
    C, S, L, _, _ = _env()
    if _preparing or not C.ACCOUNT_READY or C.DO_ACCOUNT is None:
        return
    from . import do_actions as A, do_network as N
    context = A.get_current_file_context()
    if context is None:
        return
    selected = A._staged_guardians_checksum() or N.get_selected_guardians()
    threshold = N.get_guardian_threshold()
    days = N.get_service_duration_days()
    account = C.DO_ACCOUNT
    S.ACTIVE_FILE_ID,S.ACTIVE_FILE_ID_HEX=context[0],context[1]
    _preparing = True
    L.set_status('Checking Guardian recovery settings...', 'running')
    def work():
        global _preparing
        try:
            contracts = _contracts()
            policy = record(contracts.acl.functions.getDkgFilePolicy(context[0]))
            receivers = selected or list(policy.guardians)
            chosen_t = threshold or policy.threshold
            if not receivers or not 2 <= chosen_t <= len(receivers) or days <= 0:
                raise ValueError('Select a valid Guardian committee, threshold and service duration')
            journal = RecoveryJournal(wallet_journal_path(account.address))
            for row in journal.operations():
                binding = json.loads(row['binding'])
                if (row['status'] in ('running','needs_action') and binding['file_id'][2:]==bytes(context[0]).hex()
                        and binding['chain_id']==contracts.w3.eth.chain_id
                        and binding['coordinator']==contracts.coordinator.address.lower()):
                    snapshot=journal.snapshot(row['id'])
                    S.root.after(0,lambda saved=snapshot:_existing(saved))
                    return
            key = record(contracts.coordinator.functions.getV2Key(context[0]))
            if kind=='fresh' and key.exists and key.finalized:
                from .do_v2_crypto import baby_is_on_curve
                if key.dataOwner.lower()!=account.address.lower() or not baby_is_on_curve((key.publicKeyX,key.publicKeyY)):
                    raise ValueError('The existing finalized key does not match this wallet')
                guardians=contracts.acl.functions.getGuardiansForFile(context[0]).call()
                from web3 import Web3
                known={'id':'existing-key-'+bytes(context[0]).hex(),
                    'binding':{'file_id':Web3.to_hex(bytes(context[0])),'owner':account.address.lower()},
                    'intent':{'labels':{'policy_name':context[3]}}}
                S.root.after(0,lambda:_save_result((key,guardians,None),known,account))
                return
            if days and contracts.share_proof is None:
                raise ValueError('Guardian custody proofs are missing from the selected recovery deployment')
            suggestion = C.w3.eth.gas_price * 2
            S.root.after(0, lambda: _review(kind, contracts, context, receivers, chosen_t, days, account, key.t, suggestion))
        except Exception as error:
            message = str(error) if isinstance(error, ValueError) else f'Recovery settings unavailable ({type(error).__name__})'
            S.root.after(0, lambda msg=message: L.show_error('Guardian recovery', msg))
        finally:
            _preparing = False
    threading.Thread(target=work, daemon=True, name='dkg-quote').start()


def _existing(snapshot):
    import tkinter as tk
    from tkinter import ttk
    C,S,L,_,_=_env()
    account=C.DO_ACCOUNT
    if account is None or account.address.lower()!=snapshot['binding']['owner']:
        return
    withdrawal=snapshot['binding']['kind']=='withdrawal'
    window=tk.Toplevel(S.root);window.title('Escrow withdrawal' if withdrawal else 'Existing Guardian recovery');window.transient(S.root)
    frame=ttk.Frame(window,padding=16);frame.grid()
    caption=(snapshot['message'] or 'An approved recovery operation is already running')+'\n\n'
    caption+=f'Attempts: {len(snapshot["attempts"])}/{snapshot["max_attempts"]}\n'
    caption+=f'Debit committed: {ftu_text(snapshot["committed_debit_wei"])} / {ftu_text(snapshot["max_debit"])} FTU\n'
    caption+='These controls preserve the original spending and attempt limits.'
    ttk.Label(frame,text=caption,wraplength=520).grid(row=0,column=0,columnspan=3,sticky='w',pady=8)
    def change(action):
        window.destroy()
        def work():
            try:
                from .do_tx_manager import account_transaction_lock
                with account_transaction_lock(account.address,allow_recovery=True):
                    journal=RecoveryJournal(wallet_journal_path(account.address))
                    current=journal.snapshot(snapshot['id'])
                    if action=='pause':
                        journal.set_status(snapshot['id'],'needs_action','Paused by the operator; accepted duties remain on-chain')
                    elif action in ('resume','reconsider'):
                        if action=='reconsider' and current['attempts']:
                            latest=current['attempts'][-1]
                            if latest['outcome']=='pending':
                                raise ValueError('Complete or settle the current attempt before reconsidering candidates')
                            journal.stage_value(snapshot['id'],latest['number'],'reconsider_candidates',True)
                        journal.set_status(snapshot['id'],'running','')
                    else:
                        contracts=_contracts(current)
                        sender=_sender(contracts,account,journal,current['intent'])
                        for pending in journal.pending_actions():
                            if pending['operation']==snapshot['id'] and pending['status']=='reserved':
                                journal.abandon_unsigned(snapshot['id'],pending['id'])
                        sender.recover(signed_only=True)
                        paid=journal.action(snapshot['id'],'withdraw') if withdrawal else None
                        if paid and paid['status']=='confirmed' and json.loads(paid['receipt'])['status']==1:
                            raise ValueError('This withdrawal is already confirmed; resume it to record the received amount')
                        if current['attempts'] and current['attempts'][-1]['outcome']=='pending':
                            latest=current['attempts'][-1]
                            outcome='cancelled'
                            if latest['material']:
                                bound=contracts.attempt(latest['material'])
                                if bound is None:
                                    plan=json.loads(latest['intent'])
                                    file_id=current['binding']['file_id']
                                    material=contracts.coordinator.functions.getMaterialAttemptId(file_id,plan['epoch'],plan['version']).call()
                                    pending=(contracts.acl.functions.hasRequestedKeyGenForFile(file_id).call() if plan['version']==1 else
                                             contracts.coordinator.functions.hasPendingV2Refresh(file_id).call())
                                    if pending and material.hex().removeprefix('0x')==latest['material'][2:]:
                                        raise ValueError('This unfunded request is still open; resume it to finish or settle first')
                                elif bound[1].state<3:
                                    raise ValueError('This request is still open on-chain; resume it to finish or settle its duties first')
                                elif bound[1].state==3:
                                    raise ValueError('This key operation already succeeded; resume it to save its result')
                                else:
                                    outcome={4:'failed',5:'cancelled',6:'unactivated'}[bound[1].state]
                                    if bound[1].state==5 and contracts.registry.functions.acceptanceTimedOut(bound[0].registryId).call():
                                        outcome='failed'
                            else:
                                requested=journal.action(snapshot['id'],f"{latest['number']}:request")
                                if requested and requested['status']=='confirmed' and json.loads(requested['receipt'])['status']==1:
                                    raise ValueError('Resume the confirmed request before retiring its local record')
                            journal.finish_attempt(snapshot['id'],latest['number'],outcome)
                        journal.set_status(snapshot['id'],'stopped','Retired by the operator after closing its duties')
                S.root.after(0,start_reconciler)
            except Exception as error:
                message=str(error) if type(error) in (ValueError,RuntimeError) else f'Recovery state retained ({type(error).__name__})'
                S.root.after(0,lambda msg=message:L.show_error('Guardian recovery',msg))
        threading.Thread(target=work,daemon=True,name='dkg-control').start()
    ttk.Button(frame,text='Resume within limits',command=lambda:change('resume')).grid(row=1,column=0,padx=4,pady=8)
    ttk.Button(frame,text='Pause automatic work',command=lambda:change('pause')).grid(row=1,column=1,padx=4,pady=8)
    ttk.Button(frame,text='Retire closed operation',command=lambda:change('retire')).grid(row=1,column=2,padx=4,pady=8)
    if not withdrawal:
        ttk.Button(frame,text='Reconsider candidates for the next attempt',command=lambda:change('reconsider')).grid(row=2,column=0,columnspan=3,pady=8)


def claim_credits():
    C,S,L,_,_=_env()
    if S.root is None or C.DO_ACCOUNT is None or not C.ACCOUNT_READY:return
    account=C.DO_ACCOUNT
    def work():
        try:
            contracts=_contracts();journal=RecoveryJournal(wallet_journal_path(account.address))
            for row in journal.operations():
                binding=json.loads(row['binding'])
                if (binding['kind']=='withdrawal' and row['status'] in ('running','needs_action')
                        and binding['coordinator']==contracts.coordinator.address.lower()
                        and binding['chain_id']==contracts.w3.eth.chain_id):
                    saved=journal.snapshot(row['id'])
                    S.root.after(0,lambda saved=saved:_existing(saved));return
            quote=quote_withdrawal(contracts,account)
            if quote is None:
                S.root.after(0,lambda:L.show_info('DKG escrow','No DKG escrow credits are available for this wallet'));return
            def review():
                from tkinter import messagebox
                if C.DO_ACCOUNT is None or C.DO_ACCOUNT.address!=account.address:return
                accepted=messagebox.askyesno('Withdraw DKG credits',
                    f'Claimable fees, refunds and compensation: {ftu_text(quote.amount_wei)} FTU\n'
                    f'Maximum withdrawal transaction fee: {ftu_text(quote.maximum_fee_wei)} FTU\n'
                    f'Recipient: {account.address}\n\nThis is a separate authorization for withdrawal gas. Continue?',parent=S.root)
                if not accepted:return
                def authorize():
                    try:
                        if C.DO_ACCOUNT is None or C.DO_ACCOUNT.address!=account.address:raise ValueError('Wallet changed; review again')
                        WithdrawalController.create(contracts,journal,account,token_hex(16),quote)
                        S.root.after(0,start_reconciler)
                    except Exception as error:
                        S.root.after(0,lambda name=type(error).__name__:L.show_error('DKG withdrawal',f'Withdrawal could not start ({name}); saved state retained'))
                threading.Thread(target=authorize,daemon=True,name='dkg-withdraw-authorize').start()
            S.root.after(0,review)
        except Exception as error:
            S.root.after(0,lambda name=type(error).__name__:L.show_error('DKG withdrawal',f'Credits could not be checked ({name}); no new withdrawal authorized'))
    threading.Thread(target=work,daemon=True,name='dkg-withdraw-quote').start()


def _review(kind, contracts, context, receivers, threshold, days, account, old_t, suggested_gas_price):
    import tkinter as tk
    from tkinter import ttk
    C, S, L, _, _ = _env()
    if C.DO_ACCOUNT is None or C.DO_ACCOUNT.address != account.address:
        return
    settings = C.config.DKG_RECOVERY
    supplied = settings.get('terms', {})
    window = tk.Toplevel(S.root)
    window.title('Guardian recovery limits')
    window.transient(S.root)
    window.grab_set()
    frame = ttk.Frame(window, padding=16)
    frame.grid()
    operation_name='Fresh DKG' if kind=='fresh' else 'Same-key refresh'
    ttk.Label(frame, text=f'{operation_name} · {context[3]}\nWallet: {account.address}\n'
        f'{len(receivers)} Guardians · threshold {threshold} · {days} service days').grid(row=0,column=0,columnspan=2,sticky='w',pady=(0,12))
    rows = [
        ('Maximum attempts (1–32)', str(settings.get('max_attempts',3)), 'attempts'),
        ('Maximum total debit (FTU)', ftu_text(settings.get('max_debit_wei')), 'budget'),
        ('Acceptance allowance per Guardian (FTU)', ftu_text(supplied.get('acceptance_fee_wei')), 'acceptance_fee_wei'),
        ('Material allowance per dealer (FTU)', ftu_text(supplied.get('material_fee_wei')), 'material_fee_wei'),
        ('Share confirmation allowance (FTU)', ftu_text(supplied.get('share_key_fee_wei')), 'share_key_fee_wei'),
        ('Collateral from each Guardian stake (FTU)', ftu_text(supplied.get('bond_wei')), 'bond_wei'),
        ('Maximum gas price (wei per gas)', str(settings.get('max_gas_price_wei', suggested_gas_price)), 'gas_price'),
    ]
    entries = {}
    for row, (label, value, key) in enumerate(rows,1):
        ttk.Label(frame,text=label).grid(row=row,column=0,sticky='w',padx=(0,12),pady=3)
        entry=ttk.Entry(frame,width=28);entry.insert(0,value);entry.grid(row=row,column=1,pady=3)
        entries[key]=entry
    automatic=tk.BooleanVar(value=supplied.get('automatic_replacement',True))
    ttk.Checkbutton(frame,text='Automatically replace failed candidates within these limits',variable=automatic).grid(row=8,column=0,columnspan=2,sticky='w',pady=8)
    ttk.Label(frame,text='This DKG limit covers escrow funding and your transaction fees.\nRefunds do not increase it. Guardian collateral comes from their stake.\nDaily custody and PRE fees remain separate services.').grid(row=9,column=0,columnspan=2,sticky='w',pady=8)
    def cancel():
        window.destroy()
        if getattr(S,'auto_upload_pending',False):
            S.auto_upload_pending=False
            S.auto_quiet_info=False
        L.set_status('Guardian recovery cancelled before authorization','waiting')
    window.protocol('WM_DELETE_WINDOW',cancel)
    def confirm():
        try:
            attempts=int(entries['attempts'].get())
            if not 1 <= attempts <= 32: raise ValueError('Choose between 1 and 32 attempts')
            budget=parse_ftu(entries['budget'].get(),positive=True)
            fees={name:parse_ftu(entries[name].get()) for name in ('acceptance_fee_wei','material_fee_wei','share_key_fee_wei','bond_wei')}
            if any(fees[name]>=2**128 for name in ('acceptance_fee_wei','material_fee_wei','share_key_fee_wei')):
                raise ValueError('An allowance exceeds the contract limit')
            term_fields={field.name for field in fields(RecoveryTerms)}
            terms=RecoveryTerms(**{**{k:v for k,v in supplied.items() if k in term_fields}, **fees, 'automatic_replacement':automatic.get()})
            price=int(entries['gas_price'].get())
            if price<=0: raise ValueError('Maximum gas price must be positive')
            if not settings.get('profiles'): raise ValueError('Recovery proof profiles are missing from the network settings')
            profiles={tuple(p) for p in settings['profiles']}
            if (len(receivers),threshold) not in profiles: raise ValueError('This profile is not approved by the installed network settings')
        except (ValueError,KeyError,TypeError) as error:
            L.show_error('Recovery limits',str(error));return
        window.destroy()
        S.ACTIVE_FILE_ID,S.ACTIVE_FILE_ID_HEX=context[0],context[1]
        def create():
            try:
                if C.DO_ACCOUNT is None or C.DO_ACCOUNT.address!=account.address:
                    raise ValueError('The wallet changed; review the operation again')
                journal=RecoveryJournal(wallet_journal_path(account.address))
                targets=[contracts.acl.address,contracts.coordinator.address,contracts.controller.address,contracts.escrow.address,contracts.manager.address]
                if contracts.share_proof: targets.append(contracts.share_proof.address)
                sender=RecoverySender(C.w3,account,journal,allowed_targets=targets,max_gas_price_wei=price,
                    max_gas=int(settings.get('max_transaction_gas',12000000)))
                operation=token_hex(16)
                RecoveryController.create(contracts,journal,sender,operation,lambda:_candidates(contracts,terms.max_candidate_checks),
                    file_id=context[0],kind=kind,receivers=receivers,threshold=threshold,profiles=profiles,terms=terms,
                    max_attempts=attempts,max_debit_wei=budget,service_days=days,policy_seed=context[2],
                    labels={'policy_name':context[3]})
                S.root.after(0,start_reconciler)
            except Exception as error:
                message=str(error) if isinstance(error,(ValueError,RuntimeError)) and type(error).__module__!='web3.exceptions' else 'Recovery could not start; no new limits were approved'
                S.root.after(0,lambda msg=message:L.show_error('Guardian recovery',msg))
        threading.Thread(target=create,daemon=True,name='dkg-authorize').start()
    ttk.Button(frame,text='Cancel',command=cancel).grid(row=10,column=0,sticky='e',pady=(12,0))
    ttk.Button(frame,text='Start recovery',command=confirm).grid(row=10,column=1,sticky='e',pady=(12,0))
