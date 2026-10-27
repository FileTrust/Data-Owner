"""Owner-controlled, bounded recovery for the versioned accepted-duty DKG.

One step performs at most one new chain mutation. All selections, request
cursors, deadlines and signed transactions survive a GUI/process restart.
Legacy DO actions do not enter this controller without an explicit version gate.
"""
from dataclasses import asdict, dataclass
import json

from web3 import Web3

from .do_dkg_contracts import record
from .do_dkg_journal import RecoveryLimit
from .do_dkg_selection import NoEligibleGuardians, addresses, select_replacements
from .do_dkg_tx import RecoveryTransactionPending
from .do_tx_manager import account_transaction_lock


class RecoveryNeedsAction(RuntimeError):
    pass


@dataclass(frozen=True)
class RecoveryTerms:
    acceptance_fee_wei: int
    material_fee_wei: int
    share_key_fee_wei: int
    bond_wei: int
    acceptance_seconds: int = 300
    material_seconds: int = 900
    receiver_seconds: int = 900
    heartbeat_max_age_seconds: int = 2700
    max_candidate_checks: int = 100
    automatic_replacement: bool = True

    def __post_init__(self):
        for name, value in asdict(self).items():
            if name == 'automatic_replacement':
                if type(value) is not bool:
                    raise ValueError('Automatic replacement must be true or false')
            elif type(value) is not int or value < (0 if name.endswith('_wei') else 1):
                raise ValueError(f'Invalid DKG recovery setting: {name}')
        if any(value > 86400 for value in (self.acceptance_seconds, self.material_seconds, self.receiver_seconds)):
            raise ValueError('Recovery stage windows exceed the contract limits')
        if not 20 <= self.max_candidate_checks <= 1000:
            raise ValueError('Recovery candidate checks must be bounded between 20 and 1000')


@dataclass(frozen=True)
class RecoveryProgress:
    phase: str
    message: str
    attempt: int = 0
    completed: int = 0
    total: int = 0


class RecoveryController:
    def __init__(self, contracts, journal, sender, operation, candidate_provider):
        self.c, self.journal, self.sender = contracts, journal, sender
        self.operation, self.candidate_provider = operation, candidate_provider
        self.w3 = contracts.w3

    @classmethod
    def create(cls, contracts, journal, sender, operation, candidate_provider, *, file_id, kind,
               receivers, threshold, profiles, terms, max_attempts, max_debit_wei, service_days=0, policy_seed=None, labels=None):
        file_id = bytes.fromhex(str(file_id).removeprefix('0x')) if isinstance(file_id, str) else bytes(file_id)
        receivers = addresses(receivers)
        if len(file_id) != 32 or (len(receivers), threshold) not in profiles or type(service_days) is not int or service_days < 0:
            raise ValueError('Invalid approved Guardian recovery profile or service duration')
        policy = record(contracts.acl.functions.getDkgFilePolicy(file_id))
        if policy.exists:
            if not policy.active or policy.dataOwner.lower() != sender.account.address.lower():
                raise RecoveryNeedsAction('This file policy is inactive or belongs to a different wallet')
        else:
            if kind != 'fresh' or policy_seed is None or len(bytes(policy_seed)) != 32 or Web3.solidity_keccak(
                    ['address','bytes32'], [sender.account.address, bytes(policy_seed)]) != file_id:
                raise RecoveryNeedsAction('A fresh file needs its matching policy identifier before DKG')
        key = record(contracts.coordinator.functions.getV2Key(file_id))
        if (kind == 'fresh' and key.exists and key.finalized) or (kind == 'refresh' and not (key.exists and key.finalized)):
            raise RecoveryNeedsAction('Use same-key refresh for an existing key; use fresh DKG when no finalized key exists')
        old_guardians = []
        if kind == 'refresh':
            for i in range(1, key.n+1):
                public = record(contracts.coordinator.functions.getV2SharePublicKeyFull(file_id, key.keyEpoch, key.shareVersion, i))
                if not public.exists:
                    raise RecoveryNeedsAction('The previous active share committee is incomplete')
                old_guardians.append(public.guardian)
        allowed = [contracts.acl.address, contracts.coordinator.address, contracts.controller.address,
                   contracts.escrow.address, contracts.manager.address]
        if service_days:
            if contracts.share_proof is None:
                raise RecoveryNeedsAction('Guardian custody proofs must be configured for the requested service period')
            allowed.append(contracts.share_proof.address)
        intent = {'receivers': receivers, 'n': len(receivers), 't': threshold, 'profiles': [list(p) for p in sorted(profiles)],
            'terms': asdict(terms), 'service_days': service_days, 'allowed_contracts': allowed,
            'transaction_limits': {'max_gas': sender.max_gas, 'max_gas_price_wei': sender.max_price},
            'deployment': {'acl': contracts.acl.address, 'staking': contracts.staking.address},
            'policy_seed': Web3.to_hex(bytes(policy_seed)) if policy_seed is not None else None,
            'labels': dict(labels or {}),
            'old_guardians': old_guardians, 'old_t': key.t if old_guardians else 0,
            'baseline_epoch': key.keyEpoch if key.exists else 0,
            'baseline_version': key.shareVersion if key.exists else 0,
            'public_key': [key.publicKeyX, key.publicKeyY] if key.exists else None}
        journal.create(operation, chain_id=contracts.w3.eth.chain_id, coordinator=contracts.coordinator.address,
            owner=sender.account.address, file_id=Web3.to_hex(file_id), kind=kind, intent=intent,
            max_attempts=max_attempts, max_debit_wei=max_debit_wei)
        return cls(contracts, journal, sender, operation, candidate_provider)

    def _send(self, attempt, label, fn, *, value=0):
        receipt = self.sender.submit(self.operation, attempt, f'{attempt}:{label}', fn, value=value)
        if int(receipt['status']) != 1:
            raise RecoveryNeedsAction('A recovery transaction reverted; its actual gas cost is saved for review')
        return receipt

    def _eligible(self, op, terms, now, *, excluded=(), preferred_receivers=None):
        from itertools import chain
        preferred = list(dict.fromkeys(a.lower() for a in
            [*(preferred_receivers or op['intent']['receivers']), *op['intent']['old_guardians']]))
        failed = {a.lower() for a in excluded}
        old_holders = {a.lower() for a in op['intent']['old_guardians']}
        eligible, seen, checked = [], set(), 0
        # The provider can yield registry/directory candidates lazily. Healthy
        # selected nodes are checked first; a new pool is queried only if needed.
        for address in chain(preferred, self.candidate_provider()):
            normalized = str(address).lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            if normalized not in failed:
                if checked >= terms.max_candidate_checks:
                    break
                checked += 1
                address = Web3.to_checksum_address(address)
                status = record(self.c.guardians.functions.getGuardianOperationalStatus(address))
                if status.registered and status.active and status.lastHeartbeat and now-status.lastHeartbeat <= terms.heartbeat_max_age_seconds:
                    availability = record(self.c.guardians.functions.getGuardianAvailability(address))
                    if availability.exists and (availability.unlimited or availability.maxServiceDays >= op['intent']['service_days']):
                        x, y = self.c.guardians.functions.getGuardianDkgBabyJubjubPublicKey(address).call()
                        digest = Web3.keccak(int(x).to_bytes(32, 'big') + int(y).to_bytes(32, 'big'))
                        if self.c.manager.functions.validatedEncryptionKeys(digest).call():
                            stake = self.c.staking.functions
                            available = stake.stakeOf(address).call()-stake.lockedStakeOf(address).call()-stake.minimumGuardianStake().call()
                            if available >= terms.bond_wei:
                                eligible.append(address)
            enough_old = sum(a.lower() in old_holders for a in eligible) >= op['intent']['old_t']
            if set(preferred).issubset(seen) and len(eligible) >= op['intent']['n'] and enough_old:
                break
        return eligible

    def _plan(self, op, terms, now):
        self._check_baseline(op)
        old = op['attempts'][-1] if op['attempts'] else None
        number = 1 if old is None else old['number']+1
        if number > op['max_attempts'] or (old and not terms.automatic_replacement):
            raise RecoveryNeedsAction('The recovery attempt limit was reached or automatic replacement is disabled')
        previous = json.loads(old['intent']) if old else {}
        excluded = previous.get('excluded', [])
        reset = bool(old and self.journal.stage_value(self.operation, old['number'], 'reconsider_candidates'))
        if reset:
            excluded = []
        elif old and old['material'] and self.c.attempt(old['material']):
            excluded = list(dict.fromkeys([*excluded, *self.c.failed_members(old['material'])]))
        plan = select_replacements(receivers=previous.get('receivers', op['intent']['receivers']),
            n=op['intent']['n'], t=op['intent']['t'], eligible=self._eligible(op, terms, now, excluded=excluded,
                preferred_receivers=previous.get('receivers')), excluded=excluded,
            profiles={tuple(p) for p in op['intent']['profiles']},
            old_guardians=op['intent']['old_guardians'] or None,
            old_threshold=op['intent']['old_t'] or None,
            previous_dealers=previous.get('dealer_indices', ()) if op['binding']['kind'] == 'refresh' else ())
        file_id = bytes.fromhex(op['binding']['file_id'][2:])
        descriptor = {'receivers': list(plan.receivers), 'dealer_indices': list(plan.dealer_indices), 'excluded': excluded}
        if op['binding']['kind'] == 'fresh':
            if self.c.acl.functions.hasRequestedKeyGenForFile(file_id).call():
                raise RecoveryNeedsAction('A different DKG request is already open; resume or close it first')
            descriptor.update(epoch=op['intent']['baseline_epoch']+1, version=1,
                previous_nonce=self.c.acl.functions.keyGenAttemptNonce(file_id).call())
        else:
            if self.c.coordinator.functions.hasPendingV2Refresh(file_id).call():
                raise RecoveryNeedsAction('A different same-key request is already open; resume or close it first')
            descriptor.update(epoch=op['intent']['baseline_epoch'], version=op['intent']['baseline_version']+1,
                previous_cursor=Web3.to_hex(self.c.latest_refresh_cursor(file_id, op['intent']['baseline_epoch'])))
        self.journal.begin_attempt(self.operation, number, descriptor)
        return self.journal.snapshot(self.operation)['attempts'][-1]

    def _check_baseline(self, op):
        file_id = bytes.fromhex(op['binding']['file_id'][2:])
        key = record(self.c.coordinator.functions.getV2Key(file_id))
        if op['binding']['kind'] == 'fresh':
            if key.exists and key.finalized:
                raise RecoveryNeedsAction('A key has already completed; automatic recovery will not replace it')
        elif (not key.exists or not key.finalized or key.keyEpoch != op['intent']['baseline_epoch'] or
              key.shareVersion != op['intent']['baseline_version'] or
              [key.publicKeyX, key.publicKeyY] != op['intent']['public_key']):
            raise RecoveryNeedsAction('The active key or share version changed outside this recovery operation')

    def _request(self, op, attempt, plan, file_id):
        request = self.journal.action(self.operation, f"{attempt['number']}:request")
        if request is None:
            self._check_baseline(op)
            policy = record(self.c.acl.functions.getDkgFilePolicy(file_id))
            if policy.exists and (not policy.active or policy.dataOwner.lower() != self.sender.account.address.lower()):
                raise RecoveryNeedsAction('The file policy was disabled or belongs to a different wallet')
            if op['intent']['service_days']:
                exists, _, _, days = self.c.share_proof.functions.getPolicyServicePeriod(file_id).call()
                if exists and days != op['intent']['service_days']:
                    raise RecoveryNeedsAction(
                        'The Guardian service period already exists; use funded Guardian renewal '
                        'for extra days or a new policy for a new agreement')
            if not policy.exists:
                seed = op['intent'].get('policy_seed')
                if seed is None:
                    raise RecoveryNeedsAction('The file policy is missing and its creation was not approved')
                self._send(attempt['number'], 'policy-create', self.c.acl.functions.createFilePolicyWithMode(
                    seed, plan['receivers'], op['intent']['t'], 1, op['intent']['service_days']))
                return RecoveryProgress('policy', 'File policy created within the recovery budget', attempt['number'])
            if [a.lower() for a in policy.guardians] != [a.lower() for a in plan['receivers']] or policy.threshold != op['intent']['t']:
                self._send(attempt['number'], 'policy', self.c.acl.functions.updateFilePolicy(
                    file_id, plan['receivers'], op['intent']['t'], op['intent']['service_days']))
                actual = record(self.c.acl.functions.getDkgFilePolicy(file_id))
                if actual.threshold != op['intent']['t'] or [a.lower() for a in actual.guardians] != [a.lower() for a in plan['receivers']]:
                    raise RecoveryNeedsAction('The policy changed outside this recovery operation')
                return RecoveryProgress('policy', 'Replacement committee saved on-chain', attempt['number'])
            if op['intent']['service_days']:
                exists, _, _, days = self.c.share_proof.functions.getPolicyServicePeriod(file_id).call()
                if not exists:
                    self._send(attempt['number'], 'service-period', self.c.share_proof.functions.setPolicyServicePeriod(
                        file_id, op['intent']['service_days']))
                    recorded, _, _, actual_days = self.c.share_proof.functions.getPolicyServicePeriod(file_id).call()
                    if not recorded or actual_days != op['intent']['service_days']:
                        raise RecoveryNeedsAction('The Guardian service period changed outside this recovery operation')
                    return RecoveryProgress('policy', 'Guardian service period recorded within the recovery budget', attempt['number'])
        if plan['version'] == 1:
            fn = self.c.acl.functions.requestKeyGenForFileWithNonce(file_id, plan['previous_nonce'])
        else:
            fn = self.c.coordinator.functions.requestV2SamePkShareRefreshForVersion(file_id, plan['epoch'],
                op['intent']['baseline_version'], plan['previous_cursor'], plan['dealer_indices'])
        receipt = self._send(attempt['number'], 'request', fn)
        if plan['version'] == 1:
            material = Web3.keccak(self.w3.codec.encode(['uint256','address','bytes32','uint32','uint8','uint64'],
                [op['binding']['chain_id'], self.c.coordinator.address, file_id, plan['epoch'], 0, plan['previous_nonce']+1]))
        else:
            from web3.logs import DISCARD
            full = self.w3.eth.get_transaction_receipt(receipt['transactionHash'])
            events = self.c.coordinator.events.ZkDkgV2SamePkRefreshRequested().process_receipt(full, errors=DISCARD)
            events = [e for e in events if e['address'].lower() == self.c.coordinator.address.lower() and
                bytes(e['args']['fileId']) == file_id and e['args']['keyEpoch'] == plan['epoch'] and
                e['args']['shareVersion'] == plan['version']]
            if len(events) != 1:
                raise RecoveryNeedsAction('The confirmed request does not identify the expected refresh attempt')
            material = events[0]['args']['materialId']
        self.journal.bind_material(self.operation, attempt['number'], Web3.to_hex(material))
        return RecoveryProgress('requested', 'Guardian request confirmed', attempt['number'])

    def _opening(self, op, attempt, plan, terms, now, file_id):
        self._check_baseline(op)
        material = attempt['material']
        scope = self.c.scope(file_id, plan['epoch'], plan['version'])
        if (Web3.to_hex(scope.materialId) != material or scope.newT != op['intent']['t'] or
                [a.lower() for a in scope.receivers] != [a.lower() for a in plan['receivers']] or
                sorted(scope.dealerIndices) != sorted(plan['dealer_indices'])):
            raise RecoveryNeedsAction('The chain request differs from this saved recovery attempt')
        if now > scope.unopenedDeadline:
            self._send(attempt['number'], 'unopened-expiry', self.c.controller.functions.cancelUnopened(material, file_id, plan['epoch'], plan['version']))
            self.journal.finish_attempt(self.operation, attempt['number'], 'failed')
            return RecoveryProgress('retry', 'The unfunded request expired; no Guardian accepted a duty', attempt['number'])
        preparation = self.c.controller.functions.preparations(material).call()
        if int(preparation[2], 16) == 0:
            self._send(attempt['number'], 'prepare', self.c.controller.functions.prepare(material, file_id, plan['epoch'], plan['version']))
            return RecoveryProgress('prepared', 'Proof profile and encryption snapshot prepared', attempt['number'])
        opening = self.journal.stage_value(self.operation, attempt['number'], 'opening')
        if opening is None:
            members = self.c.controller.functions.participantsFor(file_id, plan['epoch'], plan['version']).call()
            dealers = {scope.oldGuardians[i-1].lower() for i in scope.dealerIndices}
            receivers = {a.lower() for a in scope.receivers}
            fees = [[terms.acceptance_fee_wei, terms.material_fee_wei if a.lower() in dealers else 0,
                     terms.share_key_fee_wei if a.lower() in receivers else 0] for a in members]
            opening = {'accept_by': now+terms.acceptance_seconds, 'fees': fees,
                       'bonds': [terms.bond_wei]*len(members), 'budget': sum(sum(fee) for fee in fees)}
            self.journal.stage_value(self.operation, attempt['number'], 'opening', opening)
        self._send(attempt['number'], 'open', self.c.controller.functions.open(material, file_id, plan['epoch'], plan['version'],
            opening['accept_by'], terms.material_seconds, terms.receiver_seconds, opening['fees'], opening['bonds']), value=opening['budget'])
        job, _ = self.c.attempt(material)
        self.journal.bind_material(self.operation, attempt['number'], material, Web3.to_hex(job.contextHash))
        return RecoveryProgress('accepting', 'Funded duties are waiting for Guardian acceptance', attempt['number'])

    def _closed(self, op, attempt, plan, job, chain, file_id):
        if chain.state == 3:
            key = record(self.c.coordinator.functions.getV2Key(file_id))
            active = self.c.coordinator.functions.getMaterialAttemptId(file_id, plan['epoch'], plan['version']).call()
            if not key.finalized or key.keyEpoch < plan['epoch'] or Web3.to_hex(active) != attempt['material']:
                raise RecoveryNeedsAction('Completed work does not identify the saved successful key version')
            if op['binding']['kind'] == 'refresh' and [key.publicKeyX, key.publicKeyY] != op['intent']['public_key']:
                raise RecoveryNeedsAction('Same-key refresh returned a different public key')
            self.journal.finish_attempt(self.operation, attempt['number'], 'succeeded')
            return RecoveryProgress('succeeded', 'Guardian key operation finalized on-chain', attempt['number'], 1, 1)
        timed_out = chain.state == 5 and self.c.registry.functions.acceptanceTimedOut(job.registryId).call()
        outcome = 'failed' if timed_out else {4:'failed', 5:'cancelled', 6:'unactivated'}[chain.state]
        self.journal.finish_attempt(self.operation, attempt['number'], outcome)
        if chain.state != 4 and not timed_out:
            raise RecoveryNeedsAction('The request was cancelled or completed work was left unactivated; automatic replacement is stopped')
        return RecoveryProgress('retry', 'Failed duties settled; preparing a bounded replacement', attempt['number'])

    def _running(self, op, attempt, plan, job, chain, now, file_id):
        material = attempt['material']
        expected_context = Web3.to_hex(job.contextHash)
        if attempt['context'] is None:
            self.journal.bind_material(self.operation, attempt['number'], material, expected_context)
        elif attempt['context'] != expected_context:
            raise RecoveryNeedsAction('Accepted job context differs from the saved recovery operation')
        if chain.state >= 3:
            return self._closed(op, attempt, plan, job, chain, file_id)
        if chain.state == 1:
            count = len(self.c.controller.functions.getParticipants(material).call())
            if now > chain.acceptBy:
                self.journal.stage_value(self.operation, attempt['number'], 'closing', {'reason': 'acceptance_timeout'})
                self._send(attempt['number'], 'close', self.c.controller.functions.expire(material))
                return RecoveryProgress('settling', 'Acceptance timeout settled without blaming non-accepting Guardians', attempt['number'])
            return RecoveryProgress('accepting', 'Waiting for accepted duties', attempt['number'], chain.acceptedCount, count)
        dealers, receivers, contributors = self.c.coordinator.functions.getAttemptWork(material).call()
        pending = self.c.manager.functions.pendingDisputes(material).call()
        bad = self.c.manager.functions.excludedDealers(material).call()
        if receivers == (1 << op['intent']['n'])-1 and not pending and not (bad & contributors):
            if plan['version'] == 1:
                xs, ys = self.c.book.functions.getAggregate(material).call()
                fn = self.c.coordinator.functions.finalizeV2DkgForAttempt(material, file_id, plan['epoch'], xs[0], ys[0])
            else:
                fn = self.c.coordinator.functions.finalizeV2RefreshForAttempt(material, file_id, plan['epoch'], plan['version'])
            self._send(attempt['number'], 'finalize', fn)
            return RecoveryProgress('finalizing', 'All confirmed shares finalized; checking the active version', attempt['number'])
        if pending:
            for dealer in plan['dealer_indices']:
                for receiver in range(1, op['intent']['n']+1):
                    if plan['version'] == 1 and receiver == dealer:
                        continue
                    dispute_id = self.c.manager.functions.disputeIdFor(material, plan['epoch'], plan['version'], plan['version'] > 1, dealer, receiver).call()
                    dispute = record(self.c.manager.functions.getDispute(dispute_id))
                    if dispute.exists and not dispute.resolved and now > dispute.deadline:
                        self._send(attempt['number'], f'close-complaint-{dealer}-{receiver}',
                            self.c.manager.functions.finalizeExpiredZkDkgEncryptedShareDispute(dispute_id))
                        return RecoveryProgress('complaints', 'Expired complaint resolved using its accepted deadline', attempt['number'])
        if (now > chain.workDeadline or (not job.readyAt and now > chain.workDeadline-job.receiverDuration)) and not pending:
            self._send(attempt['number'], 'close', self.c.controller.functions.expire(material))
            return RecoveryProgress('settling', 'Expired work settled using chain evidence', attempt['number'])
        if pending:
            return RecoveryProgress('complaints', 'Waiting for complaint resolution', attempt['number'])
        if not job.readyAt:
            return RecoveryProgress('materials', 'Confirmed dealer material', attempt['number'],
                                    int(dealers).bit_count(), len(plan['dealer_indices']))
        return RecoveryProgress('shares', 'Confirmed Guardian shares', attempt['number'],
                                int(receivers).bit_count(), op['intent']['n'])

    def step(self):
        with account_transaction_lock(self.sender.account.address, allow_recovery=True):
            try:
                self.sender.recover()
                op = self.journal.snapshot(self.operation)
                if op['status'] != 'running':
                    return RecoveryProgress(op['status'], op.get('message') or 'Recovery is complete or requires operator action')
                terms = RecoveryTerms(**op['intent']['terms'])
                now = self.w3.eth.get_block('latest')['timestamp']
                attempt = op['attempts'][-1] if op['attempts'] else None
                if attempt is None or attempt['outcome'] != 'pending':
                    attempt = self._plan(op, terms, now)
                plan = json.loads(attempt['intent'])
                file_id = bytes.fromhex(op['binding']['file_id'][2:])
                if attempt['material'] is None:
                    return self._request(op, attempt, plan, file_id)
                bound = self.c.attempt(attempt['material'])
                if bound:
                    return self._running(op, attempt, plan, *bound, now, file_id)
                return self._opening(op, attempt, plan, terms, now, file_id)
            except RecoveryTransactionPending:
                return RecoveryProgress('confirmation', 'Transaction confirmation is uncertain; saved transaction retained')
            except (RecoveryNeedsAction, RecoveryLimit, NoEligibleGuardians) as error:
                self.journal.set_status(self.operation, 'needs_action', str(error))
                return RecoveryProgress('needs_action', str(error))
