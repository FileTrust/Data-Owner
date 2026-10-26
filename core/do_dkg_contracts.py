"""Versioned recovery contract client; no GUI, wallet/config reads or writes.

This ABI path is selected explicitly by the recovery controller. Legacy DO
operations continue to use their current contract objects until activation.
"""
import json
from pathlib import Path
from types import SimpleNamespace

from web3 import Web3


def record(fn):
    result, fields = fn.call(), fn.abi['outputs']
    if len(fields) == 1 and fields[0]['type'] == 'tuple':
        fields = fields[0]['components']
    return SimpleNamespace(**{field['name']: value for field, value in zip(fields, result)})


class DkgRecoveryContracts:
    def __init__(self, w3, coordinator_address, *, expected_chain_id, expected_acl, expected_staking):
        if type(expected_chain_id) is not int or w3.eth.chain_id != expected_chain_id:
            raise RuntimeError('The selected DKG recovery RPC belongs to another chain')
        self.w3 = w3
        self.coordinator = self._contract('ZkDkgCoordinatorV2', coordinator_address)
        f = self.coordinator.functions
        if f.acl().call().lower() != expected_acl.lower():
            raise RuntimeError('The recovery coordinator belongs to a different access controller')
        self.acl = self._contract('AccessControlFT', expected_acl)
        self.controller = self._contract('DkgAttemptController', f.attemptController().call())
        self.manager = self._contract('ZkDkgDisputeManager', f.disputeManager().call())
        share_proof = f.guardianShareProof().call()
        self.share_proof = self._contract('GuardianShareProof', share_proof) if int(share_proof, 16) else None
        cf = self.controller.functions
        self.registry = self._contract('DkgAttemptRegistry', cf.registry().call())
        self.escrow = self._contract('DkgAttemptEscrow', cf.escrow().call())
        self.book = self._contract('DkgCommitmentBook', cf.commitments().call())
        self.staking = self._contract('StakingManager', expected_staking)
        self.guardians = self._contract('GuardianRegistry', self.acl.functions.guardianRegistry().call())
        checks = [(cf.coordinator().call(), self.coordinator.address), (cf.acl().call(), self.acl.address),
            (cf.staking().call(), self.staking.address), (self.escrow.functions.staking().call(), self.staking.address),
            (self.registry.functions.coordinator().call(), self.controller.address),
            (self.escrow.functions.coordinator().call(), self.controller.address),
            (self.book.functions.controller().call(), self.controller.address),
            (self.manager.functions.zkDkgCoordinatorV2().call(), self.coordinator.address)]
        checks.append((self.manager.functions.dkg().call(), self.coordinator.address))
        checks.append((self.manager.functions.acl().call(), self.acl.address))
        if any(a.lower() != b.lower() for a, b in checks):
            raise RuntimeError('The selected DKG recovery deployment has incompatible wiring')
        if self.share_proof and (self.share_proof.functions.acl().call().lower() != self.acl.address.lower() or
                self.share_proof.functions.coordinatorV2().call().lower() != self.coordinator.address.lower()):
            raise RuntimeError('Guardian custody proofs belong to a different access controller')

    def _contract(self, name, address):
        path = Path(__file__).parent / 'contracts/recovery-v1' / f'{name}.json'
        artifact = json.loads(path.read_text())
        if artifact.get('protocol') != 'filetrust-dkg-recovery-v1':
            raise RuntimeError('Incompatible DKG recovery ABI version')
        address = Web3.to_checksum_address(address)
        if not self.w3.eth.get_code(address):
            raise RuntimeError('A required DKG recovery contract is not deployed')
        return self.w3.eth.contract(address=address, abi=artifact['abi'])

    def latest_refresh_cursor(self, file_id, epoch):
        pending = record(self.coordinator.functions.getPendingV2Refresh(file_id, epoch))
        if not pending.exists:
            return bytes(32)
        return bytes(self.coordinator.functions.getMaterialAttemptId(file_id, epoch, pending.shareVersion).call())

    def attempt(self, material_id):
        job = record(self.controller.functions.getJob(material_id))
        if not any(job.registryId):
            return None
        return job, record(self.registry.functions.getAttempt(job.registryId))

    def scope(self, file_id, epoch, version):
        return record(self.controller.functions.getAttemptRequest(file_id, epoch, version))

    def failed_members(self, material_id):
        """Public evidence for replacement, not a client decision to slash.

        Read only after authoritative terminal closure. Missing acceptance is
        unsuitable for this operation but carries no contractual fault. Once
        material was ready, honest dealers are not blamed for a silent receiver.
        """
        job, attempt = self.attempt(material_id)
        # Use the on-chain cause, including public third-party cleanup after a
        # DO crash. Elapsed time alone does not prove why a job was cancelled.
        timeout = attempt.state == 5 and self.registry.functions.acceptanceTimedOut(job.registryId).call()
        if attempt.state != 4 and not timeout:
            return []
        members = self.controller.functions.getParticipants(material_id).call()
        dealers, receivers, contributors = self.coordinator.functions.getAttemptWork(material_id).call()
        # Closed jobs keep their original evidence even if governance changes
        # the deployment's default manager before this DO comes back online.
        evidence = self._contract('ZkDkgDisputeManager', job.evidence)
        excluded = evidence.functions.excludedDealers(material_id).call()
        blocked_receivers = not job.readyAt or bool(excluded & contributors)
        failed = []
        for member in members:
            duty = record(self.registry.functions.getDuty(job.registryId, member))
            role = record(self.controller.functions.getRole(material_id, member))
            if not duty.accepted:
                failed.append(member)
            elif attempt.state == 4:
                bad_dealer = role.dealerIndex and ((excluded & (1 << (role.dealerIndex-1))) or
                    (not job.readyAt and not (dealers & (1 << (role.dealerIndex-1)))))
                bad_receiver = not blocked_receivers and role.receiverIndex and not (receivers & (1 << (role.receiverIndex-1)))
                if bad_dealer or bad_receiver:
                    failed.append(member)
        return failed

    def accounting(self, material_id, owner):
        job, _ = self.attempt(material_id)
        fund = record(self.escrow.functions.getFund(job.registryId))
        return {'settled': fund.settled, 'earned_fees_wei': fund.spent,
                'compensation_wei': fund.compensation, 'remaining_escrow_wei': fund.remaining,
                # This balance may include other operations; never label it
                # this attempt's received refund or add it to its spend cap.
                'owner_total_claimable_wei': self.escrow.functions.claimable(owner).call()}
