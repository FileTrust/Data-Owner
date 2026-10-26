"""Explicit escrow-credit withdrawal using the account's durable wallet lane.

The new authorization covers withdrawal gas only. Credits never replenish a
DKG budget, and confirmation requires the escrow's actual payment event.
"""
from dataclasses import dataclass

from web3.logs import DISCARD

from .do_dkg_journal import RecoveryLimit
from .do_dkg_recovery import RecoveryProgress
from .do_dkg_tx import RecoverySender,RecoveryTransactionPending
from .do_tx_manager import account_transaction_lock


class WithdrawalNeedsAction(RuntimeError):
    pass


@dataclass(frozen=True)
class WithdrawalQuote:
    chain_id:int
    coordinator:str
    escrow:str
    owner:str
    amount_wei:int
    gas:int
    gas_price:int

    @property
    def maximum_fee_wei(self):return self.gas*self.gas_price


def quote_withdrawal(contracts,account):
    with account_transaction_lock(account.address):
        amount=contracts.escrow.functions.claimable(account.address).call()
        if amount<=0:return None
        price=int(contracts.w3.eth.gas_price)
        if price<=0:raise ValueError('Withdrawal gas price is unavailable')
        fn=contracts.escrow.functions.withdrawTo(account.address)
        fields={'from':account.address,'gas':300000,'gasPrice':price}
        fn.call(fields)
        gas=min(300000,max(21000,(int(fn.estimate_gas(fields))*6+4)//5))
        return WithdrawalQuote(contracts.w3.eth.chain_id,contracts.coordinator.address,
            contracts.escrow.address,account.address,int(amount),gas,price)


class WithdrawalController:
    def __init__(self,contracts,journal,sender,operation):
        self.c,self.journal,self.sender,self.operation=contracts,journal,sender,operation

    @classmethod
    def create(cls,contracts,journal,account,operation,quote):
        if (quote.chain_id!=contracts.w3.eth.chain_id or quote.coordinator.lower()!=contracts.coordinator.address.lower() or
            quote.escrow.lower()!=contracts.escrow.address.lower() or quote.owner.lower()!=account.address.lower() or
            quote.amount_wei<=0 or quote.maximum_fee_wei<=0):
            raise ValueError('The withdrawal quote belongs to a different wallet or deployment')
        intent={'allowed_contracts':[contracts.escrow.address],
            'transaction_limits':{'max_gas':quote.gas,'max_gas_price_wei':quote.gas_price},
            'deployment':{'acl':contracts.acl.address,'staking':contracts.staking.address},
            'quoted_credit_wei':quote.amount_wei,'beneficiary':account.address}
        journal.create(operation,chain_id=quote.chain_id,coordinator=quote.coordinator,owner=account.address,
            file_id='0x'+'00'*32,kind='withdrawal',intent=intent,max_attempts=1,max_debit_wei=quote.maximum_fee_wei)
        sender=RecoverySender(contracts.w3,account,journal,allowed_targets=intent['allowed_contracts'],
            max_gas=quote.gas,max_gas_price_wei=quote.gas_price)
        return cls(contracts,journal,sender,operation)

    def step(self):
        with account_transaction_lock(self.sender.account.address,allow_recovery=True):
            try:
                self.sender.recover()
                op=self.journal.snapshot(self.operation)
                if op['binding']['kind']!='withdrawal':raise WithdrawalNeedsAction('This is not a withdrawal authorization')
                if op['status']=='succeeded':return self.result()
                if op['status']!='running':return RecoveryProgress(op['status'],op.get('message') or 'Withdrawal paused')
                self.journal.begin_attempt(self.operation,1,{'beneficiary':op['intent']['beneficiary']})
                receipt=self.sender.submit(self.operation,1,'withdraw',
                    self.c.escrow.functions.withdrawTo(self.sender.account.address))
                if int(receipt['status'])!=1:raise WithdrawalNeedsAction('Withdrawal reverted; its actual gas cost is saved')
                full=self.c.w3.eth.get_transaction_receipt(receipt['transactionHash'])
                events=self.c.escrow.events.Claimed().process_receipt(full,errors=DISCARD)
                paid=[event['args']['amount'] for event in events if
                    event['address'].lower()==self.c.escrow.address.lower() and
                    event['args']['account'].lower()==self.sender.account.address.lower() and
                    event['args']['recipient'].lower()==self.sender.account.address.lower()]
                if len(paid)!=1 or paid[0]<=0:raise WithdrawalNeedsAction('The confirmed receipt does not identify a withdrawal to this wallet')
                self.journal.stage_value(self.operation,1,'withdrawn_wei',str(paid[0]))
                self.journal.finish_attempt(self.operation,1,'succeeded')
                return self.result()
            except RecoveryTransactionPending:
                return RecoveryProgress('confirmation','Withdrawal confirmation is uncertain; the original signed transaction is retained')
            except (RecoveryLimit,WithdrawalNeedsAction) as error:
                self.journal.set_status(self.operation,'needs_action',str(error))
                return RecoveryProgress('needs_action',str(error))

    def result(self):
        amount=self.journal.stage_value(self.operation,1,'withdrawn_wei')
        if amount is None:raise RuntimeError('The confirmed withdrawal amount is missing')
        return RecoveryProgress('withdrawn',str(amount),1)
