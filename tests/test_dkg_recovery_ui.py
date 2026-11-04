import ast
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace as NS

import pytest

from core.do_dkg_ui import parse_ftu, ftu_text


@pytest.mark.parametrize('amount', [0,1,10**18,123456789012345678901,2**128-1,2**256-1])
def test_review_keeps_exact_native_units_including_single_wei(amount):
    assert parse_ftu(ftu_text(amount)) == amount


@pytest.mark.parametrize('value', ['1e3','NaN','Infinity','-1','1.0000000000000000001','1_000','0x10'])
def test_review_rejects_ambiguous_or_rounded_native_amounts(value):
    with pytest.raises(ValueError):
        parse_ftu(value)


def test_review_requires_positive_total_budget():
    with pytest.raises(ValueError):
        parse_ftu('0',positive=True)


@pytest.mark.parametrize('name,expected', [
    ('run_keygen_request','fresh'),('run_same_pk_refresh_request','refresh'),
    ('poll_dkg_for_key','resume'),('poll_same_pk_refresh_finalize','resume'),('start_pending_dkg_reconciler','resume')])
def test_explicit_version_one_dispatch_never_enters_the_context_free_legacy_writer(monkeypatch,name,expected):
    source=Path(__file__).parents[1]/'core/do_actions.py'
    tree=ast.parse(source.read_text())
    function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==name)
    calls=[]
    monkeypatch.setitem(sys.modules,'core.do_dkg_ui',NS(start=lambda kind:calls.append(kind),start_reconciler=lambda:calls.append('resume')))
    scope={'C':NS(DKG_ATTEMPT_PROTOCOL=1),'__package__':'core'}
    # No legacy signer, chain helper, config or UI is supplied. Falling through
    # the version gate would fail instead of quietly exercising the old path.
    exec(compile(ast.Module(body=[function],type_ignores=[]),str(source),'exec'),scope)
    scope[name]()
    assert calls == [expected]


@pytest.mark.parametrize('name,args', [
    ('ensure_v2_policy_escrow', (b'file',)),
    ('expire_dkg_keygen_onchain', (b'file', 'file', 1)),
    ('settle_v2_refresh_onchain', (b'file', 'file', 1, 2)),
    ('reconcile_pending_v2_dkg', (b'file', 'file', 'owner', 3, 5)),
    ('reconcile_known_v2_dkg_requests', ()),
])
def test_direct_legacy_financial_helpers_cannot_bypass_the_recovery_budget(name,args):
    source=Path(__file__).parents[1]/'core/do_chain.py'
    tree=ast.parse(source.read_text())
    nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and
        node.name in (name,'_require_legacy_dkg_writer')]
    scope={'C':NS(DKG_ATTEMPT_PROTOCOL=1)}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),scope)
    with pytest.raises(RuntimeError,match='approved recovery journal'):
        scope[name](*args)


@pytest.mark.parametrize('exists', [False, True])
def test_auto_upload_requests_review_before_creating_policy_or_funding_services(exists):
    source=Path(__file__).parents[1]/'core/do_actions.py'
    tree=ast.parse(source.read_text())
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_auto_prepare_for_upload')
    events=[]
    scope={'C':NS(DKG_ATTEMPT_PROTOCOL=1), 'S':NS(),
        'L':NS(set_status=lambda *_:None,log=lambda *_:None),
        'N':NS(set_auto_defaults=lambda **_:None,
            select_existing_policy_guardians=lambda *_:None,
            select_best_guardians=lambda **_:['guardian']*5),
        '_auto_profile_from_settings':lambda:dict(service_days=30,guardian_n=5,guardian_t=3,vk_n=5,vk_t=3),
        '_current_policy_tuple':lambda _:(exists,True,'owner',3,['guardian']*5),
        '_policy_has_local_or_finalized_key':lambda *_:False,
        'run_keygen_request':lambda:events.append('review')}
    # No old policy writer, escrow sender or service-period helper is supplied.
    # Falling through the preamble would fail rather than hiding a debit.
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),scope)
    assert scope[node.name](b'file','file','policy') is False
    assert events==['review']
    assert scope['S'].auto_upload_pending is True


@pytest.mark.parametrize('protocol', [0, 1])
def test_auto_selection_wait_never_starts_policy_or_funding(protocol):
    source = Path(__file__).parents[1] / 'core/do_actions.py'
    node = next(n for n in ast.parse(source.read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == '_auto_prepare_for_upload')
    class Pending(RuntimeError):
        pass
    def select(**kwargs):
        raise Pending('Guardian records changed')
    waiting = []
    scope = dict(C=NS(DKG_ATTEMPT_PROTOCOL=protocol), S=NS(),
        L=NS(set_status=lambda *a: None, log=lambda *a: None),
        N=NS(set_auto_defaults=lambda **kw: None, select_best_guardians=select,
             GuardianSelectionPending=Pending),
        _auto_profile_from_settings=lambda: dict(service_days=30, guardian_n=5,
            guardian_t=3, vk_n=5, vk_t=3),
        _current_policy_tuple=lambda file: (False, False, 'owner', 3, []),
        _guardian_selection_waiting=lambda exc: waiting.append(str(exc)))
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), scope)
    assert scope[node.name](b'file', 'file', 'policy') is False
    assert waiting == ['Guardian records changed']
