"""Local records for an explicitly selected deployment; no network access."""
from pathlib import Path
import re


def storage_root(base,config):
    if getattr(config,'DKG_ATTEMPT_PROTOCOL',0)!=1:
        return Path(base)
    settings=config.DKG_RECOVERY
    chain_id=settings.get('chain_id',getattr(config,'CHAIN_ID',None))
    coordinator=str(config.ZKDKG_COORDINATOR_V2_ADDRESS).lower()
    if type(chain_id) is not int or chain_id<=0 or not re.fullmatch(r'0x[0-9a-f]{40}',coordinator) or int(coordinator,16)==0:
        raise ValueError('Recovery records need their approved chain ID and coordinator')
    return Path(base)/'networks'/str(chain_id)/coordinator
