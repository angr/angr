try:
    from slacrs import Slacrs
    from slacrs.model import Commander as CommanderLog
except ImportError as ex:
    print(str(ex))
    Slacrs = None  # type: Optional[type]
    CommanderLog = None  # type: Optional[type]
from . import ExplorationTechnique


class Commander(ExplorationTechnique):
    def __init__(self):
        self._commander_data = {}
        self._session =  Slacrs().session()
        super().__init__()

    def step(self, simgr, stash='active', **kwargs):

        if 'stashes' in self._commander_data:
            stashes = self._commander_data['stashes']
        else:
            stashes = {}
        stashes[stash] = len(simgr.stashes[stash])

        self._commander_data['stashes'] = stashes

        if Slacrs:
            commander = CommanderLog()
            commander.stashes = self._commander_data['stashes']['active']
            self._session.add(commander)
            self._session.commit()
            self._session.close()
            print("here")

        simgr = simgr.step(stash="active", **kwargs)
        return simgr
