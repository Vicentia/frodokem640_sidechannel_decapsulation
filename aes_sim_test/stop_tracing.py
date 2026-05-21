class StopEmulation(Exception):
    pass


class SnapshotReady(Exception):
    pass


def hard_stop(ql):
    try:
        ql.uc.emu_stop()
    except Exception:
        pass

    try:
        ql.emu_stop()
    except Exception:
        pass
