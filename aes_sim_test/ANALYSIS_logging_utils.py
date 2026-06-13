from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
import time


@contextmanager
def log_output(log_path, mode="w"):
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open(mode) as log_file:
        with redirect_stdout(log_file), redirect_stderr(log_file):
            yield log_path


def run_with_log(log_path, func, *args, **kwargs):
    start = time.time()
    with log_output(log_path):
        result = func(*args, **kwargs)
    elapsed = time.time() - start
    print(f"Saved log to {Path(log_path)} ({elapsed:.1f}s)")
    return result
