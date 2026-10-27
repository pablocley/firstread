"""Start Mica's own server (akivet/Mica, `mica.server`) with a CPU thread count.

Usage: python3 -I mica_serve.py <mica_src_dir> <threads> [mica.server arguments...]

Mica's server does not pass a thread count to llama.cpp, so on a CPU it runs on llama.cpp's default of
4 threads (GGML_DEFAULT_N_THREADS). Its backend takes `n_threads`; this sets it and starts the server
unchanged otherwise. Run it in Mica's own environment (transformers 5.5.0, its requirements.txt).
"""
import sys

src, threads = sys.argv[1], int(sys.argv[2])
sys.argv = [sys.argv[0]] + sys.argv[3:]
sys.path.insert(0, src)
from mica import direct_backend  # noqa: E402

_init = direct_backend.DirectJudge.__init__


def init(self, *args, n_threads=None, **kwargs):
    _init(self, *args, n_threads=n_threads or threads, **kwargs)


direct_backend.DirectJudge.__init__ = init
from mica import server  # noqa: E402

server.main()
