"""
Tests for subinterpreter support (PEP 684 / PEP 489 / PEP 689).
"""

import os
import unittest


# ── helpers ─────────────────────────────────────────────────────────────

def _get_interp_module():
    """Return the available subinterpreter module, or None."""
    for name in ('_interpreters', '_xxsubinterpreters'):
        try:
            mod = __import__(name)
            if hasattr(mod, 'create'):
                return mod
        except ImportError:
            continue
    return None


_interp_mod = _get_interp_module()

requires_interpreters = unittest.skipUnless(
    _interp_mod is not None,
    "subinterpreter API not available in this Python build",
)


def _subinterp_code(code):
    """Wrap code with preamble so xxtea can be imported in a subinterpreter."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    return 'import sys; sys.path.insert(0, %r); ' % str(root) + code


# ── test base class ─────────────────────────────────────────────────────

@requires_interpreters
class _SubinterpreterTestCase(unittest.TestCase):
    """Creates/destroys a subinterpreter per test.  Call self._run(code)
    to execute Python code in it with the path preamble."""

    def setUp(self):
        self.iid = _interp_mod.create()

    def tearDown(self):
        _interp_mod.destroy(self.iid)

    def _run(self, code):
        _interp_mod.run_string(self.iid, _subinterp_code(code))

    def _run_in(self, iid, code):
        _interp_mod.run_string(iid, _subinterp_code(code))


# ── basic functionality ─────────────────────────────────────────────────

class TestSubinterpreterBasic(_SubinterpreterTestCase):

    def test_encrypt_decrypt(self):
        self._run("""\
import xxtea
d = b'Hello from a subinterpreter!'
k = b'0123456789abcdef'
assert xxtea.decrypt(xxtea.encrypt(d, k), k) == d
""")

    def test_encrypt_hex_decrypt_hex(self):
        self._run("""\
import xxtea
d = b'Subinterpreter hex test'
k = b'0123456789abcdef'
assert xxtea.decrypt_hex(xxtea.encrypt_hex(d, k), k) == d
""")

    def test_xxtea_object(self):
        self._run("""\
import xxtea
c = xxtea.XXTEA(b'0123456789abcdef')
d = b'Cipher object test!'
assert c.decrypt(c.encrypt(d)) == d
assert c.decrypt_hex(c.encrypt_hex(d)) == d
""")

    def test_version_exists(self):
        self._run("""\
import xxtea
assert isinstance(xxtea.VERSION, str)
""")

    def test_random_data(self):
        self._run("""\
import os, xxtea
for i in range(128):
    k = os.urandom(16)
    d = os.urandom(i)
    assert xxtea.decrypt(xxtea.encrypt(d, k), k) == d
""")


# ── isolation ───────────────────────────────────────────────────────────

class TestSubinterpreterIsolation(_SubinterpreterTestCase):

    def test_immutable_type(self):
        """XXTEA type is immutable inside subinterpreters (3.12+)."""
        self._run("""\
import sys, xxtea
if sys.version_info >= (3, 12):
    try:
        xxtea.XXTEA.newattr = 42
        raise AssertionError('type should be immutable')
    except TypeError:
        pass
    assert xxtea.XXTEA.__flags__ & (1 << 8), 'immutable flag not set'
""")

    def test_module_dict_not_shared(self):
        """Modifying a module attribute in one interpreter is invisible
        in another."""
        id_a = _interp_mod.create()
        id_b = _interp_mod.create()
        self._run_in(id_a, "import xxtea; xxtea._m = 'a'")
        self._run_in(id_b, "import xxtea; assert not hasattr(xxtea, '_m')")
        _interp_mod.destroy(id_a)
        _interp_mod.destroy(id_b)

    def test_independent_ciphers(self):
        """Two interpreters each create their own XXTEA object."""
        key_a = os.urandom(16)
        key_b = os.urandom(16)

        id_a = _interp_mod.create()
        id_b = _interp_mod.create()

        self._run_in(id_a, "import xxtea; c = xxtea.XXTEA(%r)" % key_a)
        self._run_in(id_b, "import xxtea; c = xxtea.XXTEA(%r)" % key_b)

        _interp_mod.destroy(id_a)
        _interp_mod.destroy(id_b)

    def test_noopadding(self):
        self._run("""\
import xxtea
k = b'0123456789abcdef'
for size in (8, 12, 16, 20, 32):
    d = bytes(range(size))
    enc = xxtea.encrypt(d, k, padding=False)
    assert xxtea.decrypt(enc, k, padding=False) == d
""")

    def test_custom_rounds(self):
        self._run("""\
import xxtea
k = b'0123456789abcdef'
d = b'Hello, world!'
for r in (0, 1, 8, 32, 64, 128):
    assert xxtea.decrypt(xxtea.encrypt(d, k, rounds=r), k, rounds=r) == d
""")


# ── many interpreters ───────────────────────────────────────────────────

class TestManyInterpreters(_SubinterpreterTestCase):

    def test_encrypt_decrypt_in_eight(self):
        ids = [_interp_mod.create() for _ in range(8)]
        for iid in ids:
            self._run_in(iid, """\
import os, xxtea
k = b'0123456789abcdef'
for _ in range(16):
    d = os.urandom(64)
    assert xxtea.decrypt(xxtea.encrypt(d, k), k) == d
""")
        for iid in ids:
            _interp_mod.destroy(iid)

    def test_xxtea_object_in_four(self):
        ids = [_interp_mod.create() for _ in range(4)]
        for iid in ids:
            self._run_in(iid, """\
import os, xxtea
c = xxtea.XXTEA(os.urandom(16))
for _ in range(16):
    d = os.urandom(64)
    assert c.decrypt(c.encrypt(d)) == d
    assert c.decrypt_hex(c.encrypt_hex(d)) == d
""")
        for iid in ids:
            _interp_mod.destroy(iid)


# ── errors ──────────────────────────────────────────────────────────────

class TestSubinterpreterErrors(_SubinterpreterTestCase):

    def test_short_key(self):
        self._run("""\
import xxtea
try:
    xxtea.encrypt(b'data', b'short')
    raise AssertionError('expected ValueError')
except ValueError:
    pass
""")

    def test_wrong_key_decrypt(self):
        self._run("""\
import xxtea
enc = xxtea.encrypt(b'Hello World!', b'0123456789abcdef')
try:
    xxtea.decrypt(enc, b'abcdef0123456789')
    raise AssertionError('expected ValueError')
except ValueError:
    pass
""")


# ── teardown ────────────────────────────────────────────────────────────

class TestSubinterpreterTeardown(_SubinterpreterTestCase):

    def test_destroy_after_use(self):
        iid = _interp_mod.create()
        _interp_mod.run_string(iid, _subinterp_code(
            "import xxtea; xxtea.XXTEA(b'0123456789abcdef').encrypt(b'x')"))
        _interp_mod.destroy(iid)

    def test_rapid_create_destroy(self):
        for _ in range(4):
            iid = _interp_mod.create()
            _interp_mod.run_string(iid, _subinterp_code("""\
import xxtea
k = b'0123456789abcdef'
for i in range(8):
    xxtea.decrypt(xxtea.encrypt(bytes([i] * 16), k), k)
"""))
            _interp_mod.destroy(iid)


# ── concurrent.interpreters (Python 3.14+) ──────────────────────────────

def _has_concurrent_interpreters():
    try:
        import concurrent.interpreters
        return True
    except ImportError:
        return False


requires_concurrent = unittest.skipUnless(
    _has_concurrent_interpreters(),
    "concurrent.interpreters not available (requires Python 3.14+)",
)


@requires_concurrent
class TestConcurrentInterpreters(unittest.TestCase):
    """Tests using concurrent.interpreters (Python 3.14+)."""

    @staticmethod
    def _preamble():
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent
        return 'import sys; sys.path.insert(0, %r); ' % str(root)

    def test_exec_encrypt_decrypt(self):
        import concurrent.interpreters as ci
        interp = ci.create()
        interp.exec(self._preamble() + """\
import xxtea
d = b'Hello from concurrent.interpreters!'
k = b'0123456789abcdef'
assert xxtea.decrypt(xxtea.encrypt(d, k), k) == d
""")
        interp.close()

    def test_exec_xxtea_object(self):
        import concurrent.interpreters as ci
        interp = ci.create()
        interp.exec(self._preamble() + """\
import xxtea
c = xxtea.XXTEA(b'0123456789abcdef')
d = b'concurrent cipher test'
assert c.decrypt(c.encrypt(d)) == d
assert c.decrypt_hex(c.encrypt_hex(d)) == d
""")
        interp.close()

    def test_queue_cross_interpreter(self):
        """Encrypt in interpreter A, pass ciphertext via Queue,
        decrypt in interpreter B — true cross-interpreter round-trip."""
        import concurrent.interpreters as ci

        q = ci.create_queue()
        pre = self._preamble()

        a = ci.create()
        b = ci.create()
        a.prepare_main({'q': q})
        b.prepare_main({'q': q})

        # Interpreter A: encrypt and put on queue
        a.exec(pre + '''\
import xxtea
enc = xxtea.encrypt(b"cross-interpreter!", b"0123456789abcdef")
q.put(enc)
''')

        # Interpreter B: read from queue and decrypt
        b.exec(pre + '''\
import xxtea
enc = q.get()
dec = xxtea.decrypt(enc, b"0123456789abcdef")
assert dec == b"cross-interpreter!", f"mismatch: {dec!r}"
''')

        a.close()
        b.close()

    def test_immutable_type(self):
        import concurrent.interpreters as ci
        interp = ci.create()
        interp.exec(self._preamble() + """\
import sys, xxtea
assert xxtea.XXTEA.__flags__ & (1 << 8), 'immutable flag not set'
try:
    xxtea.XXTEA.newattr = 42
    raise AssertionError('type should be immutable')
except TypeError:
    pass
""")
        interp.close()

    def test_close_after_use(self):
        """Verify interpreter can be closed cleanly after using xxtea."""
        import concurrent.interpreters as ci
        for _ in range(8):
            interp = ci.create()
            interp.exec(self._preamble() + """\
import xxtea
k = b'0123456789abcdef'
for i in range(8):
    xxtea.decrypt(xxtea.encrypt(bytes([i] * 16), k), k)
""")
            interp.close()


if __name__ == '__main__':
    unittest.main()
