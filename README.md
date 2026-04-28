maturin 0.12.20
pip install maturin==0.12.20
pyo3 0.15.2

```python
from parser_rust import get, Context

c = Context([], [])
get("-A INPUT -g TEST --ctstate RELATED,ESTABLISHED", c)

get("-A INPUT -j DROP -i swp+ -o swp1", Context([], ["swp1", "swp2"]))

```


```
>> get("", c)

thread '<unnamed>' (243342) panicked at src/lib.rs:36:77:
called `Result::unwrap()` on an `Err` value: Error(Error { input: "", code: Many1 })
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
pyo3_runtime.PanicException: called `Result::unwrap()` on an `Err` value: Error(Error { input: "", code: Many1 })
```

`maturin develop -m parser/Cargo.toml --cargo-extra-args="--features "extension-module""`
https://pyo3.rs/v0.23.5/faq.html#i-cant-run-cargo-test-or-i-cant-build-in-a-cargo-workspace-im-having-linker-issues-like-symbol-not-found-or-undefined-reference-to-_pyexc_systemerror