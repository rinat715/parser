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

#### Сборка линуксов 
```
pyenv activate parser
maturin build -r -m parser/Cargo.toml
```

#### сборка windows 64
```bash
pyenv activate parser
export PYO3_CROSS_LIB_DIR='/mnt/c/Users/rshaykhetdinov/AppData/Local/Programs/Python/Python36/libs'
maturin build -r -m parser/Cargo.toml --target x86_64-pc-windows-gnu
```
#### сборка windows 32

```bash
pyenv activate parser
export PYO3_CROSS_LIB_DIR='/mnt/c/Users/rshaykhetdinov/AppData/Local/Programs/Python/Python36-32/libs'
maturin build  -m parser/Cargo.toml --target i686-pc-windows-gnu
```

  -- PYO3_PRINT_CONFIG=1 is set, printing configuration and halting compile --
  implementation=CPython
  version=3.6
  shared=true
  abi3=true
  lib_name=python3
  lib_dir=/mnt/c/Users/rshaykhetdinov/AppData/Local/Programs/Python/Python36-32/libs
  build_flags=WITH_THREAD
  suppress_build_script_link_lines=false



### outdated 


extension-module по умолчанию выключен

https://pyo3.rs/v0.23.5/faq.html#i-cant-run-cargo-test-or-i-cant-build-in-a-cargo-workspace-im-having-linker-issues-like-symbol-not-found-or-undefined-reference-to-_pyexc_systemerror

если запустить cargo test без этого модуля 
`note: rust-lld: error: unable to find library -lpython3.12`

#### тесты 
```
cargo test --features "extension-module"
```

#### тесты с python
```
pyenv activate parser
export LD_LIBRARY_PATH=/home/archman/.pyenv/versions/3.6.15/lib/ 
cargo test --config 'build.rustflags=["--cfg", "python_required"]'
```

#### сборка 

```
pyenv activate parser
maturin develop -m parser/Cargo.toml --cargo-extra-args="--features "extension-module""
```

