Nucleus for Python
==================

Nucleus function detector bindings for Python 2.x and 3.x.


## Installation

At the moment no PIP package is available, and you need to manually build and install this package via:

```python
python setup.py install
```


## Usage

There's no documentation available for either Nucleus or the Python API that these bindings provide.
However the Nucleus headers are self-explanatory, and they have been directly mapped 1:1 into Python.
Take the following snippet as an example:

```python
import nucleus

context = nucleus.load('data.bin', binary_base=0x10000)
for function in context.cfg.functions:
    print("Function detected at 0x%X" % function.start)
```

Note that due Nucleus design (specifically, relying on a global `options` object),
multithreaded processing of binaries in not recommended.