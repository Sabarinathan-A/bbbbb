"""Legacy setup shim.

The authoritative project metadata lives in ``pyproject.toml``. This shim only
exists so that an editable install can use setuptools' legacy ``setup.py
develop`` path (``pip install --no-use-pep517 -e .``). That path is required in
this offline sandbox because the modern PEP 517/660 build needs the ``wheel``
package (for ``bdist_wheel``), which cannot be installed from the blocked PyPI.
"""

from setuptools import setup

setup()
