Installation
============

Requirements
------------

* Python 3.10 or higher
* No external dependencies required for core functionality

Installing from PyPI
--------------------

To install the latest stable version from PyPI:

.. code-block:: bash

   pip install bad_path

Installing from Conda
---------------------

To install using conda/mamba:

.. code-block:: bash

   conda install -c phygbu bad_path

Or with mamba:

.. code-block:: bash

   mamba install -c phygbu bad_path

Installing from Source
----------------------

To install the latest development version from GitHub:

.. code-block:: bash

   git clone https://github.com/stonerlab/bad_path.git
   cd bad_path
   pip install -e .

Development Installation
------------------------

For development, install with the optional development dependencies:

.. code-block:: bash

   pip install -e ".[dev]"

This includes:

* pytest for testing
* pytest-cov for coverage reports
* sphinx for documentation
* ruff for linting
