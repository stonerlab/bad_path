Usage Guide
===========

Basic Usage
-----------

The ``bad_path`` package provides several functions for checking if a file path
points to a system-sensitive location. It also provides a ``PathChecker`` class
for a more object-oriented approach with additional details.

Checking for Dangerous Paths
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The simplest way to check if a path is dangerous:

.. code-block:: python

   from bad_path import is_dangerous_path

   # Returns True if the path is dangerous, False otherwise
   if is_dangerous_path("/etc/passwd"):
       print("This is a dangerous path!")

Using the PathChecker Class
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``PathChecker`` class provides a more detailed interface that distinguishes
between platform-specific system paths and user-defined sensitive paths:

.. code-block:: python

   from bad_path import PathChecker

   # Create a checker for a path
   checker = PathChecker("/etc/passwd")

   # Use it in boolean context
   if checker:
       print("This is a dangerous path!")
       print(f"Is system path: {checker.is_system_path}")
       print(f"Is user-defined sensitive: {checker.is_sensitive_path}")

   # Access the original path
   print(f"Checked path: {checker.path}")

The ``PathChecker`` class evaluates to ``True`` when used in boolean context
if the path is dangerous (either a system path or user-defined), and ``False``
otherwise. The ``is_system_path`` property checks against platform-specific
dangerous paths (like ``/etc``, ``/bin`` on Linux, or ``C:\\Windows`` on Windows),
while ``is_sensitive_path`` checks against user-defined paths added via
``add_user_path()``.

Raising Exceptions
~~~~~~~~~~~~~~~~~~

You can also have the function raise an exception instead of returning a boolean:

.. code-block:: python

   from bad_path import is_dangerous_path, DangerousPathError

   try:
       is_dangerous_path("/etc/passwd", raise_error=True)
   except DangerousPathError as e:
       print(f"Error: {e}")

Using Path Objects
~~~~~~~~~~~~~~~~~~

The package works with both strings and ``pathlib.Path`` objects:

.. code-block:: python

   from pathlib import Path
   from bad_path import is_dangerous_path

   path = Path("/etc/passwd")
   if is_dangerous_path(path):
       print("Dangerous!")

Getting Dangerous Paths for Current OS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To see which paths are considered dangerous on the current platform:

.. code-block:: python

   from bad_path import get_dangerous_paths

   dangerous = get_dangerous_paths()
   for path in dangerous:
       print(f"Dangerous path: {path}")

Platform-Specific Behavior
---------------------------

The package automatically detects the current operating system and uses
appropriate dangerous path lists:

* **Windows**: System directories like ``C:\\Windows``, ``C:\\Program Files``
* **macOS**: System directories like ``/System``, ``/Library``
* **Linux**: System directories like ``/etc``, ``/bin``, ``/usr``

Examples
--------

Using PathChecker for Detailed Feedback
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from bad_path import PathChecker

   def validate_path(path):
       """Validate a path and provide detailed feedback."""
       checker = PathChecker(path)
       
       if checker:
           reasons = []
           if checker.is_system_path:
               reasons.append("it's a platform-specific system path")
           if checker.is_sensitive_path:
               reasons.append("it's a user-defined sensitive location")
           print(f"❌ Cannot use {path} because {' and '.join(reasons)}")
           return False
       
       print(f"✅ Path {path} is safe to use")
       return True

Validating User Input
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from bad_path import is_dangerous_path, DangerousPathError

   def save_file(filepath, content):
       """Save content to a file, but only if it's not in a dangerous location."""
       try:
           is_dangerous_path(filepath, raise_error=True)
       except DangerousPathError:
           raise ValueError("Cannot write to system directories!")
       
       with open(filepath, 'w') as f:
           f.write(content)

Filtering File Lists
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from bad_path import is_system_path
   import os

   def get_safe_files(directory):
       """Get all files in a directory that are not in system locations."""
       safe_files = []
       for root, dirs, files in os.walk(directory):
           for file in files:
               filepath = os.path.join(root, file)
               if not is_system_path(filepath):
                   safe_files.append(filepath)
       return safe_files
