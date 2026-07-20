import sys
import os
import glob

# Add common virtual environment site-packages to sys.path so tests can be run
# globally without activating the venv explicitly (e.g. by automated test scripts)
base_dir = os.path.dirname(os.path.dirname(__file__))
for venv_name in ['.venv', 'venv', '.venv-audit']:
    venv_path = os.path.join(base_dir, venv_name)
    if os.path.exists(venv_path):
        site_packages = glob.glob(os.path.join(venv_path, 'lib', 'python*', 'site-packages'))
        if site_packages:
            sys.path.insert(0, site_packages[0])
            break
