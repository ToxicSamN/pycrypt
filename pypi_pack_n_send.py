
import os
import sys
import platform
import subprocess
import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

print(os.getcwd())
if not platform.platform().lower().find('windiows') == -1:
    venv_cmd = os.path.join(os.getcwd(), "venv\\Scripts\\activate")
elif not platform.platform().lower().find('linux') == -1 or not platform.platform().lower().find('macos') == -1:
    venv_cmd = "source {}".format(os.path.join(os.getcwd(), "venv/bin/activate"))
p = subprocess.Popen('{} && {} && python setup.py sdist bdist_wheel'.format(venv_cmd, "pip list"), shell=True, stderr=sys.stdout, stdout=sys.stdout)
p.wait()
p = subprocess.Popen('twine upload --skip-existing dist/*', shell=True, stderr=sys.stdout, stdout=sys.stdout)
p.wait()
