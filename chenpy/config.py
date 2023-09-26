import os

from appdirs import user_data_dir

chen_home = os.getenv("CHEN_HOME", user_data_dir("chen"))
if not os.path.exists(chen_home):
    os.makedirs(chen_home)

# chen oras distribution url
chen_distribution_url = "ghcr.io/appthreat/chen-platform:v1"
