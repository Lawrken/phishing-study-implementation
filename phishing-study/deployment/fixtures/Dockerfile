# Owned firewall fixtures only. This image is not a live collection deployment.
FROM phishing-study-fixtures:0.1.1
RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables iproute2 shellcheck \
    && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir 'setuptools>=68' wheel
WORKDIR /workspace
