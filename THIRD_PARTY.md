# Sources and third-party components

PhiUSIIL Phishing URL (Website) dataset: Arvind Prasad and Shalini Chandra (2024), UCI Machine Learning Repository, https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+website+dataset. Dataset DOI: https://doi.org/10.1016/j.cose.2023.103545. Published labels are 0 for phishing and 1 for legitimate. The dataset is CC BY 4.0: https://creativecommons.org/licenses/by/4.0/. The separate frozen input release includes the unmodified source CSV and this project's split/audit artifacts; label provenance is retained.

Primary documentation used for setup and implementation:

- QEMU Windows download route and upstream license: https://www.qemu.org/download/ and https://www.qemu.org/docs/master/about/license.html. The Windows package is downloaded from https://qemu.weilnetz.de/w64/; its included license files remain with the extracted runtime. No QEMU binary is committed here.
- Ubuntu cloud images and checksum files: https://cloud-images.ubuntu.com/noble/20261017/. Ubuntu packages retain their individual licenses. Installed package inventories are saved in the new VM.
- cloud-init NoCloud seed format: https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html.
- Playwright network events: https://playwright.dev/python/docs/network; browser isolation: https://playwright.dev/python/docs/browser-contexts. Python packages and Chromium keep their upstream licenses; no browser binary is committed here.
- Windows Hypervisor Platform: https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform and OpenSSH Client: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse.
- 7-Zip downloads and licensing: https://www.7-zip.org/download.html and https://www.7-zip.org/license.txt. Setup downloads and extracts helpers without installing them system-wide.
- pycdlib ISO-generation library: https://github.com/clalancette/pycdlib.

Making the academic source repository public does not add a new open-source license to the project code. Upstream software and the UCI dataset remain governed by their own licenses; the dataset remains CC BY 4.0.
