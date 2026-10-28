# Hosted Linux capability inventory

A bounded read-only probe of CPU/memory/storage constraints, installed virtual-machine tools, firmware candidates and the KVM API version. It does not install packages, download images, create a VM, change device permissions, or certify a guest OS.

The optional privileged step issues only `KVM_GET_API_VERSION` through a read-only descriptor. JSON omits account identities, raw environment values, paths and exception text. Exit zero means that the inventory completed; inspect each availability field. A successful API version query is not proof of VM creation or guest execution.
