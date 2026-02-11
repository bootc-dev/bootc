
> **Note**
> Do you want to add yourself to this list? Simply fork the repository and open a PR with the required change.
> We have a short description of the adopter types at the bottom of this page. Each type is in alphabetical order. 

# bootc Adopters (direct)

| Type | Name | Since | Website | Use-Case |
|:-|:-|:-|:-|:-|
Vendor | Red Hat | 2024 | https://redhat.com | Image Based Linux 
Vendor | HeliumOS | 2024 | https://www.heliumos.org/ | An atomic desktop operating system for your devices
Vendor | AlmaLinux (Atomic SIG) | 2025 | [atomic-desktop](https://github.com/AlmaLinux/atomic-desktop), [atomic-workstation](https://github.com/AlmaLinux/atomic-workstation) | Atomic AlmaLinux desktop respins
Vendor | CIQ (Rocky Linux | 2026 | https://ciq.com/blog/rocky-linux-from-ciq-bootable-container-images-bootc/ | Bootable container images

# bootc Adopters (indirect, via ostree)

Bootc is a relatively new project, but much of the underlying technology and goals is *not* new.
The underlying ostree project is over 13 years old (as of 2024). This project also relates
to [rpm-ostree](https://github.com/coreos/rpm-ostree/) which has existed a really long time.

Not every one of these projects uses bootc directly today, but a toplevel goal of bootc
is to be the successor to ostree, and it is our aim to seamlessly carry forward these users.

| Type | Name | Since | Website | Use-Case |
|:-|:-|:-|:-|:-|
| Vendor | Endless | 2014 | [link](https://www.endlessos.org/os) | A Completely Free, User-Friendly Operating System Packed with Educational Tools, Games, and More
| Vendor | Red Hat | 2015 | [link](https://redhat.com) | Image Based Linux
| Vendor | Apertis | 2020 | [link](https://apertis.org) | Collaborative OS platform for products
| Vendor | Fedora Project | 2021 | [link](https://fedoraproject.org/atomic-desktops/) | An atomic desktop operating system aimed at good support for container-focused workflows
| Vendor | Playtron GameOS | 2022 | [link](https://www.playtron.one/) | A video game console OS that has integration with the top PC game stores |
| Vendor | Universal Blue   | 2022 | [link](https://universal-blue.org/) | The reliability of a Chromebook, but with the flexibility and power of a traditional Linux desktop
| Vendor | Fyra Labs | 2024 | [link](https://fyralabs.com) | Bootc powers an experimental variant of Ultramarine Linux

### Adopter Types

**End-user**: The organization runs bootc in production in some way.

**Integration**: The organization has a product that integrates with bootc, but does not contain bootc.

**Vendor**: The organization packages bootc in their product and sells it as part of their product.

