#![allow(dead_code)]

//! Partition type GUIDs from the Discoverable Partitions Specification (DPS)
//!
//! This module contains constants for partition type GUIDs as defined by the
//! UAPI Group's Discoverable Partitions Specification.
//!
//! Reference: <https://uapi-group.org/specifications/specs/discoverable_partitions_specification/>
//!
//! # Overview
//!
//! The Discoverable Partitions Specification (DPS) defines standardized partition
//! type GUIDs that enable automatic discovery and mounting of partitions without
//! explicit configuration. This is a key enabler for bootc's installation process
//! and for modern systemd-based initramfs implementations.
//!
//! # How bootc uses DPS
//!
//! When `bootc install to-disk` creates partitions, it sets the appropriate DPS
//! partition type GUID based on the target CPU architecture. This enables several
//! important capabilities:
//!
//! ## Automatic root discovery
//!
//! With a DPS-aware bootloader and initramfs (containing `systemd-gpt-auto-generator`),
//! the root filesystem can be discovered and mounted automatically without requiring
//! a `root=` kernel argument. The initramfs:
//!
//! 1. Reads the EFI `LoaderDevicePartUUID` variable to identify the boot disk
//! 2. Scans the GPT for a partition with the architecture-specific root type GUID
//! 3. Mounts that partition as the root filesystem
//!
//! ## Architecture-specific partition types
//!
//! Each CPU architecture has its own root partition type GUID. This prevents
//! accidentally booting a system on incompatible hardware. bootc uses
//! [`this_arch_root`] to select the correct GUID at compile time.
//!
//! ## Composefs and sealed boot
//!
//! When using the composefs backend with UKIs (Unified Kernel Images), bootc can
//! omit the `root=` kernel argument entirely. This enables:
//!
//! - Measured boot: The kernel command line is part of the UKI signature
//! - Simplified image building: No machine-specific kernel arguments needed
//! - systemd-repart integration: Future support for declarative partition management
//!
//! # Partition types included
//!
//! This module defines constants for:
//!
//! - **Root partitions**: Architecture-specific root filesystem partitions
//! - **USR partitions**: Separate `/usr` partitions (included for spec completeness; not currently used by bootc)
//! - **Verity partitions**: dm-verity hash partitions for integrity verification
//! - **Verity signature partitions**: Signed verity root hashes
//! - **Special partitions**: ESP, XBOOTLDR, swap, home, var, etc.
//!
//! # Usage (internal)
//!
//! This is an internal module. Within bootc, it is used like:
//!
//! ```ignore
//! use crate::discoverable_partition_specification::{this_arch_root, ESP};
//!
//! // Get the root partition type GUID for the current architecture
//! let root_type: &str = this_arch_root();
//!
//! // ESP GUID is architecture-independent
//! let esp_type: &str = ESP;
//! ```

// ============================================================================
// ROOT PARTITIONS
// ============================================================================

/// Root partition for Alpha architecture
pub const ROOT_ALPHA: &str = "6523f8ae-3eb1-4e2a-a05a-18b695ae656f";

/// Root partition for ARC architecture
pub const ROOT_ARC: &str = "d27f46ed-2919-4cb8-bd25-9531f3c16534";

/// Root partition for 32-bit ARM architecture
pub const ROOT_ARM: &str = "69dad710-2ce4-4e3c-b16c-21a1d49abed3";

/// Root partition for 64-bit ARM/AArch64 architecture
pub const ROOT_ARM64: &str = "b921b045-1df0-41c3-af44-4c6f280d3fae";

/// Root partition for Itanium/IA-64 architecture
pub const ROOT_IA64: &str = "993d8d3d-f80e-4225-855a-9daf8ed7ea97";

/// Root partition for 64-bit LoongArch architecture
pub const ROOT_LOONGARCH64: &str = "77055800-792c-4f94-b39a-98c91b762bb6";

/// Root partition for 32-bit MIPS Little Endian
pub const ROOT_MIPS_LE: &str = "37c58c8a-d913-4156-a25f-48b1b64e07f0";

/// Root partition for 64-bit MIPS Little Endian
pub const ROOT_MIPS64_LE: &str = "700bda43-7a34-4507-b179-eeb93d7a7ca3";

/// Root partition for 32-bit MIPS Big Endian
pub const ROOT_MIPS: &str = "e9434544-6e2c-47cc-bae2-12d6deafb44c";

/// Root partition for 64-bit MIPS Big Endian
pub const ROOT_MIPS64: &str = "d113af76-80ef-41b4-bdb6-0cff4d3d4a25";

/// Root partition for PA-RISC/HPPA architecture
pub const ROOT_PARISC: &str = "1aacdb3b-5444-4138-bd9e-e5c2239b2346";

/// Root partition for 32-bit PowerPC
pub const ROOT_PPC: &str = "1de3f1ef-fa98-47b5-8dcd-4a860a654d78";

/// Root partition for 64-bit PowerPC Big Endian
pub const ROOT_PPC64: &str = "912ade1d-a839-4913-8964-a10eee08fbd2";

/// Root partition for 64-bit PowerPC Little Endian
pub const ROOT_PPC64_LE: &str = "c31c45e6-3f39-412e-80fb-4809c4980599";

/// Root partition for 32-bit RISC-V
pub const ROOT_RISCV32: &str = "60d5a7fe-8e7d-435c-b714-3dd8162144e1";

/// Root partition for 64-bit RISC-V
pub const ROOT_RISCV64: &str = "72ec70a6-cf74-40e6-bd49-4bda08e8f224";

/// Root partition for s390 architecture
pub const ROOT_S390: &str = "08a7acea-624c-4a20-91e8-6e0fa67d23f9";

/// Root partition for s390x architecture
pub const ROOT_S390X: &str = "5eead9a9-fe09-4a1e-a1d7-520d00531306";

/// Root partition for TILE-Gx architecture
pub const ROOT_TILEGX: &str = "c50cdd70-3862-4cc3-90e1-809a8c93ee2c";

/// Root partition for 32-bit x86
pub const ROOT_X86: &str = "44479540-f297-41b2-9af7-d131d5f0458a";

/// Root partition for 64-bit x86/AMD64
pub const ROOT_X86_64: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";

// ============================================================================
// USR PARTITIONS
// ============================================================================

/// /usr partition for Alpha architecture
pub const USR_ALPHA: &str = "e18cf08c-33ec-4c0d-8246-c6c6fb3da024";

/// /usr partition for ARC architecture
pub const USR_ARC: &str = "7978a683-6316-4922-bbee-38bff5a2fecc";

/// /usr partition for 32-bit ARM
pub const USR_ARM: &str = "7d0359a3-02b3-4f0a-865c-654403e70625";

/// /usr partition for 64-bit ARM/AArch64
pub const USR_ARM64: &str = "b0e01050-ee5f-4390-949a-9101b17104e9";

/// /usr partition for Itanium/IA-64
pub const USR_IA64: &str = "4301d2a6-4e3b-4b2a-bb94-9e0b2c4225ea";

/// /usr partition for 64-bit LoongArch
pub const USR_LOONGARCH64: &str = "e611c702-575c-4cbe-9a46-434fa0bf7e3f";

/// /usr partition for 32-bit MIPS Big Endian
pub const USR_MIPS: &str = "773b2abc-2a99-4398-8bf5-03baac40d02b";

/// /usr partition for 64-bit MIPS Big Endian
pub const USR_MIPS64: &str = "57e13958-7331-4365-8e6e-35eeee17c61b";

/// /usr partition for 32-bit MIPS Little Endian
pub const USR_MIPS_LE: &str = "0f4868e9-9952-4706-979f-3ed3a473e947";

/// /usr partition for 64-bit MIPS Little Endian
pub const USR_MIPS64_LE: &str = "c97c1f32-ba06-40b4-9f22-236061b08aa8";

/// /usr partition for PA-RISC
pub const USR_PARISC: &str = "dc4a4480-6917-4262-a4ec-db9384949f25";

/// /usr partition for 32-bit PowerPC
pub const USR_PPC: &str = "7d14fec5-cc71-415d-9d6c-06bf0b3c3eaf";

/// /usr partition for 64-bit PowerPC Big Endian
pub const USR_PPC64: &str = "2c9739e2-f068-46b3-9fd0-01c5a9afbcca";

/// /usr partition for 64-bit PowerPC Little Endian
pub const USR_PPC64_LE: &str = "15bb03af-77e7-4d4a-b12b-c0d084f7491c";

/// /usr partition for 32-bit RISC-V
pub const USR_RISCV32: &str = "b933fb22-5c3f-4f91-af90-e2bb0fa50702";

/// /usr partition for 64-bit RISC-V
pub const USR_RISCV64: &str = "beaec34b-8442-439b-a40b-984381ed097d";

/// /usr partition for s390
pub const USR_S390: &str = "cd0f869b-d0fb-4ca0-b141-9ea87cc78d66";

/// /usr partition for s390x
pub const USR_S390X: &str = "8a4f5770-50aa-4ed3-874a-99b710db6fea";

/// /usr partition for TILE-Gx
pub const USR_TILEGX: &str = "55497029-c7c1-44cc-aa39-815ed1558630";

/// /usr partition for 32-bit x86
pub const USR_X86: &str = "75250d76-8cc6-458e-bd66-bd47cc81a812";

/// /usr partition for 64-bit x86/AMD64
pub const USR_X86_64: &str = "8484680c-9521-48c6-9c11-b0720656f69e";

// ============================================================================
// ROOT VERITY PARTITIONS
// ============================================================================

/// Root verity partition for Alpha
pub const ROOT_VERITY_ALPHA: &str = "fc56d9e9-e6e5-4c06-be32-e74407ce09a5";

/// Root verity partition for ARC
pub const ROOT_VERITY_ARC: &str = "24b2d975-0f97-4521-afa1-cd531e421b8d";

/// Root verity partition for 32-bit ARM
pub const ROOT_VERITY_ARM: &str = "7386cdf2-203c-47a9-a498-f2ecce45a2d6";

/// Root verity partition for 64-bit ARM/AArch64
pub const ROOT_VERITY_ARM64: &str = "df3300ce-d69f-4c92-978c-9bfb0f38d820";

/// Root verity partition for Itanium/IA-64
pub const ROOT_VERITY_IA64: &str = "86ed10d5-b607-45bb-8957-d350f23d0571";

/// Root verity partition for 64-bit LoongArch
pub const ROOT_VERITY_LOONGARCH64: &str = "f3393b22-e9af-4613-a948-9d3bfbd0c535";

/// Root verity partition for 32-bit MIPS Big Endian
pub const ROOT_VERITY_MIPS: &str = "7a430799-f711-4c7e-8e5b-1d685bd48607";

/// Root verity partition for 64-bit MIPS Big Endian
pub const ROOT_VERITY_MIPS64: &str = "579536f8-6a33-4055-a95a-df2d5e2c42a8";

/// Root verity partition for 32-bit MIPS Little Endian
pub const ROOT_VERITY_MIPS_LE: &str = "d7d150d2-2a04-4a33-8f12-16651205ff7b";

/// Root verity partition for 64-bit MIPS Little Endian
pub const ROOT_VERITY_MIPS64_LE: &str = "16b417f8-3e06-4f57-8dd2-9b5232f41aa6";

/// Root verity partition for PA-RISC
pub const ROOT_VERITY_PARISC: &str = "d212a430-fbc5-49f9-a983-a7feef2b8d0e";

/// Root verity partition for 32-bit PowerPC
pub const ROOT_VERITY_PPC: &str = "98cfe649-1588-46dc-b2f0-add147424925";

/// Root verity partition for 64-bit PowerPC Big Endian
pub const ROOT_VERITY_PPC64: &str = "9225a9a3-3c19-4d89-b4f6-eeff88f17631";

/// Root verity partition for 64-bit PowerPC Little Endian
pub const ROOT_VERITY_PPC64_LE: &str = "906bd944-4589-4aae-a4e4-dd983917446a";

/// Root verity partition for 32-bit RISC-V
pub const ROOT_VERITY_RISCV32: &str = "ae0253be-1167-4007-ac68-43926c14c5de";

/// Root verity partition for 64-bit RISC-V
pub const ROOT_VERITY_RISCV64: &str = "b6ed5582-440b-4209-b8da-5ff7c419ea3d";

/// Root verity partition for s390
pub const ROOT_VERITY_S390: &str = "7ac63b47-b25c-463b-8df8-b4a94e6c90e1";

/// Root verity partition for s390x
pub const ROOT_VERITY_S390X: &str = "b325bfbe-c7be-4ab8-8357-139e652d2f6b";

/// Root verity partition for TILE-Gx
pub const ROOT_VERITY_TILEGX: &str = "966061ec-28e4-4b2e-b4a5-1f0a825a1d84";

/// Root verity partition for 32-bit x86
pub const ROOT_VERITY_X86: &str = "d13c5d3b-b5d1-422a-b29f-9454fdc89d76";

/// Root verity partition for 64-bit x86/AMD64
pub const ROOT_VERITY_X86_64: &str = "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5";

// ============================================================================
// USR VERITY PARTITIONS
// ============================================================================

/// /usr verity partition for Alpha
pub const USR_VERITY_ALPHA: &str = "8cce0d25-c0d0-4a44-bd87-46331bf1df67";

/// /usr verity partition for ARC
pub const USR_VERITY_ARC: &str = "fca0598c-d880-4591-8c16-4eda05c7347c";

/// /usr verity partition for 32-bit ARM
pub const USR_VERITY_ARM: &str = "c215d751-7bcd-4649-be90-6627490a4c05";

/// /usr verity partition for 64-bit ARM/AArch64
pub const USR_VERITY_ARM64: &str = "6e11a4e7-fbca-4ded-b9e9-e1a512bb664e";

/// /usr verity partition for Itanium/IA-64
pub const USR_VERITY_IA64: &str = "6a491e03-3be7-4545-8e38-83320e0ea880";

/// /usr verity partition for 64-bit LoongArch
pub const USR_VERITY_LOONGARCH64: &str = "f46b2c26-59ae-48f0-9106-c50ed47f673d";

/// /usr verity partition for 32-bit MIPS Big Endian
pub const USR_VERITY_MIPS: &str = "6e5a1bc8-d223-49b7-bca8-37a5fcceb996";

/// /usr verity partition for 64-bit MIPS Big Endian
pub const USR_VERITY_MIPS64: &str = "81cf9d90-7458-4df4-8dcf-c8a3a404f09b";

/// /usr verity partition for 32-bit MIPS Little Endian
pub const USR_VERITY_MIPS_LE: &str = "46b98d8d-b55c-4e8f-aab3-37fca7f80752";

/// /usr verity partition for 64-bit MIPS Little Endian
pub const USR_VERITY_MIPS64_LE: &str = "3c3d61fe-b5f3-414d-bb71-8739a694a4ef";

/// /usr verity partition for PA-RISC
pub const USR_VERITY_PARISC: &str = "5843d618-ec37-48d7-9f12-cea8e08768b2";

/// /usr verity partition for 32-bit PowerPC
pub const USR_VERITY_PPC: &str = "df765d00-270e-49e5-bc75-f47bb2118b09";

/// /usr verity partition for 64-bit PowerPC Big Endian
pub const USR_VERITY_PPC64: &str = "bdb528a5-a259-475f-a87d-da53fa736a07";

/// /usr verity partition for 64-bit PowerPC Little Endian
pub const USR_VERITY_PPC64_LE: &str = "ee2b9983-21e8-4153-86d9-b6901a54d1ce";

/// /usr verity partition for 32-bit RISC-V
pub const USR_VERITY_RISCV32: &str = "cb1ee4e3-8cd0-4136-a0a4-aa61a32e8730";

/// /usr verity partition for 64-bit RISC-V
pub const USR_VERITY_RISCV64: &str = "8f1056be-9b05-47c4-81d6-be53128e5b54";

/// /usr verity partition for s390
pub const USR_VERITY_S390: &str = "b663c618-e7bc-4d6d-90aa-11b756bb1797";

/// /usr verity partition for s390x
pub const USR_VERITY_S390X: &str = "31741cc4-1a2a-4111-a581-e00b447d2d06";

/// /usr verity partition for TILE-Gx
pub const USR_VERITY_TILEGX: &str = "2fb4bf56-07fa-42da-8132-6b139f2026ae";

/// /usr verity partition for 32-bit x86
pub const USR_VERITY_X86: &str = "8f461b0d-14ee-4e81-9aa9-049b6fb97abd";

/// /usr verity partition for 64-bit x86/AMD64
pub const USR_VERITY_X86_64: &str = "77ff5f63-e7b6-4633-acf4-1565b864c0e6";

// ============================================================================
// ROOT VERITY SIGNATURE PARTITIONS
// ============================================================================

/// Root verity signature partition for Alpha
pub const ROOT_VERITY_SIG_ALPHA: &str = "d46495b7-a053-414f-80f7-700c99921ef8";

/// Root verity signature partition for ARC
pub const ROOT_VERITY_SIG_ARC: &str = "143a70ba-cbd3-4f06-919f-6c05683a78bc";

/// Root verity signature partition for 32-bit ARM
pub const ROOT_VERITY_SIG_ARM: &str = "42b0455f-eb11-491d-98d3-56145ba9d037";

/// Root verity signature partition for 64-bit ARM/AArch64
pub const ROOT_VERITY_SIG_ARM64: &str = "6db69de6-29f4-4758-a7a5-962190f00ce3";

/// Root verity signature partition for Itanium/IA-64
pub const ROOT_VERITY_SIG_IA64: &str = "e98b36ee-32ba-4882-9b12-0ce14655f46a";

/// Root verity signature partition for 64-bit LoongArch
pub const ROOT_VERITY_SIG_LOONGARCH64: &str = "5afb67eb-ecc8-4f85-ae8e-ac1e7c50e7d0";

/// Root verity signature partition for 32-bit MIPS Big Endian
pub const ROOT_VERITY_SIG_MIPS: &str = "bba210a2-9c5d-45ee-9e87-ff2ccbd002d0";

/// Root verity signature partition for 64-bit MIPS Big Endian
pub const ROOT_VERITY_SIG_MIPS64: &str = "43ce94d4-0f3d-4999-8250-b9deafd98e6e";

/// Root verity signature partition for 32-bit MIPS Little Endian
pub const ROOT_VERITY_SIG_MIPS_LE: &str = "c919cc1f-4456-4eff-918c-f75e94525ca5";

/// Root verity signature partition for 64-bit MIPS Little Endian
pub const ROOT_VERITY_SIG_MIPS64_LE: &str = "904e58ef-5c65-4a31-9c57-6af5fc7c5de7";

/// Root verity signature partition for PA-RISC
pub const ROOT_VERITY_SIG_PARISC: &str = "15de6170-65d3-431c-916e-b0dcd8393f25";

/// Root verity signature partition for 32-bit PowerPC
pub const ROOT_VERITY_SIG_PPC: &str = "1b31b5aa-add9-463a-b2ed-bd467fc857e7";

/// Root verity signature partition for 64-bit PowerPC Big Endian
pub const ROOT_VERITY_SIG_PPC64: &str = "f5e2c20c-45b2-4ffa-bce9-2a60737e1aaf";

/// Root verity signature partition for 64-bit PowerPC Little Endian
pub const ROOT_VERITY_SIG_PPC64_LE: &str = "d4a236e7-e873-4c07-bf1d-bf6cf7f1c3c6";

/// Root verity signature partition for 32-bit RISC-V
pub const ROOT_VERITY_SIG_RISCV32: &str = "3a112a75-8729-4380-b4cf-764d79934448";

/// Root verity signature partition for 64-bit RISC-V
pub const ROOT_VERITY_SIG_RISCV64: &str = "efe0f087-ea8d-4469-821a-4c2a96a8386a";

/// Root verity signature partition for s390
pub const ROOT_VERITY_SIG_S390: &str = "3482388e-4254-435a-a241-766a065f9960";

/// Root verity signature partition for s390x
pub const ROOT_VERITY_SIG_S390X: &str = "c80187a5-73a3-491a-901a-017c3fa953e9";

/// Root verity signature partition for TILE-Gx
pub const ROOT_VERITY_SIG_TILEGX: &str = "b3671439-97b0-4a53-90f7-2d5a8f3ad47b";

/// Root verity signature partition for 32-bit x86
pub const ROOT_VERITY_SIG_X86: &str = "5996fc05-109c-48de-808b-23fa0830b676";

/// Root verity signature partition for 64-bit x86/AMD64
pub const ROOT_VERITY_SIG_X86_64: &str = "41092b05-9fc8-4523-994f-2def0408b176";

// ============================================================================
// USR VERITY SIGNATURE PARTITIONS
// ============================================================================

/// /usr verity signature partition for Alpha
pub const USR_VERITY_SIG_ALPHA: &str = "5c6e1c76-076a-457a-a0fe-f3b4cd21ce6e";

/// /usr verity signature partition for ARC
pub const USR_VERITY_SIG_ARC: &str = "94f9a9a1-9971-427a-a400-50cb297f0f35";

/// /usr verity signature partition for 32-bit ARM
pub const USR_VERITY_SIG_ARM: &str = "d7ff812f-37d1-4902-a810-d76ba57b975a";

/// /usr verity signature partition for 64-bit ARM/AArch64
pub const USR_VERITY_SIG_ARM64: &str = "c23ce4ff-44bd-4b00-b2d4-b41b3419e02a";

/// /usr verity signature partition for Itanium/IA-64
pub const USR_VERITY_SIG_IA64: &str = "8de58bc2-2a43-460d-b14e-a76e4a17b47f";

/// /usr verity signature partition for 64-bit LoongArch
pub const USR_VERITY_SIG_LOONGARCH64: &str = "b024f315-d330-444c-8461-44bbde524e99";

/// /usr verity signature partition for 32-bit MIPS Big Endian
pub const USR_VERITY_SIG_MIPS: &str = "97ae158d-f216-497b-8057-f7f905770f54";

/// /usr verity signature partition for 64-bit MIPS Big Endian
pub const USR_VERITY_SIG_MIPS64: &str = "05816ce2-dd40-4ac6-a61d-37d32dc1ba7d";

/// /usr verity signature partition for 32-bit MIPS Little Endian
pub const USR_VERITY_SIG_MIPS_LE: &str = "3e23ca0b-a4bc-4b4e-8087-5ab6a26aa8a9";

/// /usr verity signature partition for 64-bit MIPS Little Endian
pub const USR_VERITY_SIG_MIPS64_LE: &str = "f2c2c7ee-adcc-4351-b5c6-ee9816b66e16";

/// /usr verity signature partition for PA-RISC
pub const USR_VERITY_SIG_PARISC: &str = "450dd7d1-3224-45ec-9cf2-a43a346d71ee";

/// /usr verity signature partition for 32-bit PowerPC
pub const USR_VERITY_SIG_PPC: &str = "7007891d-d371-4a80-86a4-5cb875b9302e";

/// /usr verity signature partition for 64-bit PowerPC Big Endian
pub const USR_VERITY_SIG_PPC64: &str = "0b888863-d7f8-4d9e-9766-239fce4d58af";

/// /usr verity signature partition for 64-bit PowerPC Little Endian
pub const USR_VERITY_SIG_PPC64_LE: &str = "c8bfbd1e-268e-4521-8bba-bf314c399557";

/// /usr verity signature partition for 32-bit RISC-V
pub const USR_VERITY_SIG_RISCV32: &str = "c3836a13-3137-45ba-b583-b16c50fe5eb4";

/// /usr verity signature partition for 64-bit RISC-V
pub const USR_VERITY_SIG_RISCV64: &str = "d2f9000a-7a18-453f-b5cd-4d32f77a7b32";

/// /usr verity signature partition for s390
pub const USR_VERITY_SIG_S390: &str = "17440e4f-a8d0-467f-a46e-3912ae6ef2c5";

/// /usr verity signature partition for s390x
pub const USR_VERITY_SIG_S390X: &str = "3f324816-667b-46ae-86ee-9b0c0c6c11b4";

/// /usr verity signature partition for TILE-Gx
pub const USR_VERITY_SIG_TILEGX: &str = "4ede75e2-6ccc-4cc8-b9c7-70334b087510";

/// /usr verity signature partition for 32-bit x86
pub const USR_VERITY_SIG_X86: &str = "974a71c0-de41-43c3-be5d-5c5ccd1ad2c0";

/// /usr verity signature partition for 64-bit x86/AMD64
pub const USR_VERITY_SIG_X86_64: &str = "e7bb33fb-06cf-4e81-8273-e543b413e2e2";

// ============================================================================
// OTHER SPECIAL PARTITION TYPES
// ============================================================================

/// EFI System Partition (ESP) for UEFI boot
pub const ESP: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";

/// Extended Boot Loader Partition
pub const XBOOTLDR: &str = "bc13c2ff-59e6-4262-a352-b275fd6f7172";

/// Swap partition
pub const SWAP: &str = "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f";

/// Home partition (/home)
pub const HOME: &str = "933ac7e1-2eb4-4f13-b844-0e14e2aef915";

/// Server data partition (/srv)
pub const SRV: &str = "3b8f8425-20e0-4f3b-907f-1a25a76f98e8";

/// Variable data partition (/var)
pub const VAR: &str = "4d21b016-b534-45c2-a9fb-5c16e091fd2d";

/// Temporary data partition (/var/tmp)
pub const TMP: &str = "7ec6f557-3bc5-4aca-b293-16ef5df639d1";

/// Generic Linux filesystem data partition
pub const LINUX_DATA: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";

// ============================================================================
// ARCHITECTURE-SPECIFIC HELPERS
// ============================================================================

/// Returns the root partition GUID for the current architecture.
///
/// This is a compile-time constant function that selects the appropriate
/// root partition type GUID based on the target architecture and endianness.
pub const fn this_arch_root() -> &'static str {
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            ROOT_X86_64
        } else if #[cfg(target_arch = "arm")] {
            ROOT_ARM
        } else if #[cfg(target_arch = "aarch64")] {
            ROOT_ARM64
        } else if #[cfg(target_arch = "s390x")] {
            ROOT_S390X
        } else if #[cfg(all(target_arch = "powerpc64", target_endian = "big"))] {
            ROOT_PPC64
        } else if #[cfg(all(target_arch = "powerpc64", target_endian = "little"))] {
            ROOT_PPC64_LE
        } else {
            compile_error!("Unsupported architecture")
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[ignore = "Only run manually to validate against upstream spec"]
    fn test_uuids_against_spec() {
        // This test validates our partition type UUIDs against the upstream
        // Discoverable Partitions Specification. The spec is committed to the
        // repo at fixtures/discoverable_partitions_specification.md
        //
        // Spec source: https://github.com/uapi-group/specifications/blob/6f3a5dd31009456561eaa9f6fcfe7769ab97eb50/specs/discoverable_partitions_specification.md

        let spec_content = include_str!("fixtures/discoverable_partitions_specification.md");

        // Parse the markdown tables and extract partition name -> UUID mappings
        let mut spec_uuids: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::new();

        // Regex to match table rows with partition type UUIDs
        // Format: | _Name_ | `uuid` ... | ... | ... |
        let re = regex::Regex::new(
            r"(?m)^\|\s*_(.+?)_\s*\|\s*`([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`"
        )
        .unwrap();

        for cap in re.captures_iter(&spec_content) {
            let name = cap.get(1).unwrap().as_str();
            let uuid = cap.get(2).unwrap().as_str();
            spec_uuids.insert(name, uuid);
        }

        // Verify we parsed a reasonable number of entries
        assert!(
            spec_uuids.len() > 100,
            "Expected to parse over 100 UUIDs, got {}",
            spec_uuids.len()
        );

        // Now cross-reference our constants against the spec
        macro_rules! check_uuid {
            ($name:expr, $const_val:expr) => {
                if let Some(&spec_uuid) = spec_uuids.get($name) {
                    assert_eq!(
                        $const_val, spec_uuid,
                        "UUID mismatch for {}: our value '{}' != spec value '{}'",
                        $name, $const_val, spec_uuid
                    );
                } else {
                    panic!("No spec entry found for {}", $name);
                }
            };
        }

        // Root Partitions
        check_uuid!("Root Partition (Alpha)", ROOT_ALPHA);
        check_uuid!("Root Partition (ARC)", ROOT_ARC);
        check_uuid!("Root Partition (32-bit ARM)", ROOT_ARM);
        check_uuid!("Root Partition (64-bit ARM/AArch64)", ROOT_ARM64);
        check_uuid!("Root Partition (Itanium/IA-64)", ROOT_IA64);
        check_uuid!("Root Partition (LoongArch 64-bit)", ROOT_LOONGARCH64);
        check_uuid!(
            "Root Partition (32-bit MIPS LittleEndian (mipsel))",
            ROOT_MIPS_LE
        );
        check_uuid!(
            "Root Partition (64-bit MIPS LittleEndian (mips64el))",
            ROOT_MIPS64_LE
        );
        check_uuid!("Root Partition (32-bit MIPS BigEndian (mips))", ROOT_MIPS);
        check_uuid!(
            "Root Partition (64-bit MIPS BigEndian (mips64))",
            ROOT_MIPS64
        );
        check_uuid!("Root Partition (HPPA/PARISC)", ROOT_PARISC);
        check_uuid!("Root Partition (32-bit PowerPC)", ROOT_PPC);
        check_uuid!("Root Partition (64-bit PowerPC BigEndian)", ROOT_PPC64);
        check_uuid!(
            "Root Partition (64-bit PowerPC LittleEndian)",
            ROOT_PPC64_LE
        );
        check_uuid!("Root Partition (RISC-V 32-bit)", ROOT_RISCV32);
        check_uuid!("Root Partition (RISC-V 64-bit)", ROOT_RISCV64);
        check_uuid!("Root Partition (s390)", ROOT_S390);
        check_uuid!("Root Partition (s390x)", ROOT_S390X);
        check_uuid!("Root Partition (TILE-Gx)", ROOT_TILEGX);
        check_uuid!("Root Partition (x86)", ROOT_X86);
        check_uuid!("Root Partition (amd64/x86_64)", ROOT_X86_64);

        // USR Partitions
        check_uuid!("`/usr/` Partition (Alpha)", USR_ALPHA);
        check_uuid!("`/usr/` Partition (ARC)", USR_ARC);
        check_uuid!("`/usr/` Partition (32-bit ARM)", USR_ARM);
        check_uuid!("`/usr/` Partition (64-bit ARM/AArch64)", USR_ARM64);
        check_uuid!("`/usr/` Partition (Itanium/IA-64)", USR_IA64);
        check_uuid!("`/usr/` Partition (LoongArch 64-bit)", USR_LOONGARCH64);
        check_uuid!("`/usr/` Partition (32-bit MIPS BigEndian (mips))", USR_MIPS);
        check_uuid!(
            "`/usr/` Partition (64-bit MIPS BigEndian (mips64))",
            USR_MIPS64
        );
        check_uuid!(
            "`/usr/` Partition (32-bit MIPS LittleEndian (mipsel))",
            USR_MIPS_LE
        );
        check_uuid!(
            "`/usr/` Partition (64-bit MIPS LittleEndian (mips64el))",
            USR_MIPS64_LE
        );
        check_uuid!("`/usr/` Partition (HPPA/PARISC)", USR_PARISC);
        check_uuid!("`/usr/` Partition (32-bit PowerPC)", USR_PPC);
        check_uuid!("`/usr/` Partition (64-bit PowerPC BigEndian)", USR_PPC64);
        check_uuid!(
            "`/usr/` Partition (64-bit PowerPC LittleEndian)",
            USR_PPC64_LE
        );
        check_uuid!("`/usr/` Partition (RISC-V 32-bit)", USR_RISCV32);
        check_uuid!("`/usr/` Partition (RISC-V 64-bit)", USR_RISCV64);
        check_uuid!("`/usr/` Partition (s390)", USR_S390);
        check_uuid!("`/usr/` Partition (s390x)", USR_S390X);
        check_uuid!("`/usr/` Partition (TILE-Gx)", USR_TILEGX);
        check_uuid!("`/usr/` Partition (x86)", USR_X86);
        check_uuid!("`/usr/` Partition (amd64/x86_64)", USR_X86_64);

        // Root Verity Partitions
        check_uuid!("Root Verity Partition (Alpha)", ROOT_VERITY_ALPHA);
        check_uuid!("Root Verity Partition (ARC)", ROOT_VERITY_ARC);
        check_uuid!("Root Verity Partition (32-bit ARM)", ROOT_VERITY_ARM);
        check_uuid!(
            "Root Verity Partition (64-bit ARM/AArch64)",
            ROOT_VERITY_ARM64
        );
        check_uuid!("Root Verity Partition (Itanium/IA-64)", ROOT_VERITY_IA64);
        check_uuid!(
            "Root Verity Partition (LoongArch 64-bit)",
            ROOT_VERITY_LOONGARCH64
        );
        check_uuid!(
            "Root Verity Partition (32-bit MIPS BigEndian (mips))",
            ROOT_VERITY_MIPS
        );
        check_uuid!(
            "Root Verity Partition (64-bit MIPS BigEndian (mips64))",
            ROOT_VERITY_MIPS64
        );
        check_uuid!(
            "Root Verity Partition (32-bit MIPS LittleEndian (mipsel))",
            ROOT_VERITY_MIPS_LE
        );
        check_uuid!(
            "Root Verity Partition (64-bit MIPS LittleEndian (mips64el))",
            ROOT_VERITY_MIPS64_LE
        );
        check_uuid!("Root Verity Partition (HPPA/PARISC)", ROOT_VERITY_PARISC);
        check_uuid!("Root Verity Partition (32-bit PowerPC)", ROOT_VERITY_PPC);
        check_uuid!(
            "Root Verity Partition (64-bit PowerPC BigEndian)",
            ROOT_VERITY_PPC64
        );
        check_uuid!(
            "Root Verity Partition (64-bit PowerPC LittleEndian)",
            ROOT_VERITY_PPC64_LE
        );
        check_uuid!("Root Verity Partition (RISC-V 32-bit)", ROOT_VERITY_RISCV32);
        check_uuid!("Root Verity Partition (RISC-V 64-bit)", ROOT_VERITY_RISCV64);
        check_uuid!("Root Verity Partition (s390)", ROOT_VERITY_S390);
        check_uuid!("Root Verity Partition (s390x)", ROOT_VERITY_S390X);
        check_uuid!("Root Verity Partition (TILE-Gx)", ROOT_VERITY_TILEGX);
        check_uuid!("Root Verity Partition (x86)", ROOT_VERITY_X86);
        check_uuid!("Root Verity Partition (amd64/x86_64)", ROOT_VERITY_X86_64);

        // USR Verity Partitions
        check_uuid!("`/usr/` Verity Partition (Alpha)", USR_VERITY_ALPHA);
        check_uuid!("`/usr/` Verity Partition (ARC)", USR_VERITY_ARC);
        check_uuid!("`/usr/` Verity Partition (32-bit ARM)", USR_VERITY_ARM);
        check_uuid!(
            "`/usr/` Verity Partition (64-bit ARM/AArch64)",
            USR_VERITY_ARM64
        );
        check_uuid!("`/usr/` Verity Partition (Itanium/IA-64)", USR_VERITY_IA64);
        check_uuid!(
            "`/usr/` Verity Partition (LoongArch 64-bit)",
            USR_VERITY_LOONGARCH64
        );
        check_uuid!(
            "`/usr/` Verity Partition (32-bit MIPS BigEndian (mips))",
            USR_VERITY_MIPS
        );
        check_uuid!(
            "`/usr/` Verity Partition (64-bit MIPS BigEndian (mips64))",
            USR_VERITY_MIPS64
        );
        check_uuid!(
            "`/usr/` Verity Partition (32-bit MIPS LittleEndian (mipsel))",
            USR_VERITY_MIPS_LE
        );
        check_uuid!(
            "`/usr/` Verity Partition (64-bit MIPS LittleEndian (mips64el))",
            USR_VERITY_MIPS64_LE
        );
        check_uuid!("`/usr/` Verity Partition (HPPA/PARISC)", USR_VERITY_PARISC);
        check_uuid!("`/usr/` Verity Partition (32-bit PowerPC)", USR_VERITY_PPC);
        check_uuid!(
            "`/usr/` Verity Partition (64-bit PowerPC BigEndian)",
            USR_VERITY_PPC64
        );
        check_uuid!(
            "`/usr/` Verity Partition (64-bit PowerPC LittleEndian)",
            USR_VERITY_PPC64_LE
        );
        check_uuid!(
            "`/usr/` Verity Partition (RISC-V 32-bit)",
            USR_VERITY_RISCV32
        );
        check_uuid!(
            "`/usr/` Verity Partition (RISC-V 64-bit)",
            USR_VERITY_RISCV64
        );
        check_uuid!("`/usr/` Verity Partition (s390)", USR_VERITY_S390);
        check_uuid!("`/usr/` Verity Partition (s390x)", USR_VERITY_S390X);
        check_uuid!("`/usr/` Verity Partition (TILE-Gx)", USR_VERITY_TILEGX);
        check_uuid!("`/usr/` Verity Partition (x86)", USR_VERITY_X86);
        check_uuid!("`/usr/` Verity Partition (amd64/x86_64)", USR_VERITY_X86_64);

        // Root Verity Signature Partitions
        check_uuid!(
            "Root Verity Signature Partition (Alpha)",
            ROOT_VERITY_SIG_ALPHA
        );
        check_uuid!("Root Verity Signature Partition (ARC)", ROOT_VERITY_SIG_ARC);
        check_uuid!(
            "Root Verity Signature Partition (32-bit ARM)",
            ROOT_VERITY_SIG_ARM
        );
        check_uuid!(
            "Root Verity Signature Partition (64-bit ARM/AArch64)",
            ROOT_VERITY_SIG_ARM64
        );
        check_uuid!(
            "Root Verity Signature Partition (Itanium/IA-64)",
            ROOT_VERITY_SIG_IA64
        );
        check_uuid!(
            "Root Verity Signature Partition (LoongArch 64-bit)",
            ROOT_VERITY_SIG_LOONGARCH64
        );
        check_uuid!(
            "Root Verity Signature Partition (32-bit MIPS BigEndian (mips))",
            ROOT_VERITY_SIG_MIPS
        );
        check_uuid!(
            "Root Verity Signature Partition (64-bit MIPS BigEndian (mips64))",
            ROOT_VERITY_SIG_MIPS64
        );
        check_uuid!(
            "Root Verity Signature Partition (32-bit MIPS LittleEndian (mipsel))",
            ROOT_VERITY_SIG_MIPS_LE
        );
        check_uuid!(
            "Root Verity Signature Partition (64-bit MIPS LittleEndian (mips64el))",
            ROOT_VERITY_SIG_MIPS64_LE
        );
        check_uuid!(
            "Root Verity Signature Partition (HPPA/PARISC)",
            ROOT_VERITY_SIG_PARISC
        );
        check_uuid!(
            "Root Verity Signature Partition (32-bit PowerPC)",
            ROOT_VERITY_SIG_PPC
        );
        check_uuid!(
            "Root Verity Signature Partition (64-bit PowerPC BigEndian)",
            ROOT_VERITY_SIG_PPC64
        );
        check_uuid!(
            "Root Verity Signature Partition (64-bit PowerPC LittleEndian)",
            ROOT_VERITY_SIG_PPC64_LE
        );
        check_uuid!(
            "Root Verity Signature Partition (RISC-V 32-bit)",
            ROOT_VERITY_SIG_RISCV32
        );
        check_uuid!(
            "Root Verity Signature Partition (RISC-V 64-bit)",
            ROOT_VERITY_SIG_RISCV64
        );
        check_uuid!(
            "Root Verity Signature Partition (s390)",
            ROOT_VERITY_SIG_S390
        );
        check_uuid!(
            "Root Verity Signature Partition (s390x)",
            ROOT_VERITY_SIG_S390X
        );
        check_uuid!(
            "Root Verity Signature Partition (TILE-Gx)",
            ROOT_VERITY_SIG_TILEGX
        );
        check_uuid!("Root Verity Signature Partition (x86)", ROOT_VERITY_SIG_X86);
        check_uuid!(
            "Root Verity Signature Partition (amd64/x86_64)",
            ROOT_VERITY_SIG_X86_64
        );

        // USR Verity Signature Partitions
        check_uuid!(
            "`/usr/` Verity Signature Partition (Alpha)",
            USR_VERITY_SIG_ALPHA
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (ARC)",
            USR_VERITY_SIG_ARC
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (32-bit ARM)",
            USR_VERITY_SIG_ARM
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (64-bit ARM/AArch64)",
            USR_VERITY_SIG_ARM64
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (Itanium/IA-64)",
            USR_VERITY_SIG_IA64
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (LoongArch 64-bit)",
            USR_VERITY_SIG_LOONGARCH64
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (32-bit MIPS BigEndian (mips))",
            USR_VERITY_SIG_MIPS
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (64-bit MIPS BigEndian (mips64))",
            USR_VERITY_SIG_MIPS64
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (32-bit MIPS LittleEndian (mipsel))",
            USR_VERITY_SIG_MIPS_LE
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (64-bit MIPS LittleEndian (mips64el))",
            USR_VERITY_SIG_MIPS64_LE
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (HPPA/PARISC)",
            USR_VERITY_SIG_PARISC
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (32-bit PowerPC)",
            USR_VERITY_SIG_PPC
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (64-bit PowerPC BigEndian)",
            USR_VERITY_SIG_PPC64
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (64-bit PowerPC LittleEndian)",
            USR_VERITY_SIG_PPC64_LE
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (RISC-V 32-bit)",
            USR_VERITY_SIG_RISCV32
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (RISC-V 64-bit)",
            USR_VERITY_SIG_RISCV64
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (s390)",
            USR_VERITY_SIG_S390
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (s390x)",
            USR_VERITY_SIG_S390X
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (TILE-Gx)",
            USR_VERITY_SIG_TILEGX
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (x86)",
            USR_VERITY_SIG_X86
        );
        check_uuid!(
            "`/usr/` Verity Signature Partition (amd64/x86_64)",
            USR_VERITY_SIG_X86_64
        );

        // Other special partition types
        check_uuid!("EFI System Partition", ESP);
        check_uuid!("Extended Boot Loader Partition", XBOOTLDR);
        check_uuid!("Swap", SWAP);
        check_uuid!("Home Partition", HOME);
        check_uuid!("Server Data Partition", SRV);
        check_uuid!("Variable Data Partition", VAR);
        check_uuid!("Temporary Data Partition", TMP);
        check_uuid!("Generic Linux Data Partition", LINUX_DATA);
    }
}
