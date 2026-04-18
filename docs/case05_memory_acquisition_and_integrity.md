# Case 05 – Memory Acquisition and Integrity Record

## 1. Acquisition Method
Case 05 memory acquisition was performed using a hypervisor-assisted VirtualBox memory dump. This method was used instead of an in-guest acquisition tool to avoid kernel driver restrictions and to preserve a consistent acquisition methodology across the project.

## 2. Virtual Machine Information
- VM Name: Windows 10

## 3. Host Dump Command
The following command was used on the host machine to acquire the Case 05 memory image:

### powershell
VBoxManage debugvm "Windows 10" dumpvmcore --filename "D:\2.ROEHAMPTON\Final year\FYPROJECT\Memory forensics framework tools for analyse and visualisation\shared\T_multi.raw"
##4. Transfer Path
After acquisition, the raw image was transferred from the shared folder into the Kali analysis environment and stored in:

Copy/MFF/cases/case05_multi_attack/T_multi.raw
###5. Evidence Preservation
After transfer, the image was retained as the official memory image for Case 05 and used as the source input for Volatility 3 analysis and MFF comparison.

Recommended preservation step:

Copychmod 444 /MFF/cases/case05_multi_attack/T_multi.raw
###6. Hash Verification
The following hash values were recorded for forensic integrity verification:

MD5: 8c4f8c763f78993b30b2ac4a230952a2
SHA1: 3d1825d640cbf425b54c83464eea9076ba251463
SHA256: a0983f4df938595db7ffdb377b743defdd02428f6b1d97b9f653821690a8f1d0
###7. Integrity Purpose
Hashing was used to verify that the memory image remained unchanged after acquisition and transfer. This supports chain-of-custody principles and strengthens the forensic defensibility of the case study.

###8. Methodological Justification
Hypervisor-assisted dumping was chosen because earlier project work identified practical limitations with in-guest driver-based memory acquisition. The hypervisor method provided a more stable and reproducible approach for obtaining raw memory suitable for post-Volatility analysis within the framework.


