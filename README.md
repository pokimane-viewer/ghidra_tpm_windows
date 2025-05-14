Below is a practical playbook that shows how you can (1) pull apart the Intel HM-370 boot firmware with Ghidra, (2) understand where the TPM fits into the Windows-boot trust chain, and (3) prove to yourself—by reading TPM evidence—that the stack really traveled through the TPM and wasn’t silently short-circuited.

1. Where the TPM shows up in an HM-370 boot
Boot phase	Who executes next stage	What the TPM sees
Intel Boot Guard / ACM
(hard-wired in the PCH)	Verifies the reset-vector flash block before the CPU executes it (Profile 5 on HM-370) 
Intel
Nothing yet—Boot Guard only blocks execution if the hash fails
UEFI SEC/PEI	Measures the PEI core and PEI drivers into PCR 0–2, then passes control to DXE	First TPM measurements appear
DXE + BDS	Measures DXE drivers, Option ROMs, Secure Boot policy into PCR 4	TPM log begins to mirror Secure Boot status 
Microsoft Learn
Windows Boot Manager	Measured into PCR 7; decides whether to launch BitLocker unlock	Windows now owns the log; health attestation later consumes it 
Microsoft Learn

If Boot Guard is disabled or the TPM is turned off, the very first PCR extensions never happen, leaving PCRs 0-2 at all-zeros; that’s the signal you’re looking for.

2. Pulling the firmware apart with Ghidra
Dump the SPI flash
Use chipsec_util spi dump spi.bin under a Linux live-boot or UEFI shell. CHIPSEC understands HM-370 and will warn you if Boot Guard is enforced. 
GitHub
GitHub

Load into Ghidra
Install the efiSeek plugin—it auto-identifies PEI/DXE images, GUIDs and SMI handlers, dramatically cutting the manual work. 
GitHub
DEV Community

Focus on the measurement hooks
Look for calls to EFI_TCG2_PROTOCOL->HashLogExtendEvent or, in older code, EFI_TCG_PROTOCOL->HashLogExtendEvent. These are the points the firmware uses to tell the TPM about each component. Seeing these calls (and their arguments) lets you map a component to the PCR where it lands.

Map Boot Guard configuration
In the Boot-Guard-verified Boot-Policy Manifest you’ll find flags that show whether verification is “Verified Boot” (stop-on-fail) or “Measured Boot” (just extends). The manifest is SHA-256-hashed in the FPF, so any change you see in Ghidra will fail to boot on real silicon. 
Trammell Hudson's Projects
Binarly

Diff against vendor BIOS updates
Use Ghidra’s Binary-Diff to see what changed between official updates and your dump—handy for spotting vendor backdoors or debug keys.

3. Collecting the evidence inside Windows
Task	Command / UI	What you get
Check TPM presence & firmware	tpmtool getdeviceinformation	TPM version, PCR banks, Boot Guard fuses (if surfaced) 
Microsoft Learn
Grab raw TPM event log	tpmtool gatherlogs or C:\Windows\Logs\MeasuredBoot\	CSV/JSON with each PCR extension (bootmgr, winload, ELAM…) 
Microsoft Learn
Microsoft Learn
Decode PCRs quickly	tbsloggenerator.exe -i <log> -o decoded.csv (MS tool)	Human-readable timeline of hash → PCR
View real-time PCRs	tpmtool pcrlist (Win 11) or tpm2_pcrread sha256:0,2,4,7 (Linux)	Current PCR values to compare with log
Look at Secure-/Measured-Boot events	Event Viewer → Applications and Services Logs ▶ Microsoft ▶ Windows ▶ Kernel-Boot / TPM	Correlates each PCR write with Event IDs 12, 13, 49 
Microsoft Learn

Quick test:

Boot once with TPM ON, export PCRs.

Disable TPM in BIOS, boot again, export PCRs.

Diff the two logs: PCR 0-2 are zeroed and later PCRs shift because nothing upstream was measured. Difference = proof that the TPM path was skipped.

4. Automating the comparison
powershell
Copy
Edit
# PowerShell miniburst to spot a missing TPM chain
$baseline = (Get-Content ".\pcr_tpm_on.txt") | Select-String "PCR\[0\]" | ForEach-Object { $_.Line.Split()[2] }
$test     = (Get-Content ".\pcr_tpm_off.txt") | Select-String "PCR\[0\]" | ForEach-Object { $_.Line.Split()[2] }
if ($baseline -eq $test) {
    Write-Host "⚠️  Boot DID NOT traverse the TPM (PCR₀ identical)"
} else {
    Write-Host "✅ Boot measured through TPM (PCR₀ differs as expected)"
}
5. Extra telemetry for peace of mind
Health Attestation CSP / Azure Attestation – Measured-Boot data can be validated remotely; a mismatch denies device access. 
Microsoft Learn
Microsoft Learn

BitLocker – When the protector is “TPM + PCR 7” Windows will refuse to auto-unlock if PCR 7 differs, which implicitly tells you Secure/Measured Boot ran. 
Microsoft Learn

ELAM revocation – Drivers can deliberately invalidate the chain; check Event ID 7000 for Tbsi_Revoke_Attestation if you suspect this. 
Microsoft Learn

6. Limitations & tips
Boot Guard on HM-370 is fuse-controlled; once burned you can’t turn it off without new silicon.

If the flash descriptor is locked, you may need an external programmer to dump firmware for Ghidra analysis.

Measuring the chain doesn’t block malware (that’s Secure Boot’s job) — it only provides evidence. Always combine with Secure Boot. 
Microsoft Learn

TL;DR
Use CHIPSEC to dump firmware, Ghidra + efiSeek to map where each UEFI module hashes itself into the TPM, then let tpmtool and the Measured-Boot logs prove (or disprove) that PCRs 0-7 were actually extended on your last Windows start. With one baseline log in hand, any deviation—especially zero-filled early PCRs—tells you the boot stack bypassed the TPM and therefore bypassed you.# ghidra_tpm_windows

