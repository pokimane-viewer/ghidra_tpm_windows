
#!/usr/bin/env python3
"""
arm64 ⇒ secure_enclave
Windows ∧ Win32_Tpm ⇒ tpm_windows
¬arm64 ∧ ¬Windows ∧ ∃ESAPI ⇒ tpm
"""
import platform,sys,re

def is_apple_silicon() -> bool:
    """
    arm64 ↔ SE_present
    """
    return platform.machine()=='arm64'

def is_windows() -> bool:
    """
    Windows ↔ System_is_Windows
    """
    return platform.system()=='Windows'

def interpret_hresult(hr:int)->str:
    """
    hresult↔name
    """
    names={
        0x80041003:'WBEM_E_ACCESS_DENIED',
        0x80041001:'WBEM_E_FAILED',
        0x80041002:'WBEM_E_NOT_FOUND',
        0x80041010:'WBEM_E_INVALID_CLASS',
    }
    return names.get(hr,'UNKNOWN')

def windows_tpm_info():
    """
    info ↔ (TPM_present ⊕ reason)
    """
    try:
        import wmi
    except Exception as e:
        return False,f'import_error:{e}'
    try:
        c=wmi.WMI(namespace="root\\CIMv2\\Security\\MicrosoftTpm")
        tpms=c.Win32_Tpm()
        if not tpms:
            return False,'no_instances'
        t=tpms[0]
        enabled=bool(getattr(t,'IsEnabled_InitialValue',None))
        activated=getattr(t,'IsActivated_InitialValue',None)
        owned=getattr(t,'IsOwned_InitialValue',None)
        status=f'enabled={enabled},activated={activated},owned={owned}'
        return enabled,status
    except Exception as e:
        s=str(e)
        m=re.search(r'0x([0-9A-Fa-f]{8})',s)
        if m:
            hr=int(m.group(1),16)
            return False,f'hresult=0x{hr:08X}:{interpret_hresult(hr)}'
        return False,f'query_error:{e}'

def esapi_available():
    """
    ESAPI_importable ↔ TPM_present
    """
    try:
        import tpm2_pytss
        return True,'import_ok'
    except ImportError as e:
        return False,f'import_error:{e}'

def tpm_get_random(n:int)->bytes:
    """
    RNG(n) → bytes
    """
    from tpm2_pytss import ESAPI
    with ESAPI() as esys:
        return esys.GetRandom(n).buffer

def main():
    """
    decide_and_print_status
    """
    debug=[]
    arch=platform.machine()
    os_name=platform.system()
    os_rel=platform.release()
    os_ver=platform.version()
    edition=getattr(platform,'win32_edition',lambda:'')()
    debug.append(f'Architecture:{arch}')
    debug.append(f'OS:{os_name} release:{os_rel} version:{os_ver} edition:{edition}')
    if is_apple_silicon():
        debug.append('Detected:AppleSilicon')
        print('SecureEnclave:available')
        print('\n'.join(debug))
        sys.exit(0)
    if is_windows():
        debug.append('Detected:Windows')
        present,detail=windows_tpm_info()
        debug.append(f'WMI:{detail}')
        if present:
            try:
                import tpm2_pytss
                debug.append('tpm2_pytss:import_ok')
                rnd=tpm_get_random(16)
                debug.append('Random:TPM')
                print('TPM:available')
                print(rnd.hex())
            except Exception as e:
                rnd=__import__('os').urandom(16)
                debug.append(f'tpm2_pytss:error:{e}')
                debug.append('Random:os.urandom')
                print('TPM:available_fallback')
                print(rnd.hex())
        else:
            debug.append('TPM:not_present')
            print('TPM:not_available')
        print('\n'.join(debug))
        sys.exit(0)
    debug.append('Detected:OtherOS')
    present,detail=esapi_available()
    debug.append(f'ESAPI:{detail}')
    if present:
        rnd=tpm_get_random(16)
        debug.append('Random:TPM')
        print('TPM:available')
        print(rnd.hex())
    else:
        debug.append('TPM:not_present')
        debug.append('Random:Unavailable')
        print('TPM:not_available')
    print('\n'.join(debug))

if __name__=='__main__':
    main()

