## python-libehsm is a Python wrapper for the ellipticSecure PKCS11 shared library

Note that while the wrapper does export some PKCS#11 helper 
functions it does so only partially - there are other wrappers 
available to interface with PKCS#11.

The focus of this wrapper is to export the BIP32/Bitcoin specific functions.

## Installation

Download and install the native shared library for your platform here: [https://ellipticsecure.com/downloads/](https://ellipticsecure.com/downloads/)

pip install ehsm


## Example

Signing a transaction hash with a BIP32 (Bitcoin etc.) derived key stored on
a MIRkey or eHSM device:

```python
import ehsm

mirkey = ehsm.load_ehsm()
        
# Get the available device slots
slots = mirkey.enumerate_slots()

if len(slots) > 0:        
    # Use the first available slot
    slot = slots[0]
        
    # Initialize the library
    mirkey.init()
    try:
        session = mirkey.get_logged_in_rw_session(slot, b"testsu")
        found = mirkey.bip32_has_root_key(session)
        if found:
            hash = bytes(32)
            # list of integers representing a bip32 path to the derived key
            # 
            # ie. this is "m/0", "m" would be []
            indexes = [0] 
            sig = mirkey.bip32_sign_data(session, hash, indexes)
    finally:
        mirkey.finalize()
else:
    print "No devices found"
    
```

Please see the test cases for more usage examples.
