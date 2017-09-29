# efficient-3pc
Secure Three-Party Computation with Fairness and Guaranteed Output Delivery.

This repository contain implementations for MRZ15 a fair protocol based on MRZ15.
An efficient three party Garanteed output delivery protocol.

## Testing instructions

Always start the evaluator first. run garblers in different terminals.
'''
make
./mrz.exe e 10.192.39.21
./mrz.exe g 10.192.39.21
./mrz.exe g 10.192.39.21
'''

By default they are evaluation on SHA-256 circuit. The efficient circuit files are from http://www.cs.bris.ac.uk/Research/CryptographySecurity/MPC/ .
