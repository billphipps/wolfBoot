# wolfTPM PCR Policy pubkey sealing

## NOTE: Currently only ecc256 keys are supported for policy sealing

The image verification public key that wolfBoot uses to verify the boot partition image is typically stored within wolfBoot partition.  However, this public key can instead be stored (sealed) in the TPM and also be tied to the boot partition digest, which has been extended into a TPM PCR. The key can only be retrieved (unsealed) if the image digest is untampered.  When signature verification using the unsealed key and the untampered image signature is completed, this proves the image has not been tampered with since it was signed, typically after compilation.
To use this pubkey sealing feature, define (within the configuration file) `WOLFBOOT_TPM_KEYSTORE?=1` and set `WOLFBOOT_TPM_KEYSTORE_NV_INDEX` and `WOLFBOOT_TPM_POLICY_NV_INDEX` to NVM indicies supported by your TPM. The default PCR index can be overridden by defining and setting `WOLFBOOT_TPM_PCR_INDEX` to a resettable PCR register number, such as 16.
Sealing the image verification pubkey requires two asymmetric keys: a policy key and an image verification key. The private (and disposable) policy key is used to sign a TPM2 element aHash, generating a Policy Signed signature. The public policy key is embedded into the wolfBoot partition and is used to unseal the public verification key from the TPM.  The keys and policy signature can be generated automatically with the tools/preseal/keygen command executed on a host computer:

```
$ tools/preseal/keygen
Generating keys and signed aHash for public key sealing...
Policy Signature: policy-signed.raw
Policy Public Key: policy-public-key.raw
Verification Public Key: public-key.raw
Verification Private Key: private-key.raw
```

To import the policy public key into the wolfBoot partition, use the tools/keytools/keygen command to override the existing image verification public key and generate the wolfBoot executable (wolfboot.elf) and partition (wolfboot.bin):

```
$ tools/keytools/keygen --ecc256 -i policy-public-key.raw
Keytype: ECC256
Imp policy-public-key.raw
Associated key file:   policy-public-key.raw
Key type   :           ECC256
Public key slot:       0
Done.

$ make wolfboot.bin
...
	[BIN] wolfboot.bin

	[SIZE]
   text	   data	    bss	    dec	    hex	filename
  79104	     24	  68016	 147144	  23ec8	wolfboot.elf
```

Build the test-app image and calculate the image digest for version 1.  Note that the the policy public key is not used to calculate the image digest, but the size and type of key are used to ensure the header fields are correctly set.

```
$ make test-app/image.bin
...
	[BIN] image.bin
   text	   data	    bss	    dec	    hex	filename
    448	   2496	    556	   3500	    dac	test-app/image.elf

$ tools/keytools/sign --ecc256 --sha256 --sha-only test-app/image.bin policy-public-key.raw 1
wolfBoot KeyTools (Compiled C version)
wolfBoot version 10F0000
Update type:          Firmware
Input image:          test-app/image.bin
Selected cipher:      ECC256
Selected hash  :      SHA256
Public key:           policy-public-key.raw
Output digest:        test-app/image_v1_digest.bin
Target partition id : 1 
ECC256 public key detected
Calculating SHA256 digest...
Digest image test-app/image_v1_digest.bin successfully created.
```

Make the image signature, which will be placed into the signed image partition, by signing the image digest using the image verification private key with the tools/preseal/sign tool.  Create the signed image partition using tools/keytools/sign with the --manual-sign option and the --policy-sign option passing in the image signature and the signed policy (which is used to unseal image verification public key from the TPM).  Note the hash of the policy public key is stored in the image partition which is used to locate the corresponding policy within the TPM NVM.

```
$ tools/preseal/sign private-key.raw test-app/image_v1_digest.bin
Signing the digest
Image Signature: image-signature.raw

$ tools/keytools/sign --ecc256 --sha256 --manual-sign --policy-signed test-app/image.bin policy-public-key.raw 1 image-signature.raw policy-signed.raw
wolfBoot KeyTools (Compiled C version)
wolfBoot version 10F0000
Update type:          Firmware
Input image:          test-app/image.bin
Selected cipher:      ECC256
Selected hash  :      SHA256
Public key:           policy-public-key.raw
Output  image:        test-app/image_v1_signed.bin
Target partition id : 1 
ECC256 public key detected
Calculating SHA256 digest...
Opening signature file image-signature.raw
Opening signature file policy-signed.raw
Output image(s) successfully created.
```
With both the wolfBoot and image partitions created, assemble them into a factory programmable image factory.bin using tools/bin-assemble/bin-assemble.  Note the offsets listed on the command line correspond to the partition addresses specified in the configuration file:

```
$ tools/bin-assemble/bin-assemble factory.bin 0x20020000 wolfboot.bin 0x20040000 test-app/image_v1_signed.bin
	Added        79128 bytes at 0x20020000 from wolfboot.bin
	Added        51944 bytes of 0xff fill
	Added         3200 bytes at 0x20040000 from test-app/image_v1_signed.bin
```

Lastly, the policy and the image verification public key needs to be sealed to the target TPM using the policy public key, the signed policy, and the image digest. Note that the previous commands could be run from a seperate system, but the tools/preseal/preseal command must be run on a system connected to the TPM.  The keystore NV index (25166336), policy NV index (25166337), and PCR number (16) here must match the values specified in the configuration file:

```
$ tools/preseal/preseal public-key.raw policy-public-key.raw policy-signed.raw test-app/image_v1_digest.bin 25166336 25166337 16
```

Using the corresponding flash programming tool, write the factory programmable image (factory.bin) to the corresponding offset (0x200020000 in this example) in the target's non-volatile memory and boot the target to test.

If you need to seal keys to target system with no filesystem you can compile preseal with the following environment variables (updated to match the hex values of the corresponding files) and run it without arguments:

```
$ NO_FILESYSTEM=1 PUBKEY="c46f95fab07b0ad2412f4b18ba14c37314feb058f106a0c21728985cd1636db9f5b73a477da4f552c1470f8c83769981f33e23ec772a2582f82ea765b221d417" POLICY_PUBKEY="925a8a35dbe4bd419a35fbf9bd30ce1440380f6d3bcd9bc5558c1fa8adb88d92c88b797dfca39af80ca9729c61508813df8254575cef48674071cf75c30e6aa8" POLICY_SIGNED="4BDAC51C517C0F3D8EDBB632B514262C256E289565A2F1CD8605A4F775302C0CD7BBFE0242CAA536A30C87A37756C390DB9A2B06037B15476A509CA06B857B6D" IMAGE_DIGEST="5b09b05afaf98e43fd59c0dc286fca8337604ec0815caad09fc0784c8a5e692b" SEAL_NV_INDEX=25166336 POLICY_DIGEST_NV_INDEX=25166337 PCR_INDEX=16 make

# Then on the target system, run the resulting binary: ./preseal
```

## NOTE: the PolicySigned key is used in place of the real signing key and acts as an intermediate key to unseal the actual signing key form the TPM
