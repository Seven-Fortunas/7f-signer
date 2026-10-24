# 7F Signer

**The post-quantum, air-gapped signer for the keys that must not move.**

7F Signer is Seven Fortunas's extension of [SeedSigner](https://seedsigner.com/), the open-source air-gapped signing device, with post-quantum ML-DSA-65 signatures (NIST FIPS 204). It holds the keys at the top of [7fchain](https://github.com/Seven-Fortunas/7fchain)'s certificate chain, and it is built for any organization whose keys authorize chains, certificates or other people's money.

## Built to refuse

The largest custody thefts did not break the cryptography. The attacker reached the system in front of the signer, and the signer signed what it was shown. 7F Signer is designed so that an attacker who controls everything in front of it still cannot get a signature it was not built to give.

- **It signs only what it was built to sign.** A fixed list of operations, each bound to its own key by the operation itself, never by an option the caller supplies. There is no "sign this hash".
- **It shows what you are approving, in words.** Every request is parsed and shown as fields: which chain, which dates, which recipient, how much, and the fee. A digest and the device's key identifier let the holder confirm the request with their coordinator.
- **It refuses the unexpected.** An unknown request is rejected outright, and risk is shown, not buried.

## Stores nothing, connects to nothing

- **No network.** Data goes in and out only as QR codes, through the camera and the screen. Production units run no network software, units for the most critical keys carry no working radio, and a tripwire wipes the keys and halts if a radio or USB device appears.
- **Nothing at rest.** The device boots into memory. Keys come from the holder's own phrase and are gone when the power is off, so there is nothing to extract from a unit that is switched off.
- **Entropy you can check.** Dice rolls become the 24-word phrase, and the holder can repeat the conversion offline. For the most important keys, a second, independently built 7F Signer confirms the keys before they are used.
- **Proven against the chain.** Before every release, 7fchain's own tools check that the device derives and signs exactly as 7fchain does.

## Quorums, not single points of failure

A quorum of 7F Signers holds the cold authority: several holders, each with a device and a phrase, and a set number must agree. Devices cost little enough for every holder to own one and are simple enough to explain to an auditor in a paragraph. On 7fchain, the Root keys at the top of the certificate chain are held on 7F Signers by separate holders.

## Assurance you can verify yourself

- **Reproducible, signed images:** independent builders produce the same image, and customers can rebuild it themselves.
- **Secure boot:** the board runs only an image signed with the customer's own boot key.
- **Inspection and your own seal:** each unit is checked against a published reference and boards bought at retail, then sealed by the customer.
- **Witnessed ceremonies:** keys are made and used to a written procedure, with what each signer must see set in advance.
- **Off-the-shelf boards:** public part numbers that anyone can buy and compare.

## For every tier of key

| Tier | Keys |
|---|---|
| **Sovereign** | Defense and government keys |
| **Systemic** | Keys that govern a chain or other people's money: Roots, development funds, Layer 2 federations, token issuers |
| **Institutional** | Treasuries, certificate registrars, Layer 2 partners |
| **Individual** | People and small teams, for example two of three devices |

Beyond 7fchain, the same phrase signs for Ethereum, Optimism and Base at separate key paths, so a treasury keeps reserves and operating balances under one discipline.

## Services

The device is the easy part; knowing what to do with it is the product. Seven Fortunas provides key ceremonies, quorum and key-policy design, training, inspection and self-build support, audit support and post-quantum migration advice.

## Contact

Maintained by Seven Fortunas. For questions, open an issue on this repository or write to build@sevenfortunas.com. The firmware and ceremony tools are not published here. Security reports: security@sevenfortunas.com.
