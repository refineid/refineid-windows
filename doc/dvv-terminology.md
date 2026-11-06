# DVV terminology

Code identifiers use universal PKI terms; user-facing strings (WinUI
resources, Win32 labels, CLI and error messages) use DVV's vocabulary.

## Pairing

Pairing is *yhdistäminen*, and its code is the *yhdistämiskoodi*.
*Paritus*, *pariliitos* and *laitepari* are not used. A pairing the
holder breaks is a broken pairing (*rikottu yhdistäminen*), never a
*paritus*.

## Revocation

Revocation-list evidence is labelled *sulkulista*; a revoked state is
*mitätöity* and its time the *mitätöintiaika*.

## Activation PIN

The credential in DVV's activation letter takes DVV's official name
from the letters, under both activation schemes of FINEID S4-1 v4.2
§4.6 (the §4.6.1 scheme, where the letter's code is the PUK, and the
§4.6.2 scheme, where both PINs ship preset to it):

| English        | suomi                | svenska                                   |
|----------------|----------------------|-------------------------------------------|
| Activation PIN | aktivointitunnusluku | aktiveringskod (definite aktiveringskoden) |

The organisation card letter reads "Aktivointitunnusluku /
Aktiveringskod / Activation PIN". User-facing text never says
"activation code". Code identifiers such as `ActivationCode` keep
their names.
