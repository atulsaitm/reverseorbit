# crackme-easy-1

This documents how `crackme-easy-1.exe` was cracked, first with basic CLI tools and then again with `radare2`.

## Result

- Target: `crackme-easy-1.exe`
- Patched output: `crackme-easy-1-r2patched.exe`
- Known-good reference: `crackme-easy-1-cracked.exe`
- Matching SHA-256:

```text
445d2150d8cc7f66692533c58325999c973a05fc61a5175eb503d3d52a33b022
```

## What was patched

The crack is a straight conditional-jump patch:

- Virtual address: `0x40104b`
- File offset: `0x44b`
- Original bytes: `75 07`
- Patched bytes: `90 90`

That changes:

```asm
cmp eax, 0x54a337
jne 0x401054
```

into:

```asm
cmp eax, 0x54a337
nop
nop
```

So the program always falls through to the success message.

## Workflow 1: CLI tools

### 1. Identify the binary

```bash
file crackme-easy-1.exe
sha256sum crackme-easy-1.exe crackme-easy-1-cracked.exe
```

### 2. Pull strings

```bash
strings -n 4 crackme-easy-1.exe
```

Relevant strings:

```text
--- Crackme ! ---
Password :
Good cracker !
Submit your solution !
Bad password ! Try again !
```

### 3. Compare original vs cracked sample

```bash
cmp -l crackme-easy-1.exe crackme-easy-1-cracked.exe
```

Output:

```text
1100 165 220
1101   7 220
```

This means:

- offset `1099` / `0x44b`: `0x75 -> 0x90`
- offset `1100` / `0x44c`: `0x07 -> 0x90`

### 4. Disassemble around the changed bytes

```bash
objdump -D -Mintel --start-address=0x401020 --stop-address=0x401080 crackme-easy-1.exe
xxd -g 1 -l 64 -s 0x440 crackme-easy-1.exe
xxd -g 1 -l 64 -s 0x440 crackme-easy-1-cracked.exe
```

Relevant disassembly:

```asm
401041: call 0x401090
401046: cmp eax, 0x54a337
40104b: jne 0x401054
40104d: push 0x402114    ; "Good cracker !"
401052: jmp 0x401059
401054: push 0x402140    ; "Bad password ! Try again !"
```

### 5. Patch manually

```bash
cp crackme-easy-1.exe crackme-easy-1-mycrack.exe
printf '\x90\x90' | dd of=crackme-easy-1-mycrack.exe bs=1 seek=1099 conv=notrunc
```

### 6. Verify

```bash
sha256sum crackme-easy-1-mycrack.exe crackme-easy-1-cracked.exe
cmp -l crackme-easy-1-mycrack.exe crackme-easy-1-cracked.exe
```

Both patched files matched exactly.

## Workflow 2: radare2

### 1. Inspect strings

```bash
r2 -q -e scr.color=0 -e bin.relocs.apply=true -c 'aa; izz~Password' crackme-easy-1.exe
r2 -q -e scr.color=0 -e bin.relocs.apply=true -c 'aa; izz~Good cracker' crackme-easy-1.exe
r2 -q -e scr.color=0 -e bin.relocs.apply=true -c 'aa; izz~Bad password' crackme-easy-1.exe
```

Expected hits:

```text
0x00402108  Password :
0x00402114  Good cracker ! / Submit your solution !
0x00402140  Bad password ! Try again !
```

### 2. Locate the compare and branch

Search for the compare immediate plus jump bytes:

```bash
r2 -q -e scr.color=0 -e bin.relocs.apply=true -c 'aa; /x 3d37a354007507' crackme-easy-1.exe
```

Expected hit:

```text
0x00401046 hit0_0 3d37a354007507
```

### 3. Disassemble the check

```bash
r2 -q -e scr.color=0 -e bin.relocs.apply=true -c 'aa; s 0x401020; pd 24' crackme-easy-1.exe
```

Key block:

```asm
0x00401041      e84a000000     call 0x401090
0x00401046      3d37a35400     cmp eax, 0x54a337
0x0040104b      7507           jne 0x401054
0x0040104d      6814214000     push ... ; success string
0x00401054      6840214000     push ... ; failure string
```

### 4. Inspect the hash routine

```bash
r2 -q -e scr.color=0 -e bin.relocs.apply=true -c 'aa; s 0x401090; pdf' crackme-easy-1.exe
```

That function computes a rolling value and returns it in `eax`, then the caller compares it to `0x54a337`.

The core logic is:

```text
d = (byte + (d << 6)) % 10000000
```

A separate solver can be used against that routine to recover a valid input. One valid password for the unpatched binary is:

```text
:Rew
```

### 5. Patch with radare2

Create a writable copy:

```bash
cp crackme-easy-1.exe crackme-easy-1-r2patched.exe
```

Apply the patch interactively in one command:

```bash
r2 -q -e bin.relocs.apply=true -w -c 's 0x40104b; wx 9090; q' crackme-easy-1-r2patched.exe
```

Or use the included script:

```bash
r2 -q -e bin.relocs.apply=true -w -i patch_crackme_easy_1.r2 crackme-easy-1-r2patched.exe
```

Contents of `patch_crackme_easy_1.r2`:

```text
s 0x40104b
wx 9090
q
```

### 6. Verify with radare2 tools and hashes

Show the changed bytes:

```bash
r2 -q -e scr.color=0 -c 's 0x40104b; px 2' crackme-easy-1-r2patched.exe
```

Expected output:

```text
0x0040104b  9090  ..
```

Compare original vs patched:

```bash
cmp -l crackme-easy-1.exe crackme-easy-1-r2patched.exe
radiff2 -x crackme-easy-1.exe crackme-easy-1-r2patched.exe
sha256sum crackme-easy-1-r2patched.exe crackme-easy-1-cracked.exe
```

The only meaningful difference is the `75 07 -> 90 90` patch, and the patched output matches the provided cracked sample exactly.

## Files created

- `patch_crackme_easy_1.sh`
- `patch_crackme_easy_1.r2`
- `crackme-easy-1-mycrack.exe`
- `crackme-easy-1-r2patched.exe`
