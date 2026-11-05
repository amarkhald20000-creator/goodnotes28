# GNUnlock v28

An iOS dylib for **Goodnotes 7.1.34** (`com.goodnotesapp.x`), injected with LC Sign.

Two jobs, in this order:

1. **Find out what actually kills the launch** — and stop guessing.
2. **Unlock the paid tier** — without ever writing executable memory.

No Theos, no CydiaSubstrate, no external dependencies.

---

## v28: the crash leaves the dylib behind and becomes a packaging question

v27's log closed the runtime investigation with one number:

```
CKPersona.launch: 0 slot(s) hold the address and none could be redirected
```

Zero import slots. The call from `CKPersona.launch` into `objc_exception_throw`
is a direct branch into the dyld shared cache, so the trampoline was never
entered, `FORCED SWALLOW` never printed, and no data-only mechanism in this repo
could ever have reached it. That is not a bug in the slot walker; it is the slot
walker correctly reporting that there is nothing there to redirect. The nine
releases of interposition machinery were aimed at a layer the call does not pass
through.

So this version stops adding interception and changes the input instead: the
entitlements that CloudKit reads, before the app runs.

### One correction that changes what the fix has to be

The request was to strip the four iCloud keys out of
`Payload/Goodnotes.app/archived-expanded-entitlements.xcent`. That is worth
doing, and `tools/ipa_icloud_strip.py` does it. But it is not, by itself, the
fix, and believing it is would cost another device round-trip:

**`archived-expanded-entitlements.xcent` is a build artefact.** It is written
into the bundle by the archiver after signing. It is not part of the code
signature, and it is not what the kernel or CloudKit reads. What CloudKit reads
is the entitlements blob inside the main executable's `LC_CODE_SIGNATURE`
(`SuperBlob` -> `CSSLOT_ENTITLEMENTS`), which is produced by whoever signs the
binary — LC Sign, in this pipeline.

So there are two candidates for where `"*"` came from, and they need different
answers:

| Where the four keys live | What removes them |
|---|---|
| In the bundle's `.xcent`, because the signer imports it as its default entitlements | `strip` — the file is gone, so it cannot be imported |
| In the signature, because the signer generates entitlements itself | nothing in the IPA; the signer has to be given a different entitlements file, or a profile with no iCloud capability |

The second row is the one that cannot be fixed by editing a file in the archive,
and it is the one that would have looked identical from the outside. Hence
`inspect`: it reads the entitlements out of the code signature and says which
row you are in, in one line, on any machine, without an iPad.

```
$ python3 tools/ipa_icloud_strip.py inspect Goodnotes-NoiCloud-signed.ipa
signature: 9 entitlement(s) in Payload/Goodnotes.app/Goodnotes
  PRESENT  com.apple.developer.icloud-services = '*' (str)
  absent   com.apple.developer.icloud-container-identifiers
  ...
VERDICT: the four keys are IN THE SIGNATURE. Whatever the bundle's xcent files
say, this is what CloudKit will read.
And 1 of them are the wrong type: com.apple.developer.icloud-services
```

That last line is the v13 crash report, reproduced locally, from the file
instead of from a device. `"*"` is a string; `com.apple.developer.icloud-services`
is required to be an array of strings. The type check knows which keys demand an
array, so it is not a heuristic that happens to pass `"*"`.

### What the tool does, and the one design decision that matters

Asked for "unzip, edit, repackage". It does not unpack. Repackaging from a
directory is where re-signing tools break apps, and every one of those failures
is silent at build time and fatal at install time:

* mode bits — a repack from disk gives every member 0644 and the main executable
  stops being executable;
* symlinks — a link extracts as a copy of its target;
* Unicode — APFS stores names decomposed and compares them normalized, so a
  `.lproj` directory written back with different normalization is a different
  name to the bundle's own lookup;
* case — the default macOS volume is case-insensitive, so two members differing
  only in case collide on extract and one is lost.

Instead the archive is read entry by entry and written entry by entry with a
copy of each `ZipInfo` — same name, `date_time`, `external_attr`, `create_system`,
`compress_type`, same order. Untouched members are streamed through. Nothing is
written to the filesystem at any point, and the output is written to a temporary
file and renamed only after verification, so a failed run leaves nothing that
looks like a finished IPA.

Then it checks its own output, because "it produced a file" is not evidence:

* `testzip()` — every CRC in the output archive;
* the member list and its order, against the source;
* CRC-32 and size of every member it did not touch;
* mode bits and symlink flags, member by member;
* SHA-256 of the main executable, before and after — it must be identical;
* every edited plist: none of the four keys, no key lost that was not one of the
  four, no key gained, every other value unchanged.

Failures fail rather than produce something. An `.xcent` that does not parse
stops the run with exit 2 and no output, because half-stripped looks finished. A
truncated zip is rejected the same way. An IPA with nothing to strip exits 3 and
does not copy a gigabyte to say so.

`--selftest` builds synthetic archives and asserts all of the above, plus the
three failure modes above, plus the type check that v13's crash report needed.
It runs in the `lint` job on every push.

### Using it

Local:

```
python3 tools/ipa_icloud_strip.py strip in.ipa -o Goodnotes-NoiCloud.ipa \
        --report strip-report.json --entitlements-out NoiCloud.entitlements
```

`--entitlements-out` writes a signing template with the four keys absent, taken
from `embedded.mobileprovision` when the bundle carries one — that is the set the
profile actually grants, which is the set a signature is allowed to declare —
and from the signature otherwise. If LC Sign offers a choice of entitlements
file, that is the file to give it.

In Actions, two manual runs:

1. `ipa_url` = the decrypted IPA. Produces `Goodnotes-NoiCloud.ipa`,
   `NoiCloud.entitlements`, and a report with the SHA-256 of both input and
   output. Sign that with LC Sign.
2. `signed_ipa_url` = the IPA LC Sign returned. Runs `inspect` and **fails the
   job** while the four keys are still in the signature, with the offending key
   and its type in the error message. This is the gate; run it before installing
   anything.

### What this does not do, and what the next log answers

It cannot remove an entitlement that is already inside a signature — that is not
a file, it is a signature, and only signing changes it. If step 2 above fails,
the signer is supplying the keys and the answer is `NoiCloud.entitlements` or a
profile without the iCloud capability, not another edit to the archive.

It also cannot promise that the launch stops crashing, because the exception was
never the only thing on that path. With the four keys absent the entitlement read
cannot produce the *malformed* throw — that one is a type error and the type is
gone — but `CKPersona.launch` still runs, and what it does with no iCloud
services is unobserved. Two outcomes, and the log distinguishes them:

| Next log | Meaning | Next move |
|---|---|---|
| app launches | the throw was the entitlement read, and it is gone | unlock tier; the dylib is no longer needed for launch |
| a `CKException` again, with a *different* reason string | CloudKit is unhappy about the absence rather than the shape | data-only: `Hooks.Defaults.Overrides` to force the app's own sync preference off, so the sync path is never entered |
| no `throw-interpose:` and no `CKException`, but a hang | the launch is waiting on something that used to fail fast | `xpc-gate` lines will say which connection |

### What was verified

* `tools/ipa_icloud_strip.py --selftest` — 36 checks, all passing, including the
  three refusal paths and the type check.
* The rewrite against a 450 MB archive: one member changed, two untouched
  members CRC-identical, main binary byte-identical, 1.7 s, peak RSS 35 MB.
  (It was 480 MB before the signature read was switched from "load the binary"
  to "seek to the blob"; that is the kind of number a 1 GB bundle makes
  expensive, so it is fixed rather than noted.)
* The Mach-O reader against v27's own `GNUnlock.dylib`: both fat slices
  enumerated at 0x4000 / 0x58000, 21 load commands each.
* The rest of the tree, unchanged: 83 plist keys / ConfigVersion 27, 41 plist
  mutations, 101 invariants with 101 mutations caught, the four host C tests,
  `gnstatic` selftest, `rebind_lint`, `rebind_decoder_test`.
* Diff against the v27 archive: 77 files identical, `src/` and `config/` not
  touched at all. **The dylib in this release is byte-identical to v27's.** Only
  the workflow changed.

### What was not verified

Any real IPA. This machine has no GoodNotes bundle and no Apple signature, so the
fixtures are synthetic: a hand-built arm64 Mach-O carrying a hand-built SuperBlob.
That exercises the parser and the rewriter, and it does not exercise a real
App Store archive whose member list is 20,000 entries long. Run `inspect` on the
IPA you have — it reads, it changes nothing — and it will tell you immediately
whether the parser agrees with a real signature.


## v27: two numbers, and the reading that decides whether they are numbers at all

v26 answered one question: does the throw reach this dylib. v27 answers the other
half of the same launch — does the symbol layer have anything to aim at — and it
does it with two integers taken off a crash report instead of another rebuild of
the mechanism.

**Where the numbers came from, and the arithmetic**

```
CrashReport-14C42871-1D82-4C0E-91DF-A9C2F2149AEE.json
usedImages[CloudKit].image_addr = 7278968832        (0x1B1DC4000)

frame 13  CKPersona.launch              7279034588   - base = 65756    = 0x100DC
frame 21  CKMainBundleIsAppleExecutable 7279271752   - base = 302920   = 0x49F48
```

Both now sit in `CloudKitSymbolOffsets`, keyed by the labels the resolver reads —
`CKPersona.launch` and `CKMainBundleIsAppleExecutable`, not the mangled names.
`CloudKitSymbolOffsetKind` stays `interior`: these are the addresses a crash log
prints for a frame, and `LC_FUNCTION_STARTS` is what turns one into the entry a
caller would bind.

One correction is worth keeping, because it will bite the next person who does
this by hand: 7278968832 is **0x1B1DC4000**, not `0x1B1DD0000`. The offsets above
are right — they came from the decimal subtraction — but anyone who anchors on
that hex string and subtracts in hex lands one segment half off, inside the
neighbouring function, which is a resolved address the slot walk then matches
nothing against. Decimal base, or the hex that actually matches it.

**The second change: the reading is no longer a bet**

A number relative to an image base has exactly two readings, and a crash report
does not say which one it printed. v25/v26 treated `interior` as an assumption and
**returned** when the walk could not find a function start — which means a
mismatched kind (or a cache image without `LC_FUNCTION_STARTS`) burned a whole
device launch on a one-word mistake.

v27 uses the other reading instead of giving up:

```
CKPersona.launch: offset 0x100dc is interior, and the entry it belongs to could not
be found (no function start at or below that offset) - reading the same number as an
entry instead
CKPersona.launch: offset 0x100dc (entry, fallback) -> 0x1b1de00dc in 'CloudKit'
```

That fallback is safe by construction: a number that already *is* an entry survives
it unchanged, and a number that is not an entry resolves to an address no slot
holds, so the walk matches zero and writes nothing. The cost of guessing wrong is
now a log line, not a relaunch.

**What the next log should say, in order**

```
symbol-quarantine: gate ON, slot rewriting ON, 2 entr(y|ies), image 'CloudKit', offsets interior
throw-interpose: installed
...
CKPersona.launch: is not exported by any image in this process (RTLD_DEFAULT, RTLD_NEXT and a CloudKit handle all answered NULL)
CKPersona.launch: 'CloudKit' is not loaded yet, and the offset is relative to it. Resolution moves to the add-image callback ...
waiting for 'CloudKit' to load; 2 slot walk(s) will run when it does
CloudKit loaded (.../CloudKit.framework/CloudKit) - resolving the entries that were waiting for it
CKPersona.launch: offset 0x100dc (interior) -> entry 0x..., N byte(s) into the function per LC_FUNCTION_STARTS
CKPersona.launch: M slot(s) hold the address and none could be redirected - every caller reaches it by direct branch inside its own image ...
trampoline:   decision: name=in-list image=in-scope force=on nil=yes used=0/4 -> swallow
trampoline: FORCED SWALLOW #1 ...
```

The line that matters most is the slot count, and it is the one that can actually
change the outcome rather than the diagnosis:

| what the walk says | what it means |
|---|---|
| `0 slot(s) hold the address` (or `M slot(s) ... none could be redirected`) | CloudKit reaches both functions by direct branch, as predicted. The forced swallow is the only layer left, exactly as v26 |
| `1 slot(s) redirected` on `CKMainBundleIsAppleExecutable` | this is the one that could *remove* the exception instead of swallowing it: the function decides whether the main bundle is Apple's own, and Apple's binaries skip the provisioning-entitlement path CloudKit is rejecting this bundle on |
| `1 slot(s) redirected` on `CKPersona.launch` | the getter itself answers nil for every caller — the `dispatch_once` body never runs and there is no CKException to swallow at all |

**What could make these two numbers wrong, stated once**

1. **A different CloudKit build.** These offsets are per OS build. A system update
   moves them, and the log then says `-> entry 0x...` with an address that looks
   plausible and matches nothing. Re-derive from the next `.ips`; do not carry
   these numbers across an update.
2. **A plist on the device.** `GNConfig()` merges with `addEntriesFromDictionary:`,
   which replaces a top-level key **wholesale** — so a `GNUnlock.plist` in the app
   bundle or in `Documents` that contains `CloudKitSymbolOffsets` replaces this
   whole dict, including an empty one. If `config: bundle override loaded` or
   `config: Documents override loaded` appears in the log, delete that file, or
   copy both keys into it.
3. **Nothing else.** The kind, the image name and the labels are all in the log on
   the first two lines, so a number that is wrong for any other reason says so.

**What was verified here, and what was not**

Verified: `plist_expect` (83 keys, `ConfigVersion` 27, 41 mutations caught,
including four new ones for the offset table — emptied, non-hex, zero, missing
label), `v12_lint` (101 invariants, 101 mutations caught, two of them moved to the
new version and one new rule for the fallback), every source compiled to an arm64
object through `stubcheck.sh`, the function-start walker (20 checks), the slot
walker (50 checks), the repair policy (664 checks), the ladder (7 mutations), the
rebind decoder, `gnstatic.py selftest`, and the baked blob decoded back out of
`GNBakedConfig.h` to confirm all three facts survive baking:

```
ConfigVersion 27 · ThrowSwallowForce True · ThrowSwallowReturnNil True
CloudKitSymbolOffsets {CKPersona.launch: 0x100DC, CKMainBundleIsAppleExecutable: 0x49F48}
```

Not verified: the link and the launch. No OS here runs CloudKit's 7.1.34-era cache,
so the only place these two numbers can be checked against the image they name is
your iPad. If `offset 0x100dc (interior) -> entry` prints an address, the walk
found the function and the numbers are right for this OS build. If it prints the
fallback line instead, the numbers are still usable but the function-start table
is the thing to look at next.

---
## v26: the last move in this mechanism, and the one line that says whether it ran

The v25 device log closed the last open question in the symbol path:

```
throw-interpose: installed
symbol-quarantine: gate ON
cloudkit-stub: installed
trampoline: swallow-at-site ON (budget 4, images CloudKit)
...
12  libobjc.A.dylib  objc_exception_throw + 448
13  CloudKit         $sSo9CKPersonaC8CloudKitE6launchABSgvgZ + 592
...
21  CloudKit         CKMainBundleIsAppleExecutable + 60
```

Three mechanisms armed, the throw still leaves the process, and the site it
leaves from is a **direct branch inside CloudKit**: zero slots hold the address,
`dlsym` cannot see the name, and the shared cache page is Apple-signed so the
instruction cannot be rewritten. There is no proven-return site left to earn a
swallow at. What remains is to *resume the block* and read what the resumed bytes
do — which is what `ThrowSwallowForce` was gated behind, and which is now on.

**What changed, and nothing else**

1. **`ThrowSwallowForce` ships `true`.** A swallow now happens at the CloudKit
   throw site even though the instruction after the call is not a provable
   return. Scoped exactly as before: only for `CloudKitExceptionNames`, only
   inside `ThrowSwallowImages`, never more than `ThrowSwallowBudget` (4) times per
   launch.
2. **`ThrowSwallowReturnNil` ships `true`** — new key, and the reason it exists
   is the return type at that site. `CKPersona.launch` is a Swift static property
   getter returning `Optional<CKPersona>`: zero is `.none`, anything else is a
   pointer the caller will message as a persona. v23 returned the exception
   object, which is pointer shaped, passes a `guard let`, and dies later at an
   address that names nothing. Zero takes the branch CloudKit already has for
   "no persona". Set it to `false` to get v23's value back, for comparison.
3. **One decision line per classified throw**, printed *before* the branch that
   acts on it:

   ```
   trampoline:   decision: name=in-list image=in-scope force=on nil=yes used=0/4 -> swallow
   ```

   This is the v26 fix that is not about forcing anything. In v25 the log was
   silent in two cases that look identical from the outside — an exception name
   outside `CloudKitExceptionNames`, and a spent budget. Both produce no swallow
   and no line, so a launch with force on that dies in the same place reads
   exactly like force never being read. That ambiguity is what this line removes.

**What the next launch can produce — three outcomes, all informative**

| in the log / the crash | what it means |
|---|---|
| `decision: ... -> swallow` then `FORCED SWALLOW #1` and the app keeps running | the resumed bytes ended the block. The throw is gone; whatever CloudKit does next with a nil persona is the next question |
| `FORCED SWALLOW #1` then a crash **at the same address**, `EXC_BREAKPOINT` / `EXC_BAD_INSTRUCTION` instead of `SIGABRT` | the resumed bytes are the compiler's unreachable trap. This mechanism is finished at this site; the next version attacks the caller instead |
| no `decision:` line at all, and no `throw <name>:` line either | the throw never reached this dylib. Force cannot help, and the interpose table is the thing to re-examine |
| `decision: ... name=NOT-in-CloudKitExceptionNames` | the exception is not a `CKException`. Add its name to `CloudKitExceptionNames` — that is a one-key change, not a rebuild of the mechanism |

A fourth possibility deserves naming because it does not look like a crash: the
throw site is inside a `dispatch_once`. A swallowed throw makes the once gate
complete with the nil returned above, so CloudKit may then fail on its own
nil persona instead of on an exception. Budget 4 bounds that to four swallows;
the fifth throw rethrows and the launch dies as it does today.

**Do the shipped defaults reach the device, or does the plist have to be edited**

No edit needed, provided nothing on the device overrides it. `GNConfig()` merges
in this order, later winning:

```
baked at build time  <-  app bundle GNUnlock.plist  <-  Documents/GNUnlock.plist  <-  ExperimentLadder
```

So a `GNUnlock.plist` placed inside the app bundle (LC Sign / IPA) or in
GoodNotes' `Documents` folder overrides the baked value **for the keys it
contains**. The log says which files were consulted:

```
config: baked plist loaded (83 top-level keys)
config: bundle override loaded (...)
config: Documents override loaded
```

If the second or third line appears and `ThrowSwallowForce` is in that file, that
file decides. Either delete it, or write the two keys into it:

```xml
<key>ThrowSwallowForce</key><true/>
<key>ThrowSwallowReturnNil</key><true/>
```

**What was verified here, and what was not**

Verified: `scripts/plist_expect.py` (83 keys, `ConfigVersion` 26), the 100 lint
invariants and all 100 mutations, `stubcheck.sh` compiling every source to an
arm64 object, the repair-policy test (664 checks), the function-start walker
(20 checks, 3 of 3 selfcheck), the slot walker, the ladder test, both v11 rules,
the rebind decoder, and the baked blob decoded back out of `GNBakedConfig.h` to
confirm `ThrowSwallowForce = true` survives baking.

Not verified: the link and the launch. This machine has no Xcode, no iOS SDK and
no GoodNotes, so the macOS job is the first real compile and the iPad is the
first real launch. Every claim above about what a swallow *does* is read off the
source and the crash log, not observed.

---

## v25: the linker was right, and the link-time table was the wrong idea

v24 did not link. Not a lint rule, not a plist value — the linker itself:

```
Undefined symbols for architecture arm64:
  "static (extension in CloudKit):__C.CKPersona.launch.getter : __C.CKPersona?"
      referenced from _GNCloudKitPersonaLaunchReplaced in GNCloudKitSymbolQuarantine.o
  "_CKMainBundleIsAppleExecutable"
      referenced from _GNCloudKitMainBundleIsAppleReplaced
ld: symbol(s) not found for architecture arm64
```

`weak_import` never had a chance to help. A weak import still has to name
something the linker can *recognise*; neither of these names is in CloudKit's
`.tbd`, so there was nothing to weaken. That is the same fact the v23 install log
had been printing at run time — *"is not exported by any image in this process"* —
arriving one stage earlier, as a build failure instead of a log line.

**What changed**

The `__DATA,__interpose` table is gone. There is no `extern`, no asm label, no
section: nothing in `GNCloudKitSymbolQuarantine.m` has to be resolved at link
time. An address now comes from two sources, tried in order, and the log says
which one answered:

1. **dlsym** — `RTLD_DEFAULT`, `RTLD_NEXT`, then a `RTLD_NOLOAD` handle on
   CloudKit. Expected to answer NULL here, for exactly the reason the link failed,
   and measured rather than assumed either way.
2. **The offset a crash log prints.** A `.ips` frame gives an *interior* offset
   (`CKPersona.launch + 592`) and the image carries its function entries, unnamed,
   in `LC_FUNCTION_STARTS`. Walking that ULEB128 delta list and keeping the last
   start at or below the offset turns the frame into the entry a caller would bind.
   `src/GNFunctionStarts.h` is that walk: no Apple headers, no Foundation, and
   executed by `scripts/functionstarts_test.c` on the host.

The address then goes to the v16 import-slot walker (`GNSlotRebindAddress`), which
rewrites every slot in the process that holds it. Data pages only — nothing here
can trip the amfid check that killed v5.

**The boundary, stated once**

A slot rewrite reaches *bindings*. CloudKit calling its own function inside its own
image is a direct branch, and a direct branch has no slot. So the log reports, per
entry: the address, where it came from, how many slots held it, how many were
rewritten. Zero slots is a finished measurement — it says the remaining layer is
the throw-level swallow — not a failure. v15, v17 and v19 each shipped a log where
"armed" read as "reached"; that sentence is the fix.

**Two things that had to be right, and were easy to get wrong**

*CloudKit is usually not loaded yet.* GoodNotes links it lazily, and the crash this
targets happens inside CloudKit's own initialisation. A number relative to
CloudKit's load address is meaningless before CloudKit is in the process, so an
entry that cannot resolve at install time is not reported as a failure — it waits,
and a `_dyld_register_func_for_add_image` callback finishes the job when the image
arrives.

*An interior offset is not an entry.* Using `+ 592` as if it were the function
start would point the slot 592 bytes into the function; the first call through it
would run whatever bytes live there. The walk is conservative on purpose: a
truncated, overlong or overflowing delta list answers "no" for an address past the
last entry it managed to read, because the function containing that address may be
one of the entries it never decoded. `--selfcheck` runs the same expectations
against v24's reading and requires them to fail.

**New keys**

```xml
<key>CloudKitSymbolRebind</key><true/>          <!-- false = measure only -->
<key>CloudKitSymbolImage</key><string>CloudKit</string>
<key>CloudKitSymbolOffsets</key>                <!-- empty until you paste one in -->
<dict>
    <key>CKPersona.launch</key><string>0x...</string>
</dict>
<key>CloudKitSymbolOffsetKind</key><string>interior</string>  <!-- or entry -->
```

The offset table ships empty on purpose. Guessing one becomes a rewritten slot
pointing into the middle of a function. Take the number from the last `.ips`:
`threads` gives the frame, `usedImages` gives CloudKit's `base`, and
`base - frame` is the value. The parser accepts `0x` or bare hex and refuses
anything else, including `0`.

### Reading the next log

| Line | Meaning |
|---|---|
| `CKPersona.launch: is not exported by any image in this process` | expected; dlsym answered NULL in all three scopes |
| `... is not loaded yet, and the offset is relative to it` | resolution deferred to the add-image callback |
| `offset 0x250 (interior) -> entry 0x... , 592 byte(s) into the function` | the walk agreed with the crash log's arithmetic |
| `no function start at or below that offset` | wrong offset, or an image whose `LC_FUNCTION_STARTS` was trimmed |
| `CloudKitSymbolOffsets['...'] is not a hex offset` | the parser refused it; nothing was written |
| `N slot(s) hold the address and none could be redirected` | direct branch inside CloudKit — the throw swallow is the only layer left |
| `reached: CKPersona.launch -> nil` | a rewritten slot was actually taken |

### What was verified

* All 29 sources compile to arm64 objects against the stub SDK, the new one
  included, with `-Wall -Wextra` clean.
* `scripts/functionstarts_test.c`: 20 checks — exact entries, interior offsets,
  multi-byte deltas, a three-byte delta, a truncated encoding, an overlong one, an
  overflowing delta, an address below `__TEXT`, a list with no terminator, and the
  exact-hit-before-truncation case. `--selfcheck` fails on v24's reading, as it
  must.
* `v12_lint`: 99 invariants, 99 mutations caught. Eight are new for v25 and each
  one is a defect that would have shipped: a link-time reference coming back, a
  mistyped mangled name, a resolver that skips dlsym, a relaxed offset parser, a
  slot write outside the walker, a log that stops saying "not exported", a
  replacement that ignores its gate, and a replacement that calls itself.
* `plist_expect`: 35 mutations, including the new keys — a non-dictionary offset
  table and an invented `CloudKitSymbolOffsetKind` are both refused.
* `slotwalk` 50 checks, `rebind` decoder, `repair policy` 664, `v11` 7/7.

### What was not verified

The link itself and the device. This machine has no Xcode, no iOS SDK and no
GoodNotes, so "it links" is your Actions job's answer, and "the CKException is
gone" is your iPad's. What can be said here: the two undefined symbols are gone
from the translation unit — there is no reference left to resolve — which is the
one thing v24 could not say.

If the build is green and the log shows `0 slot(s)` for both entries, that is a
result, not a failure: it means CloudKit reaches both by direct branch, and the
next move is `ThrowSwallowForce`, not another interposing layer.

---

## v24: the preflight contradicted itself, and the plist was right

v23 never compiled. The `lint` job died in its second step:

```
AssertionError: ThrowSwallowAtSite must ship false: returning from a noreturn
call site is only survivable where the decoder proves the next instruction is a
return
```

Nothing on the device was at fault. The shipped plist said `true` - that is
what v23 is for - and `scripts/v12_lint.py` had a rule saying it must be `true`
as well. But `.github/workflows/build-dylib.yml` carried a second, handwritten
copy of the same assertion, and that copy still said `false`, because nobody
edited it when the default changed for v23.

Two files, one fact, one release. Neither file was wrong about its own version,
and that is exactly the shape of defect this repository has been deleting since
v12: the launch-guard check used to be a `grep -n` in this workflow, and it
failed a whole round when the code moved. It became a lint rule, mutation
tested. This is the same move, for the same reason.

**What changed**

`scripts/plist_expect.py` now owns every statement about the *shipped* plist,
and the three consumers call it instead of restating the keys:

```
scripts/build.sh                    preflight, before anything compiles
.github/workflows/build-dylib.yml   the "Validate the plist" step
scripts/v12_lint.py                 imports PINNED and CONFIG_VERSION and
                                    requires them to agree with its own rules
```

Two properties are worth naming:

* the workflow's `v12 ships inert` step asserted `ObserveOnly` / `RunLevel` /
  `AutoBisect` / `GuardEnabled` / `ResignFix` a second time. Those assertions
  moved into the same module and that step is gone. One file, one place.
* `--selftest` mutates a copy of the config once per expectation - 30 of them,
  including `ThrowSwallowAtSite` flipped back to `false` and `ThrowSwallowForce`
  flipped to `true` - and requires the check to reject every one. The v23 copy
  was dead weight for an entire release because no test ever flipped the value
  it guarded. A preflight is only worth its runtime if it can fail.

Three new lint rules keep it that way, mutation tested like everything else:

```
plist-expect-single-source   build.sh and the workflows call the module and do
                             not parse the plist themselves; a file that
                             restates a default is a file that goes stale
plist-expect-mirrors-lint    the module's PINNED dict and this lint's own rules
                             must agree key by key - the v23 failure, one
                             release early
plist-expect-version         ConfigVersion equals GN_UNLOCK_VERSION, so no
                             build ships v24 defaults under a v23 log line
```

`ConfigVersion` and `GN_UNLOCK_VERSION` are `24`. That is the whole change to
the dylib.

**What this build does on the device: nothing new.**

The C sources differ from v23 by one string. Every mechanism the v23 section
below describes - the scoped swallow, the forced-swallow opt-in, the symbol
table for `CKPersona.launch` and `CKMainBundleIsAppleExecutable`, the class
quarantine that honestly reports it can see no methods - is byte for byte the
same. The device plan from v23 still stands, and the beacon will say `v24`:

```
GNUnlock v24 beacon - constructor reached
symbol-quarantine: CKPersona.launch is exported (0x...) - ...
trampoline: throw CKException: <the reason, which is the thing worth reading>
trampoline:   site CloudKit + 0x... continuation=...
```

If the reason line is what v23 was built to obtain, this round costs nothing and
answers it. If the crash is still SIGABRT out of a `dispatch_once`, then
`ThrowSwallowForce = true` is the next single-key experiment, and the log names
the resume address before it goes anywhere.

---

## v23: the throw site the stack named

The v22 crash log is the first artifact in this project that names the failing
function instead of naming a framework:

```
12  libobjc.A.dylib  objc_exception_throw + 448
13  CloudKit         $sSo9CKPersonaC8CloudKitE6launchABSgvgZ + 592     (CKPersona.launch)
14  CloudKit         CKContainerEnvironmentString + 456
...
21  CloudKit         CKMainBundleIsAppleExecutable + 60
```

Frame 12 is a thread other than the main one, and frame 13 is a *Swift static
property getter*. Those two facts decide the whole of v23, because between them
they invalidate the two mechanisms v20 through v22 were built on.

### Why the quarantine could never have contained it

`GNCloudKitQuarantine` sweeps **Objective-C method lists**: it looks for
void-returning methods whose selector starts with a work prefix, on classes a
CloudKit image defines. `CKPersona` is a Swift class, so `launch` is not a method
in a method list at all — it is a static property getter, emitted as a plain
mangled C function. `CKMainBundleIsAppleExecutable` is a C function, so it has no
class to hang off either. A wider prefix list, a bigger class filter, another
retry: none of them can put either name in front of that sweep. It was the wrong
surface, not a short list.

So v23 adds the surface that does contain them — a symbol table
(`src/GNCloudKitSymbolQuarantine.m`, two `__DATA,__interpose` tuples, both
`weak_import`) — and then states its boundary in the install log, per entry:

* **exported** → cross-image *bindings* to it are redirected by dyld;
* **not exported** → every caller is inside the CloudKit image by direct branch,
  and no interpose table rewrites a direct branch. The log says so instead of
  reporting "installed".

That last sentence is the whole reason this file is honest about v15/v17/v19: three
versions shipped a log that said "armed" and a crash that said otherwise. Which
callers are cross-image is not something this dylib can know in advance, and it is
not something it should pretend to know afterwards.

### Why the throw is the second, independent lever

An exception thrown inside a `dispatch_once` block cannot be unwound: libdispatch
is C, the C++ unwinder cannot pass through it, and the fallback is `abort()`. That
is exactly the SIGABRT in the v10 log (`objc_exception_throw` →
`_dispatch_once_callout`), and it means "let it throw and catch it further up" is
not an available option here. The throw has to not happen, or it has to not
leave.

v23 therefore turns on the swallow that v20 built and shipped off:

```
ThrowSwallowAtSite = true
```

with two things it never had:

* **scope.** `ThrowSwallowImages` (default `["CloudKit"]`). The swallow only
  fires when the *throwing* function lives in one of those images. Swallowing a
  Foundation exception because it happened to be named `CKException` is not a fix
  for anything.
* **a name filter that was already there and stays there.**
  `CloudKitExceptionNames`, an allow list, not a reason substring.

### The part that is not proven, stated as such

`ThrowSwallowAtSite` only fires where the instruction after the call is provably a
return (`ret`, `b`, `ldp x29,x30,[sp],#n; ret`). At every other site returning
would resume a block the compiler emitted as unreachable — a different crash with
a worse log. The trampoline decodes that instruction and prints it either way:

```
trampoline:   site CloudKit + 0x1f4  continuation=mid-function (0xd503201f, then 0x...)
              -> returning from here would run bytes that are not code
```

If your log says `mid-function` at the `CKPersona.launch` site, the proven subset
will decline to swallow, and the one key that changes that is:

```
ThrowSwallowForce = true
```

Off in the shipped plist on purpose. Forced, it swallows anyway, up to
`ThrowSwallowBudget` times, and logs a `FORCED SWALLOW` line naming the address
the block resumes at. Two outcomes, and the log cannot tell them apart in advance:
the block ends there and the launch continues, or it does not and the next crash
is at that named address. The second is still information — it is the address of
the instruction after the call, which is more than any .ips has given us so far.

### What is in the box

| Piece | What it does | Where |
|---|---|---|
| `GNCloudKitSymbolQuarantine.m` | `CKPersona.launch` → nil, `CKMainBundleIsAppleExecutable` → true, by symbol, with a per-entry "is it exported" measurement | new in v23 |
| `CloudKitQuarantineClasses` | answers a class **by name**, including a Swift class, and reports `0 ObjC-visible methods` when that is the truth | `GNCloudKitQuarantine.m` |
| `ThrowSwallowImages` | image scope for the swallow | `GNThrowTrampoline.m` |
| `ThrowSwallowForce` | the forced swallow, one key, off by default | `GNThrowTrampoline.m` |
| `ThrowSwallowAtSite` | now `true` in the shipped plist | `config/GNUnlock.plist` |

New config keys, all documented in the plist:

```
ThrowSwallowAtSite                     true    proven-return swallow
ThrowSwallowForce                      false   forced swallow (the gamble)
ThrowSwallowImages                     [CloudKit]
CloudKitQuarantineClasses              [CKPersona]
CloudKitSymbolQuarantine               true
CloudKitSymbolQuarantinePersonaLaunch  true
CloudKitSymbolQuarantineMainBundleIsApple   true
CloudKitSymbolQuarantineMainBundleAnswer    true
CloudKitSymbolQuarantineLogBudget      8
```

### Reading the device log

```
symbol-quarantine: 2 entr(y|ies) in __DATA,__interpose; gate ON
symbol-quarantine: CKPersona.launch is exported (0x...) - cross-image bindings
                   will be redirected; a call made *inside* the CloudKit image to
                   its own function stays a direct branch and is not affected
symbol-quarantine: CKMainBundleIsAppleExecutable is exported (0x...) - ...
quarantine: named class CKPersona - 0 instance / 0 class method(s) ObjC-visible (none at all: ...)
throw-interpose: first exception of this launch is arriving through the interpose table
trampoline: throw CKException: <the reason string, which is the next thing to read>
trampoline:   site CloudKit + 0x... continuation=... -> ...
trampoline: SWALLOWED #1 CKException - ...
```

| What you see | What it means |
|---|---|
| `is not exported` for both entries | both names are internal to the CloudKit image; only the throw layer can act, and the log tells you so before the crash does |
| `exported` but no `reached:` line, still crashes | the caller is inside the image; the binding was not the path |
| `reached: CKPersona.launch -> nil` and the launch continues | the persona path was the crash, and it is now a nil persona |
| `NOT swallowed - ... continuation=mid-function` | the proven subset declined; `ThrowSwallowForce = true` is the next experiment, and the address in that line is what the next crash should be compared against |
| `FORCED SWALLOW #1` then a crash at the address in the same line | the resume point was not the end of the block — but now it is named |
| `FORCED SWALLOW #1` and the launch continues | the block ended there; check whether iCloud sync being off is acceptable |
| `trampoline: throw CKException: <reason>` | read the reason. It is the entitlement or the condition, in CloudKit's own words — the thing five versions of hooks could not get out of it |

### Verified here, and not

Verified on this machine:

* every source compiles to an arm64 object against the stub SDK, including the two
  weak `__DATA,__interpose` tuples (`weak_import` checked in the object's symbol
  table: `N_WEAK_REF` set on both);
* `v12_lint` 93 invariants, and 93 mutations — one per rule — all caught, including
  six new ones that pin this version's shape: swallow must be image-scoped,
  swallow must check the name allow list, a forced swallow must not be the shipped
  default, the symbol table must keep both names and `weak_import` and the section,
  the replacements must go through `GNInterposeReal`, and the install must measure
  whether each symbol is exported before claiming anything;
* repair policy 664 checks, slot walk 50 checks, the v11 lint 7/7, `stubcheck`
  rc=0.

Not verified here: a launch on your iPad. This machine has no GoodNotes, no shared
cache, no signature, and no Xcode — so "the CKException is gone" is a claim only
your device can make. And the macOS runner is still the authoritative compile;
`<xpc/connection.h>` cost us a round trip once already.

### Rollback, one key each

```
ThrowSwallowAtSite = false          back to v22 behaviour (rethrown, named in the log)
ThrowSwallowForce  = false (default) never resumes an unproven block
CloudKitSymbolQuarantine = false    both symbols call through, same behaviour plus a frame
CloudKitQuarantineClasses = []      the shape sweep only, as in v22
```


## v21: the layer under the layer

v20 was installed correctly and the log says so:

```
cloudkit-stub: installed (mode=noAccount)
cloudkit-stub: -[GNStubCKDatabase addOperation:] -> ignored, there is no database behind this object
```

and then the same exception, one step later:

```
EXCEPTION name=CKException
  reason=Application has malformed entitlements. Found value "*" for entitlement
         com.apple.developer.icloud-services, expected an array of strings
```

Those two lines together are the most useful pair this project has produced. They
say the replaced Objective-C entry point was **not** the failing one. Something
underneath it is still running, and it is still talking to `cloudd`.

### The three things that were asked for, and what each one actually is

**1. "Hook NSXPCConnection / cloudd and drop the operation."**

Done, but one level lower than the ask, and for a reason worth stating: the reply
is not fabricated. `GNXPCGate` interposes `xpc_connection_create` through
`__DATA,__interpose` (and `xpc_connection_create_mach_service` too, until v22
established that iOS marks that one `unavailable` and it cannot be named at all —
see the v22 section at the end), and when the service name matches CloudKit it
passes a name that has nothing behind it. libxpc then does
what it always does for a dead endpoint: it fails the connection with
`XPC_ERROR_CONNECTION_INVALID`, asynchronously, on the queue the caller asked for.

That is strictly better than intercepting `send_message_with_reply` and calling
the handler with an invented error object, for two reasons:

* the error object has to be a real `xpc_object_t` of type `XPC_TYPE_ERROR`, and
  the cleanest way to get one is to fail a real connection — at which point the
  redirect already exists and the interception is dead weight;
* a handler invoked from inside the send that CloudKit just made breaks an
  assumption CloudKit is entitled to (its completion is not re-entered on the
  stack of the call), which is the same class of mistake v8's delegate wrappers
  made.

`-[NSXPCConnection initWithMachServiceName:options:]` gets the same name
substitution, for the parts of CloudKit that use the Foundation flavour.

**2. "Hook NSException raise again — now it will go through -[NSException raise]."**

It will not. `@throw` never reaches `-[NSException raise]`, and it did not in v19
either; that is why the guard logged nothing. But the underlying idea — intercept
`objc_exception_throw` process-wide — was right, and it is now what the dylib
does. The reason v20 could not is worth keeping in the record:

> v20 installed its trampoline by finding import **slots** holding the function's
> address. Three images had one: Goodnotes, MSAL, CoreUI. CloudKit did not,
> because a slot is a property of the caller's image. A slot-oriented tool has
> nothing to say about a caller that reaches the function another way.

`__DATA,__interpose` is a different mechanism with a different coverage rule: it
is a table dyld reads, and dyld applies it to **every binding in the process**,
shared-cache images included, whether they were loaded before this dylib or after
it. The question "does this image have a slot" stops being asked.

What that buys is not a new trick, it is reach for the v20 logic that was already
written and already correct: every throw is classified, the instruction at the
return address is decoded, and the log says whether returning from there would be
a real return (`ret`, `b`, or a frame pop followed by `ret`) or a jump into bytes
that were never code. Swallowing (`ThrowSwallowAtSite`) fires only where the
decode proves it is survivable, with a budget, and only for the exception names in
`CloudKitExceptionNames`. Default remains off: swallowing means handing the
exception object back to a caller as if it were a return value, which is a lie
that is only safe at a proven return site.

**3. "Use an Info.plist / UserDefaults key to tell GoodNotes to stay off CloudKit."**

The preference key is GoodNotes' own, and guessing it is the same mistake as
guessing a selector — but the goal behind it does not need a key. `GNCloudKitQuarantine`
selects on **shape** instead of on a name:

> on classes defined by a CloudKit image, every **void-returning** method whose
> selector begins with a work verb (`addOperation`, `fetch`, `save`, `delete`,
> `modify`, `perform`, `start`, `request`, `account`, …) gets an empty body, and
> the original is never called.

A void method cannot hand a result back, so dropping its body leaves a stall
rather than a contradiction — and a sync subsystem that never answers is a state
every one of these apps already ships UI for. Methods that return an object are
untouched, because returning `nil` where Swift expects a non-optional `CKDatabase`
is a trap: a worse crash with a worse log, and exactly the trade v20 refused to
make when it built a real subclass instead of a proxy.

This is strictly stronger than a preference toggle: a preference can be ignored by
the code that reads it, while a method with an empty body cannot be.

### The hole v20 left

v20 replaced `+[CKContainer defaultContainer]`, `+[CKContainer containerWithIdentifier:]`
and the accessors — but not the initialisers. So

```objc
[[CKContainer alloc] initWithContainerIdentifier:@"iCloud.com.goodnotesapp.x"]
```

still built a real container and still ran whatever that initialiser runs. v21
replaces `-initWithContainerIdentifier:`, `-initWithContainerID:` and `-init` with
the substitute, retained (`ns_returns_retained`, because ARC does not infer the
init family for a plain C function and the caller would over-release a singleton).

### Order matters, and the constructor enforces it

```
beacon -> probe -> entitlement repair -> slots -> dlsym tap
       -> throw interpose        (reach)
       -> xpc gate               (no daemon conversation)
       -> quarantine             (shape)
       -> cloudkit stub          (the fourteen named answers, last word)
       -> forensics -> guard -> audit
```

The quarantine runs before the stub on the first pass **and** on every retry,
because CloudKit loads lazily: the stub's fourteen answers are better than an
empty body and have to end up as the last word on those selectors.
`scripts/v12_lint.py` holds this as an invariant (`quarantine-before-stub`), so a
future reordering is a lint failure rather than a behaviour change nobody notices.

### What to look for on the device

```
throw-interpose: installed - 1 entr(y|ies) in __DATA,__interpose, coverage is
                 every binding in the process including the dyld shared cache
xpc-gate: installed - 2 C entr(y|ies) in __DATA,__interpose, filter: cloudd, cloudkit, com.apple.ck.
quarantine: neutralised - 12 CloudKit class(es) inspected, 37 method(s) this pass
cloudkit-stub: installed (mode=noAccount)
```

Then, in order of what each outcome means:

| In the log | Means |
|---|---|
| `xpc-gate: CloudKit service 'com.apple.cloudd' -> 'com.zaka.gnunlock.blackhole'` | the connection really was being made; the daemon conversation is now dead |
| `trampoline: throw CKException: Application has malformed entitlements ...` + `site CloudKitCore + 0x… continuation=ret` | the throw site is named **and** it is survivable — turn on `ThrowSwallowAtSite` |
| the same line with `continuation=mid-function` | named but not survivable at that site; the next version needs the caller, not the return |
| `quarantine: no CloudKit classes loaded yet` | CloudKit is not in this process — the crash was never CloudKit's |
| `trampoline: SWALLOWED #1 CKException` | it was returned from at a proven return site; the launch continued |
| no `throw CKException` line at all, and no crash | the gate worked; find out next whether iCloud sync being off is acceptable |

### Config added

| Key | Default | What it does |
|---|---|---|
| `ThrowInterpose` | `true` | the process-wide throw gate. Off means pass-through, not absent — the table is link time and the header says so |
| `XPCGate` | `true` | redirect CloudKit mach services at a name with nothing behind it |
| `XPCGateNSXPC` | `true` | same substitution for `NSXPCConnection` |
| `XPCGateServices` | `cloudd`, `cloudkit`, `com.apple.ck.` | what counts as CloudKit. Narrow on purpose |
| `CloudKitQuarantine` | `true` | shape-selected neutralisation of CloudKit's void work methods |
| `CloudKitQuarantineMode` | `neutralise` | `assert` prints what would be dropped and changes nothing |
| `CloudKitQuarantinePrefixes` | empty | empty means the built-in prefix list |

### What v21 does not claim

* It does not make iCloud work. It makes CloudKit stop asking, and a launch that
  does not ask cannot be refused.
* It cannot prove which of the two hypotheses (operation route / daemon-side check)
  is true — it answers both, so the distinction stops mattering for the launch.
  The throw site in the log will say which one it was, after the fact.
* If `CloudKitQuarantineMode` is `neutralise` and some CloudKit call the app waits
  on synchronously never returns, the symptom becomes a hang, not a crash. Set
  `CloudKitQuarantine: false` to get the pre-v21 behaviour back in one relaunch.
* Nothing here was run on a device. 24 sources compile to arm64; the invariant
  suite, the mutation suite, the repair-policy table and the slot walker all pass;
  the interpose section is verified present in the compiled object. Whether the
  exception is gone is a question only the iPad can answer.

---

## v20: stop asking CloudKit, start answering for it

v19 shipped the cleanest possible measurement and it came back with a result
worth more than the mechanism it was measuring:

```
slot: self-test  plural, direct (dlsym, the real function) : dictionary(1) …=array(1) ["CloudKit"]
slot: self-test  plural, through this dylib's binding      : dictionary(1) …=array(1) ["CloudKit"]
EXCEPTION name=CKException  reason=... Found value "*" for entitlement com.apple.developer.icloud-services ...
slot: 'SecCodeCopySigningInformation' unreachable: 2526 slot section(s), none held its address
```

Both SecTask doors answer `array(1) ["CloudKit"]`. The value CloudKit complains
about is still `"*"`. Those two facts leave exactly one conclusion, and it is not
"one more hook":

**the value CloudKit rejects is not read through any door this dylib can arm.**

Five versions tried to make that check pass. The singular read, the plural read,
the dlsym that resolves them, the signing-information dictionary. Each measured
LIVE. Each left the launch dying identically. Adding a sixth reader is a bet
against a measurement, so v20 stops betting.

### 1. What actually changed: the answer, not the hook

Instead of making iCloud *work*, v20 makes it *unavailable*. That is not a
degradation - it is a state every app already handles, because a device with no
iCloud account exists and GoodNotes ships UI for it. `CKAccountStatusNoAccount`
has a code path in the app. `CKException: malformed entitlements` does not.

The dylib builds a runtime **subclass of the real `CKContainer`**, allocates one
instance with zeroed ivars, and replaces the entry points:

| entry point | answer |
|---|---|
| `+[CKContainer defaultContainer]` | the substitute container |
| `+[CKContainer containerWithIdentifier:]` | the substitute container |
| `-privateCloudDatabase` / `-publicCloudDatabase` / `-sharedCloudDatabase` | the substitute database |
| `-accountStatusWithCompletionHandler:` | `CKAccountStatusNoAccount` |
| `-accountInfoWithCompletionHandler:` | nil info + `CKErrorNotAuthenticated` |
| `-fetchUserRecordIDWithCompletionHandler:` | nil + `CKErrorNotAuthenticated` |
| `-[CKDatabase saveRecord:…]` and the other writes | nil + `CKErrorNotAuthenticated` |
| anything not listed | zeroed return, via the invocation's own signature |

Why a subclass and not a proxy: `isKindOfClass:` and the Swift dynamic cast both
have to keep working. A stub of another class is a different type, and the first
`as? CKContainer` in the app turns into a cast failure instead of a launch.

Zeroed ivars matter too. The instance is created with `class_createInstance`, so
every ivar starts at 0 - not a half-built container whose fields point into a
cache that was never populated.

### 2. The part that is not cosmetic: `dispatch_once`

Every v14-v19 design caught the exception somewhere above CloudKit's initialisation
path and returned a fallback value. That leaves a landmine, and it is worth stating
plainly because it is the reason the design changed:

CloudKit validates inside a `dispatch_once`. An ObjC exception thrown out of that
block unwinds straight past `_dispatch_once_callout` - which has no landing pad -
so the once gate stays **owned by this thread**. The block never completed, the
gate never broadcast. The next call to the same `dispatch_once` from this thread
takes the slow path, sees the gate owned by itself, and faults with
`dispatch_once() called recursively`.

So catching converts one named `CKException` into one unnamed libdispatch fault,
later, further away, with no exception record. **Replacing the entry point never
enters the block**, so the gate is never touched and there is nothing to re-enter.
That is the whole reason this is a substitution and not an `@try`.

### 3. `SecCodeCopySigningInformation`: measured, not hooked

The request was to fishhook the CloudKit image, or inline-hook the function. Both
were considered and neither is the right instrument:

- **fishhook** rewrites import slots. CloudKit has no slot holding that address -
  2526 slot sections walked, zero matches, in the same pass that found 3 slots for
  `objc_exception_throw`. There is nothing to rebind.
- **MSHookFunction / inline patch** writes the first instructions of the function.
  That is a code page. On a Distribution signature the page loses its signature and
  amfi kills the task on the next fetch - this project already paid for that lesson
  once (`CODESIGNING / Failed to fault in a page with execute permissions`).

v20 does the thing that can be measured instead. `EntitlementReadSurface` sweeps
**fourteen** public entitlement doors after launch - `SecTaskCreateFromSelf`,
`SecTaskCreateWithAuditToken`, `SecCodeCopySelf`, `SecCodeCopyGuestWithAttributes`,
`SecStaticCodeCreateWithPath`, `SecCodeCheckValidity`, `xpc_copy_entitlement_for_self`,
`xpc_copy_entitlement_for_token`, and the ones already known - and prints, per
symbol, whether this process has it and how many import slots hold its address.
Counted, never rewritten.

```
reads:   SecTaskCopyValueForEntitlement          0x…  1 slot(s) in 2526 section(s) - callers go through an import slot
reads:   SecCodeCopySigningInformation           absent  - no image in this process exports it
reads:   xpc_copy_entitlement_for_self           0x…  0 slot(s) in 2526 section(s) - no caller reaches it through a slot
```

A symbol that is *absent* cannot be the reader. A symbol present with *zero* slots
is either called by direct branch or resolved once and cached - and the cached case
is what the dlsym tap already counts. If `CKException` still appears with every door
accounted for, the check is not reading this process's own task, and no in-process
hook can answer it. That line is the difference between a guess and a finding.

### 4. The throw trampoline: what it can prove, and what it cannot

`objc_exception_throw` is now routed through `GNThrowTrampolineObject` instead of
the v18 tap. It does one new thing, and it is the thing an assembly stub would have
had to do anyway:

**it decodes the instruction at the return address.**

A slot rewrite already is a trampoline - the caller arrives via `blr x16`, so x0
holds the exception and x30 the return address, exactly what a hand-written stub
would set up. The only thing assembly could add is *skipping the call and returning
to x30*. Whether that is a swallow or a crash is decided entirely by the instruction
at x30, because the compiler emitted that call knowing it does not return:

| next instruction | returning from here is |
|---|---|
| `ret` | a real return from the throwing function, x0 = its result |
| `b` | a real tail branch, same thing |
| `ldp x29, x30, [sp], #n; ret` | a real return through the epilogue |
| anything else (padding, another function's prologue, mid-function) | executing bytes that were never code |

So every throw through the trampoline now logs one of these:

```
trampoline: throw CKException: Application has malformed entitlements. Found value "*" …
  site CloudKitCore + 0x2f1a4  continuation=ret (0xd65f03c0, then 0x00000000) -> returning from here is a real return
trampoline: throw CKException: …
  site CloudKitCore + 0x2f1c8  continuation=mid-function (0xa9bf7bfd, then 0x…) -> returning from here would run bytes that are not code
```

`ThrowSwallowAtSite` arms the swallow, and it only ever fires where the decode
proves a return **and** the exception name is on the allow list **and** the budget
allows. Every swallow is logged by name. It ships off by default - not because it
is dangerous to the process, but because it is a lie to the caller: the function
that threw returns the exception object as its result. Turn it on when the log
classifies a site as a return and you want to see whether the launch survives it.

What it will not do, and no assembly would: swallow a throw whose site is
mid-function. There is no continuation there. Returning into it is the "different
crash with a worse log" that v18 described, and in CloudKit it lands inside the
`dispatch_once` from section 2.

### 5. `ObserveOnly`: what it means, and why it is still `true`

The reading of the v19 log - "ObserveOnly=yes blocks the fix" - is close but not
quite the right lever. `ObserveOnly` in this project has always meant *the v8-v11
legacy hook stack is off*: preference overrides, container fallbacks, the keychain
interposition, the patch pipeline. Flipping it to `false` would arm twenty files of
unrelated hooks, including the code patching that lost this project a launch.

What was actually blocking the fix was the boundary *mode*, and that is what v20
changes: `CloudKitBoundaryMode` and the probe list are config, and the substitute
is not a boundary at all - it replaces rather than wraps. The log now states the
distinction explicitly:

```
observe mode: legacy hook stack off (no preference override, no container fallback, no code patch)
observe mode: the entitlement repair, the exception guard and - if CloudKitStub is on - the
              CloudKit substitute ARE installed: they are launch fixes, not features
```

### What the device log should say

```
cloudkit-stub: installed (mode=noAccount) - iCloud now answers CKAccountStatusNoAccount
cloudkit-stub: CloudKit's own dispatch_once is never entered, so there is no
               half-initialised singleton behind this and nothing to re-enter
cloudkit-stub: +[CKContainer defaultContainer] -> the substitute container, CloudKit never sees the call
```

Read them in this order:

1. **`installed`** — if it says `CKContainer is not loaded yet` five times and then
   nothing, CloudKit is not linked into the process and this crash was never CloudKit's.
2. **`defaultContainer`** — if this line never appears, the app never asked for a
   container and the substitute is not on the path; the launch is dying elsewhere.
3. **`installed` + no `CKException` in `gnunlock-exceptions.txt`** — the entitlement
   check is off the path. The launch survives it.
4. **`installed` + the app still dies** — then the throw is somewhere the substitute
   does not cover, and the trampoline's `site …` line names the image and offset.
   That is a new, answerable question instead of the same one for the sixth time.

### Config

| key | default | what it does |
|---|---|---|
| `CloudKitStub` | `true` | the substitute. `false` restores pre-v20 behaviour exactly |
| `CloudKitStubMode` | `noAccount` | `nil` (only for a caller known to handle nil), `observe` (log only) |
| `CloudKitStubLogBudget` | `12` | log lines per launch |
| `ThrowSwallowAtSite` | `false` | arm the swallow, only where the decode proves a return |
| `ThrowSwallowBudget` | `4` | swallows per launch |
| `ThrowTrampolineLogBudget` | `16` | throw-site lines per launch |
| `EntitlementReadSurface` | `true` | the fourteen-door sweep, run after launch |

`ConfigVersion` is 20.

### What was run, and what was not

Run on the build host:

- every one of the 23 sources compiled to an arm64 object, no errors
- import slot walker: 50 checks, 4 real Mach-O inputs
- repair policy: 664 checks, plus the v17 planner replayed through the same
  assertions - 48 of them catch it
- `v11_lint`: 7 invariants, 7 mutations, all caught
- `v12_lint`: **61 invariants, 61 mutations, all caught** - including the six new
  ones: the substitute must be a runtime subclass created with
  `class_createInstance`, must never keep a pointer to what it replaced, must stay
  behind a config key; the trampoline must read its return address, must require
  `continuation.safe` in the swallow decision, and must write the record *before*
  it swallows; the read-surface probe must not arm the writer it is measuring
- clean unpack of the shipped archive, re-run: green

Not run: a device launch. This machine has no GoodNotes, no shared cache and no
instrumented signature, so "the CKException is gone" is the iPad's word, not this
document's. A green CI means it compiles and the invariants hold - it does not mean
a hook fired.

---

## v19: the hook was live, and nobody had proved CloudKit was calling it

v18 ended with two facts that cannot both be read the way they were written:

```
slot: self-test  VERDICT: interception is LIVE in this process
EXCEPTION name=CKException  reason=... Found value "*" for entitlement ...
slot: 'SecCodeCopySigningInformation' unreachable: 2526 slot section(s), none held its address
```

"The replacement runs" and "CloudKit went through the replacement" are different
statements. v18 had evidence for the first and had been reading it as the second.
That is the bug v19 fixes - not in the hook, in the inference.

### 1. `SecCodeCopySigningInformation`: the zero is the answer, not a failure

In the same walk, in the same process, at the same instant:

| symbol | import slots found |
|---|---|
| `SecTaskCopyValueForEntitlement` | 1 |
| `SecTaskCopyValuesForEntitlements` | 0 |
| `objc_exception_throw` | 3 (Goodnotes, MSAL, CoreUI) |
| `SecCodeCopySigningInformation` | 0 |

The walker found slots for three of the four, including one inside a shared
cache image. A walker that can see `CoreUI`'s `__got` and `Goodnotes`' `__got` in
the same pass is not blind to `SecCodeCopySigningInformation`; the symbol simply
has no import slot anywhere in this process.

That leaves exactly one mechanism, and it is the one that fits every number:

> **CloudKit and Security both live inside the dyld shared cache.** A call from
> one cache image to another is resolved when the cache is built and emitted as a
> direct branch. There is no import slot to find, no dyld binding to interpose,
> and nothing `fishhook` could bind - fishhook edits the pointer a slot holds,
> and here there is no slot.

So the request to "hook it via fishhook on the CloudKit image" has no target, and
the request to "force the `__interpose` to work" cannot be granted: dyld applies
`__interpose` to bindings, and a direct branch is not one.

**What v19 does instead** is stop assuming and measure. Every hit on each of the
three repaired doors is now recorded with the caller's return address, and the
addresses are resolved at +5s (never during dyld init) to `image + offset`. The
next log ends with one of three verdicts:

```
audit: VERDICT: nothing in this process reached a repaired door. ...
audit: VERDICT: callers arrived but the value was already well formed ...
audit: VERDICT: the repair answered and the value was rewritten, and the launch
       still died. Read the caller images below: ...
```

If the answer is the first one, no amount of further hooking helps and the next
commit should not be another hook.

### 2. `objc_exception_throw`: it cannot swallow, and the assembly stub is the code we already have

This was asked for twice, so here is the whole reason it will not be shipped as
"fixed", in the order the obstacles appear.

*There is no continuation point.* The compiler knows `objc_exception_throw` is
`noreturn`. The call is the last instruction of its basic block; what follows is
padding or the next function's prologue, and the registers still hold this
throw's operands. Returning there does not resume anything - it runs whatever
bytes happen to sit after the call.

*An assembly stub changes nothing.* The slot rewrite is already an indirect
branch: the caller executes `blr x16` and the replacement receives the exception
in `x0` with `x30` as its return address. A hand-written stub would receive
exactly the same registers and end in exactly the same tail call the C version
compiles to. Assembly buys one thing - skipping the call - which is the one thing
that does not work.

*And swallowing would be worse than the crash.* This throw happens inside a
`dispatch_once` block. `dispatch_once` sets the token to "running", calls the
block, and marks it done **after the block returns**. An exception leaves the
token at "running" forever. The next call to that same `dispatch_once` - and
there will be one; it is a lazy singleton - takes the slow path, sees the token
belongs to the current thread, and faults with `dispatch_once() called
recursively`. So "survive and continue" converts a named `CKException` into an
unnamed fault in libdispatch, later, further from the cause.

**What v19 does instead:** catches where our frame *is* on the stack. A boundary
on an ObjC entry point is a real `@try` - the exception unwinds into our wrapper
and we choose. The probe list now covers CloudKit's container and database entry
points (`+[CKContainer defaultContainer]`, `+containerWithIdentifier:`,
`-privateCloudDatabase`, `-publicCloudDatabase`, `-sharedCloudDatabase`,
`-accountStatusWithCompletionHandler:`, `-[CKDatabase
fetchAllRecordZonesWithCompletionHandler:]`, `NSUbiquitousKeyValueStore`) in
**observe** mode: record the class, the selector and the exception, then rethrow.
Behaviour is identical by construction, and the log gains the name of the call
that throws - which is the one thing v18 could not say.

They never swallow by default, on purpose. Those selectors return non-optional
values in Swift, so handing back `nil` turns a caught ObjC exception into a Swift
trap: the same crash with a worse log. Once the log names the culprit, one entry
can be moved to `Mode = swallow` in `config/GNUnlock.plist`, for that selector,
deliberately.

### 3. The fix that is left: write the value correctly

The error names a value, and the value is in the signature. `config/entitlements.icloud.plist`
is the same file with `"*"` replaced by what CloudKit's schema asks for:

```xml
<key>com.apple.developer.icloud-services</key>
<array>
    <string>CloudKit</string>
    <string>CloudDocuments</string>
</array>
```

Two things to know before trying it:

* an entitlement your provisioning profile does not grant kills the process at
  launch, before any of this code runs. If the profile has iCloud, this is the
  fix. If it does not, no hook can substitute for it - the read is inside the
  shared cache, per section 1;
* if the profile has no iCloud, the goal changes from "make iCloud work" to "do
  not enter CloudKit's initialiser at all". That is a preference, and
  `Hooks.Defaults.Overrides` is the data-only way to force it.

### What to look for in the v19 log

```
audit: N call(s) through a repaired door, M with a rewritten value; ...
audit:    3 hit(s) (rewritten) <- CloudKitCore + 0x2f1a4 (shared cache)
audit: VERDICT: ...
boundary(observe): +[CKContainer defaultContainer] threw CKException: ... - recorded, then rethrown
```

* `audit` with `CloudKitCore` in the caller list and the launch still dying means
  the value arrives and CloudKit rejects it anyway - the signature is then the
  only place left.
* `audit` with only app-owned callers means CloudKit is not among them.
* `audit: 0 call(s)` is the answer to the whole hooking question: nothing in this
  process went through a door, so the door is not on the path.
* a `boundary(observe)` line names the exact entry point that throws. That line
  is worth more than the `.ips`, because it is the call, not the frame.

---

## v18: the hook was live and the answer was the wrong type

The device log said:

```
slot: self-test  VERDICT: interception is LIVE in this process (repair counter 0 -> 1)
slot: 'SecTaskCopyValueForEntitlement'   ... 1 slot(s) rewritten
slot: 'SecTaskCopyValuesForEntitlements' ... 0 slot(s) rewritten
repair: #1 com.apple.developer.icloud-services: string "*" -> string "CloudKit"
```

The mechanism worked. The arm64e slot was found by address, the signature was
reproduced byte for byte, the replacement ran, and the counter moved. And the
launch still died, because of the last line:

**CloudKit asks for an array of strings. The repair answered with a bare string.**
`"*"` → `"CloudKit"` is a change of value with no change of type, so CloudKit was
handed the same malformed shape it had just refused. Everything in the log was
true and the one thing that mattered was wrong.

### Why it happened, and why no test caught it

The decision lived inline in `src/GNEntitlementRepair.m`: one branch wrapped a
string into an array, another branch called a "default for this rule" helper that
built a `CFString`. The wildcard path took the second branch. That is not a hard
bug to fix; it was a hard bug to *see*, because the only thing that could execute
the decision was CoreFoundation on a device.

So the decision is now a separate, pure C file — `src/GNRepairPolicy.h`:

```
GNRPlanRepair(expect, kind, isWildcard, arrayAllStrings, arrayCount, fillMissing)
    -> { change, produce, source }
```

`produce` is the *final* kind, wrapping included. There is no flag a caller can
forget and no second path to fall through, and `scripts/repair_policy_test.c`
executes all 192 combinations of inputs asserting one property:

```
a repair either changes nothing, or produces exactly the kind the schema requires
```

That test is run by `scripts/stubcheck.sh` and by the CI lint job, and
`--selfcheck` runs the same assertions against **v17's decision**, which they must
reject. They reject it in 48 places. The v17 code is now a failing test case in
this repository instead of a shipped defect.

### The plural read: what the zero meant

```
slot: 'SecTaskCopyValuesForEntitlements' ... 0 slot(s) rewritten
```

Same walker, same 2622 images, same instant as the singular read, which found a
slot. Two ways a caller can reach a function with no slot pointing at it:

| | reachable in process? |
|---|---|
| **direct branch** — `bl` into the function, instruction on a code page | no. Writing there loses the code signature; amfi kills the task on the next fetch. This project already paid for that once. |
| **cached pointer** — resolved once (dlsym, or a weak import bound into a variable), then called through the value | yes. The address is data. |

`SecTaskCopyValuesForEntitlements` is several OS generations younger than the
singular form, which is exactly the profile of a soft-linked symbol: resolve it
once, keep the pointer, call through it. v18 covers that case where it can only
be covered — at the resolution:

* `src/GNDlsymTap.m` rewrites the import slots that hold `dlsym()` to a
  replacement that answers the three entitlement symbols with this dylib's repair
  and defers every other name to the real function. The real `dlsym` is resolved
  and stored **before** the first slot is rewritten, so the tap can never call
  itself.
* If a framework probes for a symbol the process does not have, it still gets
  "absent" — the tap only substitutes a symbol that resolved to something.
* `SecCodeCopySigningInformation` is watched too, and the entitlements dictionary
  inside the answer is repaired: it is the other public door onto the same value,
  and the v17 log is what made it worth covering.

The launch self-test now measures the plural read the same way it measures the
singular one — twice, once through `dlsym` and once through this dylib's binding —
and prints the type CloudKit would get from each:

```
slot: self-test  plural, direct (dlsym, the real function) : dictionary(1) icloud-services=string "*"
slot: self-test  plural, through this dylib's binding      : dictionary(1) icloud-services=array(1) ["CloudKit", ...]
slot: self-test  VERDICT (plural): interception is LIVE - CloudKit's batch read is answered by this dylib
```

If those two lines are identical, the zeros in the slot line are the whole story:
the read goes through a direct branch, nothing data-only can see it, and the value
has to be fixed at signing time. That is a measurement, not a guess.

### objc_exception_throw: a tap, and why it cannot be a catch

`objc_exception_throw` is now one of the watched symbols, so the tap reaches
throws made from shared cache images, where `-[NSException raise]` never runs
because the compiler emits a direct `@throw`. It records name, reason, userInfo and
the throw site (image + offset, the same arithmetic as an `.ips`), then calls the
real function. Behaviour is unchanged.

What it deliberately does **not** do is return instead of throwing, and that is
not caution — it is not available. The throw call is the last instruction of its
basic block because the compiler knows the function does not return, so there is
no landing pad to resume at, and the registers still hold the operands of the
throw. In CloudKit that code sits inside a `dispatch_once`; "resuming" there
continues with a half-built container, and the resulting crash is harder to
explain than the one being avoided and does not reproduce.

An assembly stub does not change that. A slot rewrite is already an indirect
branch (`blr x16`), so the replacement receives the exception in `x0` and returns
to `x30` exactly as the real function does — the C tap compiles to the tail call
an assembly stub would have to write by hand. The only thing an assembly stub
could add is the skip-the-call version, which is the one that cannot work. What
the tap buys is the diagnosis: for the first time this crash will have a *name*
and a *reason* in the log, not a bare `EXC_CRASH`.

The real cure is still the repair. A launch that no longer prints a
`throw| name=...CKException` line is a launch where the value was correct before
CloudKit ever looked at it.

### What v18 changed, precisely

| | v17 | v18 |
|---|---|---|
| `icloud-services: "*"` | `string "CloudKit"` | `array(1) ["CloudKit"]` |
| decision | inline in CF code | `src/GNRepairPolicy.h`, host-executed, 192 combinations |
| rules | 4 keys | 6 keys (adds `icloud-container-environment`, development containers) |
| per-key values | fixed strings | overridable via `EntitlementRepairValues` |
| plural read | slot scan only, 0 found | slot scan + dlsym tap + self-test measurement |
| signing-information read | not covered | covered |
| exception thrown from a cache image | invisible | tapped, named, logged with the throw site |
| code pages written | 0 | 0 |

### What to look for on the device

First, the repair line — the type is the point:

```
repair: #1 com.apple.developer.icloud-services (schema wants array of strings): string "*" -> array(1)
```

Then the two self-tests. Both should exist:

```
slot: self-test  VERDICT: interception is LIVE in this process
slot: self-test  plural, ... : array(1) ["CloudKit", ...]
```

Then the absence that means success: **no** `throw| name=...` line naming
`CKException`. If one appears, it now carries the exact entitlement key and the
type CloudKit wanted, which is the answer rather than another round trip.

### What is still not proven

This machine has no device, no dyld shared cache and no Apple signature. What was
run here: all 23 sources compile to arm64 objects against the stub SDK, the slot
walker's 50 checks against four different real Mach-O objects, the repair policy's
192 combinations plus the selfcheck that rejects v17's decision, and
`v12_lint`'s 49 invariants with all 49 mutations caught. What was not run: a
launch. The three log lines above are how the launch reports back.


## v17: the test that failed was measuring the compiler, not the hook

The v16 dylib is unchanged. What failed was the host test CI runs before the
build, and it failed for a reason worth writing down:

```
real image: /tmp/gn_slot_fixture.o
FAIL  scripts/slotwalk_test.c:509  sections = 2
```

The fixture is an arm64 Mach-O object compiled by whatever clang the job has.
Where the test was written, that object came from zig's clang and carried twelve
sections, most of them `__DWARF`. On the runner it comes from Apple clang and
carries exactly two — `__text` and `__compact_unwind` — because nothing in it
asks for debug info. The walker counted them correctly. The assertion
`sections >= 5` was a fact about the build machine that had been written down as
if it were a fact about the walker.

The fix is not a smaller number. A constant that has to hold on every machine is
a constant nobody can write: the same fixture is 1 section with
`-fno-unwind-tables`, 3 with `-g0`, 12 with debug info, and 2 on a plain Apple
object, and all of them are valid input.

So the test now asks the file:

```
    CountSectionsRaw()   parses the section table with absolute byte offsets
                         (ncmds +16, sizeofcmds +20, nsects +64, section +80) and
                         none of GNSlotWalk.h's structs, then reports how many
                         segments and sections the fixture declares;
    CHECK                requires the walker's counts to equal those, and requires
                         the section names it reads to be printable "__..." bytes.
```

That makes the check stronger than it was, not weaker. Before, a wrong field
offset in `GNWSection` could still pass as long as it landed inside a table of
the right rough size. Now two readers with no shared layout have to agree, and a
section whose `segname` does not match its segment command's — in a linked
image, where the segment is named — is a failure.

Also added: `TestNameFilterRejectsPrefixes`, which puts `__got_like`,
`__auth_got_x`, `__la_symbol_ptr` truncated to fifteen characters and
`__compact_unw` in front of the filter and requires exactly one match. And the
real-image check no longer assumes the fixture is unlinked: if a future fixture
does have import slots, it validates them (one of the four exact names, non-zero
address, whole pointers) instead of failing on their presence.

`v12_lint` grew two invariants so this cannot come back — `real-fixture-reads-
the-file` (the comparison must be against the file) and `real-fixture-not-a-
constant` (no `>=` floor above one on `stats.sections` / `stats.segments`), with
its own mutation proving the second one fires. 37 invariants, 37 mutations
caught. `ConfigVersion` is 17, so a stale bisect ladder resets.

---

## v16: the interposition was armed and nothing was intercepted

v15's log line was:

```
repair: armed - SecTaskCopyValueForEntitlement intercepted for the whole process
```

That line was true and it was useless. It says the table was read by dyld; it
does not say a single call went through it. The launch still died on the same
`CKException`, which is the only fact that matters.

### Why the interpose table can miss, in one paragraph

`__DATA,__interpose` is applied to **bindings** — import slots. A caller that
reaches `SecTaskCopyValueForEntitlement` with a direct branch has no slot, so
there is nothing for dyld to rewrite. And our replacement is only ever reached
through a slot dyld rewrote: if the read happens in an image whose binding dyld
does not touch, the repair is dead code that logs "armed".

### Why fishhook is not the answer either

You suggested rebinding the slot inside CloudKit's image with fishhook. It cannot
work here, and neither reason is a bug in fishhook:

* **it finds a slot by name.** It walks the classic symbol table and the
  indirect symbol table. The dyld shared cache strips both. Every system image
  therefore reports zero symbols and nothing is ever found — and system images
  are exactly where this call is made;
* **on arm64e the slot holds an authenticated pointer**, signed over the
  identity of that slot. A plain address written there does not fail at the
  write. It fails at the next call, in a frame that looks nothing like the hook.

### What v16 does instead: identify by address, prove before writing

Both problems disappear once you stop using names and stop guessing.

```
find it     walk __got / __auth_got / __la_symbol_ptr / __nl_symbol_ptr out of
            the SECTION TABLE (which the cache does keep), read each entry, and
            compare it with the resolved address of the function. A slot that
            points at it is, by definition, a call site for it. No name needed.
prove it    the slot already holds a correctly signed pointer to that address.
            Sign the same address again with each candidate key/discriminator
            and require the result to equal the BYTES ALREADY IN THE SLOT. Only
            a pair that reproduces the existing content bit for bit is used to
            sign the replacement.
refuse      a slot that cannot be reproduced is left exactly as it was. The
            failure mode is a refusal and a log line, never a fault.
```

`GNSlotMoveTo()` in `src/GNRebind.m` is the proof; `src/GNSlotScan.m` is the walk
and `src/GNSlotWalk.h` is the hardware-neutral core of it.

### Why not your options 1 and 3

**Option 1 (assembly trampoline that "pops the return address").** Two problems,
both fatal, neither about taste:

* on arm64 there is nothing on the stack to pop. `bl` puts the return address in
  `x30`. A stub that "returns to the caller" is just `ret`, and what it returns
  to is the instruction after the call;
* `objc_exception_throw` is declared `noreturn`, so the call is the last
  instruction of its basic block. The compiler emits nothing after it. `ret`
  therefore resumes on whatever bytes happen to follow — a landing pad, padding,
  or the next function's prologue — with the registers the throw was about to
  use. Inside a `dispatch_once` during app initialisation that is a worse crash
  than the one being avoided, and not reproducible.

Not "risky": there is no correct continuation to jump to. The exception has to
not be constructed.

**Option 3 (dummy `CKContainer`).** `CKContainer.default()` and
`CKContainer(identifier:)` are non-optional in Swift. Returning nil at that
boundary turns an Objective-C exception into a Swift trap: same launch, different
body count. It stays in the config as a boundary net, off by default.

**MSHookFunction / any inline hook** is unavailable on this signature for a
reason this project already paid for once: a patched text page loses its
signature, and amfi kills the task on the next instruction fetch
(`CODESIGNING` / `Failed to fault in a page with execute permissions`). v16
writes data pages only.

### Three layers, and a measurement

```
1  interpose        v15's table, kept: dyld rewrites the process's bindings
2  slot rewrite     v16: every import slot in every image, shared cache
                    included, plus any framework loaded later with dlopen
                    (CloudKit is dlopen'ed by GoodNotes after our constructor)
3  self-test        call com.apple.developer.icloud-services twice at launch,
                    once through dlsym (the real function) and once through this
                    dylib's own binding, and compare the type of both answers
```

Layer 3 is the part v15 did not have, and it is the answer to "do not send me
another version unless you verify it". It cannot be faked by a log line that only
reports installation, because the two calls differ in exactly one respect:
whether an import binding is in the middle.

### What the next log will say, and what each line means

```
slot: self-test  direct (dlsym, the real function) : string "*"
slot: self-test  through this dylib's binding      : array(1) ["CloudKit", ...]
slot: self-test  VERDICT: interception is LIVE in this process
```

→ the read is intercepted, CloudKit gets the type it requires, and the exception
should never be constructed. If the app still dies, the next exception is a
different one — and v14's `-raise` guard plus the forensics hook will name it.

```
slot: CloudKit __DATA_CONST,__auth_got: 1 of 96 slot(s) held
      'SecTaskCopyValueForEntitlement' - rewritten
```

→ the slot inside CloudKit itself was found and rewritten, with the signature
reproduced. This is the specific case you asked for.

```
slot: no import slot section in any image held either symbol. Every caller
      reaches these functions through a direct branch ... The value has to be
      fixed at signing time.
```

→ the measurement said no, and it says why. In that world no in-process hook of
any kind can see the read: not fishhook, not interpose, not an entry patch. That
is the end of the code road, and it is now a measured fact rather than a theory.

### Verification (things that were actually run, not asserted)

| Check | Result |
|---|---|
| `scripts/v12_lint.py` | 37 invariants hold (2 of them v17's) |
| `scripts/v12_lint.py --selftest` | 37/37 mutations caught, each with its own reason |
| `scripts/stubcheck.sh` | 18 sources compile to arm64 objects |
| `scripts/slotwalk_test.c` | **executed**, 42 checks, 0 failures |
| same test, real fixture | **executed** against an arm64 Mach-O object from the same linker: 50 checks with the fixture, 0 failures - the counts are compared with the file's own section table, so 1, 2, 3 or 12 sections all pass |
| slot move proof | a slot whose bytes cannot be reproduced is refused (unit tested) |
| baked config | decodes as `ConfigVersion=17`, `EntitlementSlotRebind=true` |

The slot walker test runs for real, on the host, against synthetic Mach-O images
placed at the end of a mapped page with a `PROT_NONE` guard page behind them — so
a read past the readable run is a segfault in the test rather than an
unexplainable launch failure in a system framework. It covers a lying `nsects`, a
lying `cmdsize`, a truncated `sizeofcmds`, a wrong magic, the refusal path and
idempotence of a second pass.

### Not proven, and why it cannot be proven here

* that dyld gives us those sections for a shared cache image — the on-device
  self-test reports it in the first two lines of the log;
* that pointer authentication reproduces a cache slot byte for byte — the code
  refuses instead of guessing if it does not, and the refusal is logged with the
  address;
* that the app launches. v16 removes one named cause; if a different exception is
  next, the forensics hook will name it.

---

## v15: stop raising the exception, answer with the right type

v14 put a suppressor on `-[NSException raise]`. The next launch says it never
ran: CloudKit uses `@throw`, which calls `objc_exception_throw` directly, and
`-raise` is not on that path. So the exception was never something to survive
after the fact.

There is exactly one place it can be stopped: the value. CloudKit reads its own
entitlements in process, finds a string where the schema says *array of
strings*, and throws. Answer that read with the right type and the exception is
never constructed.

### The two candidates, and why one of them is not a fix

**Hook `objc_exception_throw` and return.** This looks like the shortest path
and is the one that gets proposed most. It is a fall-through, not a return: the
call is the last instruction of its basic block because the compiler knows it
does not return, so "returning" resumes at whatever bytes happen to follow - a
landing pad, padding, or the next function's prologue - with the registers the
throw was about to use. In CloudKit that code sits inside a `dispatch_once`
during app initialisation. A corrupted continuation there is a worse crash than
the one being avoided, and it is not reproducible, so it cannot even be debugged
from a log.

**Hook `SecTaskCopyValueForEntitlement` and answer correctly.** No tail: the
exception is never built, CloudKit takes its ordinary success path, and every
other caller in the process sees exactly what the signature says. This is v15.

### Why the call site is not available to `GNRebind`

`GNRebind` rewrites import slots, and it deliberately restricts itself to images
inside the app bundle. The call that matters here is made by CloudKit and by the
ubiquity client, i.e. from the dyld shared cache. Rewriting an auth-signed slot
there by hand means signing a pointer with a discriminator that is not in the
image's section headers - and an unsigned pointer in an auth slot is not
"unverified", it is a crash on the next call.

dyld can do it properly, so v15 asks dyld:

```objc
// src/GNEntitlementRepairInterpose.m  (the only file naming the API)
__attribute__((used)) static GNInterposeTuple GNEntitlementInterposeTable[]
    __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)&GNRepairCopyValueForEntitlement,   (const void *)&SecTaskCopyValueForEntitlement },
    { (const void *)&GNRepairCopyValuesForEntitlements, (const void *)&SecTaskCopyValuesForEntitlements },
};
```

dyld reads that table at load time and applies it to **every** binding of the
symbol in the process, shared cache included, doing its own pointer
authentication per slot. Nothing in this dylib writes a data page, an import
slot or a code page.

The declarations are `weak_import` on purpose:
these symbols are exported at run time but they are **not** in `Security.tbd`,
so a plain `extern` reference compiles and then fails at link time - which is
v12.1 all over again. `weak_import` binds when present and reads back as 0 when
absent, and the log then says the table bound nothing instead of pretending.

### What the repair will and will not do

Four keys, from the exception message and Apple's entitlement schema:

| entitlement | type Apple requires |
|---|---|
| `com.apple.developer.icloud-services` | array of strings |
| `com.apple.developer.icloud-container-identifiers` | array of strings |
| `com.apple.developer.ubiquity-container-identifiers` | array of strings |
| `com.apple.developer.ubiquity-kvstore-identifier` | string |

A value is rewritten **only when its type is wrong**, or when it is the literal
wildcard `"*"` a signer writes when it does not know the real value. That gate
is `GNValueIsCorrect()` and `scripts/v12_lint.py` enforces it
(`entitlement-repair-type-only`, mutation tested).

It is a type repair, not a grant:

* a correctly typed value passes through untouched, whatever it contains;
* a key the signature does not carry stays absent (`EntitlementRepairFill`
  turns that off by default and on by request);
* it cannot make iCloud work on a Distribution certificate. It only stops a
  malformed value from being the reason the launch dies.

`EntitlementRepair` is on by default, like `CloudKitGuard`, because the shipped
default is the configuration the crash happens in.

### What to read in the next log

```
repair: interpose[0] SecTaskCopyValueForEntitlement: bound by dyld
repair: interpose[1] SecTaskCopyValuesForEntitlements: bound by dyld
repair: armed - SecTaskCopyValueForEntitlement intercepted for the whole process
repair: #1 com.apple.developer.icloud-services: string "*" -> array(1)
...
repair(delayed): armed (n=1, fill=off), 1 entitlement value(s) rewritten this launch
```

* `repair: #n ...` — the repair fired. CloudKit got a well-typed answer and
  there is no exception to survive.
* `interpose[i] ... NOT BOUND (symbol absent)` — weak import did not resolve;
  the module is dead code in this process and the log says so.
* `repair: armed` with `n=0` and the launch still dying — nothing ever asked for
  one of the four keys, so the interposition never proved itself. That is the
  one outcome that means "dyld did not reach the caller", and then the signer
  owns the value after all.

The v14 guard stays installed behind this. If CloudKit has a second reason to
raise `CKException` (a container that does not exist, say), it is still the
second line of defence.

### Verification

| check | result |
|---|---|
| `scripts/v12_lint.py` | 23 invariants hold (5 new) |
| `scripts/v12_lint.py --selftest` | 23/23 mutations caught, each for its own reason |
| `scripts/stubcheck.sh` | every source compiled to an arm64 object |
| `__DATA,__interpose` in the object | present, 2 entries |
| `_SecTaskCopyValueForEntitlement` in the object | `N_UNDF` + `N_WEAK_REF` (0x0040) - binds if present, 0 if not |

The last two are read out of the compiled `GNEntitlementRepairInterpose.o`, not
asserted in prose: the table is in the section dyld looks at, and the two
symbols are weak references rather than the strong ones that broke v12.1.

**Not proven.** This environment has no iOS device and no ObjC runtime, so:

* that dyld applies the table to shared cache images *on this OS version* - it
  is documented behaviour since dyld4 and it is what the `repair:` lines will
  confirm or refute;
* that CloudKit reads the entitlement through `SecTaskCopyValueForEntitlement`
  rather than some other copy of the same data (the exception text matches the
  value this process reads through exactly that API, which is strong but not
  conclusive);
* that the app then launches. The repair removes one named cause; if the next
  exception is a different one, the log will name it.

---

## v14: the crash was not a hook, it was a string in the entitlements

v13's log closed the loop:

```
probe: entitlements as signed in THIS process:
  com.apple.developer.icloud-services = *
  com.apple.developer.icloud-container-identifiers = ( )

EXCEPTION name=CKException
          reason=Application has malformed entitlements. Found value "*"
          for entitlement com.apple.developer.icloud-services,
          expected an array of strings
```

The dylib works. The constructor runs, the probe reads the process' real signed
state, and the exception capture names the exception. Nothing to fix there.

The launch dies because **the signer wrote a string where CloudKit requires an
array of strings**. CloudKit validates its own entitlements in process on first
use, finds `"*"`, raises `CKException` out of app initialisation, and nothing
catches it.

### The fix that actually ends this, in LC Sign (no rebuild needed)

Open the entitlements LC Sign applies to the app. For
`com.apple.developer.icloud-services` you will find `*` — the wildcard some
signers inject when they do not know the real value. CloudKit reads it as a
string and refuses it. It is a type error, not a permission problem, so "grant
more capabilities" makes it worse rather than better.

Pick one:

**A. Remove the iCloud keys** (safest with a Distribution certificate whose
profile does not carry iCloud):

```xml
<!-- delete all of these -->
<key>com.apple.developer.icloud-services</key>
<key>com.apple.developer.icloud-container-identifiers</key>
<key>com.apple.developer.ubiquity-kvstore-identifier</key>
<key>com.apple.developer.ubiquity-container-identifiers</key>
```

CloudKit then behaves like an app with no iCloud account: sync is unavailable
and the app keeps running. Goodnotes' local library is unaffected.

**B. Write the right types** (only if the provisioning profile really carries
iCloud — otherwise the daemon rejects it later and you get a different, quieter
failure):

```xml
<key>com.apple.developer.icloud-services</key>
<array><string>CloudKit</string></array>

<key>com.apple.developer.icloud-container-identifiers</key>
<array><string>iCloud.$(CFBundleIdentifier)</string></array>

<key>com.apple.developer.ubiquity-kvstore-identifier</key>
<string>$(TeamIdentifierPrefix)$(CFBundleIdentifier)</string>
```

The probed values after re-signing should then read `array` / `string`, and the
probe prints `VERDICT: every checked entitlement has the type Apple requires`.

### What v14 adds anyway, because you should not have to re-sign to find out

Three things, none of which touch the entitlement itself — only the signer can:

1. **`src/GNCloudKitGuard.m`** — suppresses the exception at
   `-[NSException raise]`, the last method before `objc_exception_throw`, and
   only when the exception *name* is allow listed (`CKException`). Every other
   exception in the process is raised exactly as before. The raise returns
   instead of unwinding, so CloudKit continues on its own failure path and the
   launch goes on.

2. **The probe now validates types.** A value can be present, non-empty, and
   still be the reason the app dies. "Does the key exist" was the wrong
   question; the log now prints `MALFORMED — CloudKit requires array of strings,
   got *` and the exact fix, on the next launch, without another round trip.

3. **Optional boundaries** around `-[NSFileManager
   URLForUbiquityContainerIdentifier:]` and `-[NSUbiquitousKeyValueStore
   synchronize]`, for the case where CloudKit used `@throw` and never reached
   `-raise`. Both answer with the value Apple documents for "not available".

### Three answers to the three questions in the request

**"Can we hook `-[NSException initWithName:reason:userInfo:]` and return nil?"**
No — and this is the one worth writing down. That method *constructs*; it does
not raise. Returning nil from it hands a nil object to the raise path, which
turns your exception into a null dereference, and it also destroys every
exception object in the process — including the forensics capture that produced
the v13 log. The interception point is `-[NSException raise]`. It is now a lint
rule (`cloudkit-no-init-hook`), with a mutation that proves it fires.

**"Can we hook `CKContainer` init and return a mock?"** Only as a fallback, and
it is off by default. `CKContainer.default()` and `CKContainer(identifier:)` are
non-optional in Swift, so a nil from the boundary converts a caught ObjC
exception into a Swift trap — you trade one crash for another. It is documented
in `config/GNUnlock.plist` for the case where the log proves the throw bypassed
`-raise`.

**"Is there a config switch to disable iCloud completely?"** The closest honest
one is `CloudKitBoundaries` — the guard's boundary list. Goodnotes' own iCloud
switch lives behind its settings UI and its key names are not in the binary's
class dump, so guessing a preference name would be exactly the kind of
speculation v12 existed to stop.

### Why swallowing here is not the v10 mistake again

v10 and v11 swallowed exceptions at `@try` nets around the app delegate's
launch selectors. That failed for two reasons: the net was not on the crashing
call path, and a `dispatch_once` block that is abandoned mid-flight stays
entered, so the second caller blocks forever.

This one is different in both respects. It sits on the one path every
Objective-C exception must take, and it does not abandon a block: the raise
returns normally, so the `dispatch_once` completes, and every later caller is
served. What it *cannot* fix is the state CloudKit leaves behind — an iCloud
subsystem that failed to initialise. The app is expected to come up with sync
unavailable, which is the same state a user gets with no iCloud account.

### Verification

```
v12_lint.py                     18 invariants hold
v12_lint.py --selftest          18/18 mutations caught
v11_lint.py --selftest          7/7 mutations caught
stubcheck.sh                    every source -> arm64 object (16 files, incl. GNCloudKitGuard.m)
```

Four new invariants, each with a mutation that proves it fires:

| Rule | What it forbids |
|---|---|
| `cloudkit-guard-narrow` | a suppressor that is not gated on an exception-name allow list |
| `cloudkit-guard-before-observe` | the guard installed behind the observe early return, i.e. dead in the shipped default |
| `cloudkit-no-init-hook` | suppressing at `initWithName:` instead of at `-raise` |
| `cloudkit-guard-default-on` | shipping with `CloudKitGuard` false |

### Not proven

The guard has not been executed against a real `NSException` — this environment
has no Objective-C runtime, so the predicate and the boundary trampolines are
compiled and mutation-tested but not run. What the log will tell you on the next
launch, unambiguously:

```
cloudkit-guard: armed - swallowing 1 name(s) [CKException], reason filter off
cloudkit-guard: SWALLOWED #1 CKException: Application has malformed entitlements...
```

and the app stays up. If instead you see the `EXCEPTION name=CKException` line
with **no** `SWALLOWED` line after it, CloudKit used `@throw` and never reached
`-raise`; then turn on the `CKContainer` boundary entries from the plist comment.

---

## v13: ten front-end errors, one cause — the private API was declared by the wrong file

v12.1 never reached the linker:

```
src/GNProbe.m:56:5: error: unknown type name 'SecTaskRef'; did you mean 'SecTrustRef'?
src/GNProbe.m:68:5: error: call to undeclared function 'SecTaskCreateFromSelf';
src/GNProbe.m:92:5: error: call to undeclared function 'SecTaskCopyValueForEntitlement';
10 errors generated
  FAILED  arm64  GNProbe.m
  FAILED  arm64e GNProbe.m
```

`SecTaskCreateFromSelf` / `SecTaskCopyValueForEntitlement` are real: Security.framework
exports them and they are the correct way to ask a process what it was actually
signed with. They are also **private** — not in `<Security/Security.h>`, and not in
the SDK's `Security.tbd`. That is two separate failures wearing one name:

| stage | what happens |
|---|---|
| front end | the type and the prototypes do not exist, so naming them is a hard error — the ten above |
| link | a hand-written `extern` prototype compiles, then `Undefined symbols for architecture arm64: _SecTaskCreateFromSelf`, because the linker resolves against the `.tbd`, not the framework |

So of the two fixes that suggest themselves, one is wrong:

* **`extern` declarations** — gets past the front end and dies at link time, and only
  on the real SDK, i.e. a third round trip.
* **`dlsym`** — no declaration to reject, no symbol for the linker to resolve. This is
  the one that was taken.

### Why the local pre-flight was green

This is the part worth fixing, not just the call site.

`scripts/stubcheck.sh` type checks every source against `scripts/stubsdk/`, a small
reconstruction of Foundation / UIKit / Security / CoreFoundation. That stub had
declared the whole SecTask family. So the pre-flight was checking a header the
project had authored itself, and it reported `ok` on the exact file CI rejects.

A stub that is more permissive than the SDK does not test anything. It converts a
front-end error into a false green, and it does it silently, at the one stage where
the check is cheapest.

### What changed

1. **`src/GNPrivateSecTask.{h,m}`** — the only place in the tree that names these
   symbols. `GNSecTaskHandle` is an opaque `const void *` (no private typedef
   re-declared by another name), the two symbols are resolved once with
   `dlsym(RTLD_DEFAULT, ...)`, and a `dlopen` of Security runs only if that fails. The
   unit is Foundation-free because it runs in the dylib constructor.
   When the symbols are absent the probe logs that it cannot read entitlements and
   says to check the signed `.mobileprovision` instead — it does not print `<ABSENT>`
   for a question it never got to ask.
2. **`src/GNProbe.m`** — four call sites, now wrappers. It compiles with no private
   declaration anywhere; the file no longer includes `<Security/Security.h>` at all.
3. **`scripts/stubsdk/include/Security/Security.h`** — the SecTask declarations are
   gone, with the reason written at the top of the file. The stub's job is to fail
   where the SDK fails.
4. **`scripts/stubcheck.sh`** — a new gate compiles the exact v12.1 line and requires
   it to **fail**. If the stub ever drifts back into being more permissive, the
   pre-flight fails instead of shipping.

Two invariants, both mutation tested (`scripts/v12_lint.py`, 14 rules now):

| rule | what it forbids |
|---|---|
| `private-api-dlsym` | any private symbol named outside a string literal anywhere in `src/`. A name inside a literal is text and links nowhere; the same name as an identifier is a front-end or link error on the SDK that matters. |
| `stub-no-private-api` | the stub SDK declaring anything the public SDK does not. |

### Regression proof

The v12.1 `src/GNProbe.m`, byte for byte, against the new stub:

```
error: use of undeclared identifier 'SecTaskRef'
error: call to undeclared function 'SecTaskCopyValueForEntitlement';
        ISO C99 and later do not support implicit function declarations
```

The same class of error, at the same lines, produced locally in 0.07 s instead of one
CI round trip. That is the whole point of the gate: the pre-flight now reproduces the
macOS front end instead of contradicting it.

### What this does not change

Nothing at run time. The probe reads the same two functions and logs the same lines;
the only difference is how the addresses are obtained. Defaults are untouched —
`ObserveOnly=true`, `RunLevel=0`, `ResignFix` off, `GuardEnabled=false` — and
`scripts/v12_lint.py` still fails the build if any of that moves. The v12 conclusion
stands unchanged: with the default config this dylib installs nothing, so the next
launch has one variable.

**Not proven:** that the symbols resolve in *your* process (they will if the app
links Security, which it does — but the probe now reports it either way), and that the
app launches. That last one still needs one install.

---

## What v12 is, and what it refuses to claim

Ten builds went by adding mechanisms to catch a crash. Each one was a behaviour
change in a process that was already throwing an exception out of a
`dispatch_once` during app initialisation — we kept buying the ability to
diagnose a crash by making the crash more likely.

**v12 ships inert.** With the defaults in `config/GNUnlock.plist`, the
constructor does three things:

| step | what | touches the app? |
|---|---|---|
| `GNBoot()` | opens the log on four paths with `open(2)`, writes a banner, `fsync`s | no |
| `GNProbeSignedState()` | reads this process' own entitlements and app-group answers | no |
| `GNInstallExceptionForensics()` | hooks `-[NSException initWithName:reason:userInfo:]`, records ≤3 exceptions, removes itself | read-only |

No delegate is wrapped. No private UIKit selector is hooked. No container answer
is overridden. No import slot is rebound. No preference is written. No code page
is touched. `src/GNUnlock.m` names none of the hook symbols — the whole v8–v11
stack moved to `src/GNLegacy.m` and is only reachable when `ObserveOnly` is set
to `false`, and `scripts/v12_lint.py` fails the build if that ever changes
silently.

**I will not tell you this build is guaranteed to launch.** Nobody can, and a
build that promises it and then doesn't is what a tenth round trip costs you.
What this build guarantees is narrower and more useful: *it adds nothing*. Which
makes the next launch an experiment with one variable.

---

## v12.1: the preflight was failing before it compiled

The v12 tree never reached the compiler on GitHub. The `config + scripts` job
died on its own step:

```
error: the guard install or the run level gate is missing
```

That step was written for v11. It located two statements by line number inside
`src/GNUnlock.m`:

```sh
guard=$(grep -n 'GNInstallLaunchGuard();' src/GNUnlock.m | head -1 | cut -d: -f1)
gate=$(grep -n 'int level = GNRunLevel();'  src/GNUnlock.m | head -1 | cut -d: -f1)
```

v12 moved both of them into `GNRunLegacyMode()` in `src/GNLegacy.m`. So the
grep found nothing, the step reported the *consequence* as a cause ("the guard
install is missing"), and the job failed before `clang` ran once.

The check was not wrong to exist. Installing the launch guard **before** the run
level gate is a real invariant: forensics are not part of the bisect ladder, so
they have to be installed at every level, level 0 included, or a level 0 crash
stays as opaque as the crash the guard exists to explain. The mistake was
restating that invariant as "this statement sits at a lower line number in this
file", which is not the invariant — it is a fact about one version of the source
that every refactor invalidates.

What changed in the tree, and only this:

| File | Change |
|---|---|
| `scripts/v12_lint.py` | three new invariants (below), each with its own mutation in `--selftest`; the rule set is now 12 |
| `.github/workflows/build-dylib.yml` | the line-number step is gone; the v12 lint step carries a note saying where the rule lives now |
| `README.md` | this section, and the claim in the v9 notes that both v9 checks were mutation tested, which was not true of this one |

New invariants:

- **`legacy-guard-first`** — inside `GNRunLegacyMode()`, `GNInstallLaunchGuard();`
  precedes the `GNRunLevel();` read. Same requirement, checked where the code
  actually is, by parsing the function body rather than by counting lines.
- **`legacy-unreachable`** — the constructor reaches `GNRunLegacyMode()` only
  after the observe branch has returned, and that branch still returns. This is
  v12's central claim, and nothing was asserting it: the old rule checked an
  ordering inside a file the hook stack no longer lives in, and no rule checked
  that the stack could not run.
- **`ci-no-line-numbers`** — no file under `.github/workflows/` may call
  `grep -n`. Structural properties belong in a lint that `--selftest` can prove
  still fires; a workflow step that pins a statement's position will break on
  the next refactor and, worse, will report a layout change as a missing call.

**No runtime code changed.** `src/` is byte-identical to the v12 drop, so the
dylib this tree builds is the same dylib, and every conclusion in the review
below still stands.

Local verification of this drop (all of it, before packaging):

```
lint job, all 14 steps replayed against this tree      ok
scripts/v12_lint.py                                    12 invariants hold
scripts/v12_lint.py --selftest                         all 12 mutations caught
scripts/v11_lint.py --selftest                         all 7 mutations caught
scripts/stubcheck.sh                                   every source → arm64 object
```

Not proven, as always: that a macOS runner with the real SDK sees what the stub
SDK saw, and that the app launches.

---

## The A-to-Z review — what the evidence actually says

### 1. "It crashes before any of our code runs" cannot be true

A dylib's constructors run from dyld's initialiser list, before `main()`, and
therefore long before `UIApplicationMain`. Your crash report has
`UIApplicationMain` at frame 26. If the process got there, the constructor ran.

So "no `gnunlock.log`" never meant our code did not run. It meant one of:

- the file was written where you could not reach it, or
- the write failed, or
- it was written and not found.

That distinction is the whole reason v11 was stuck: the ladder, the state file
and the log all lived in `Documents`, obtained through
`NSSearchPathForDirectoriesInDomains` and written through Foundation during dyld
init. **If those writes failed, the ladder could never advance** — it is entirely
state-file driven — and you would see exactly what you saw: same crash, no log,
no progression. The ladder was not failing to read the state file. It was most
likely failing to write it.

v12 obtains the container from `$HOME`, which is what the kernel actually gave
the process, and writes to four paths with raw `open`/`write`/`fsync`:

```
$HOME/Documents/gnunlock.log
$HOME/gnunlock.log
$HOME/tmp/gnunlock.log
$HOME/Library/Caches/gnunlock.log
```

The first line of the file is `GNUnlock v12 beacon - constructor reached`. If
that line is not there, the dylib did not load, and no hook in it matters.

### 2. Why the v11 ladder could not have worked even with a working state file

`GNInstallLaunchGuard()` was called **before** the run-level check, so it ran at
every level including 0. That means the level-0 "control experiment" — the step
whose entire purpose was to prove "the crash is not ours" — still had our
`-[UIApplication setDelegate:]` swizzle and our hook on the private
`-[UIApplication _handleDelegateCallbacksWithOptions:isSuspended:restoreState:]`
installed. There has never been a launch of this dylib that installed nothing.
v12 is that launch.

### 3. Why `NSSetUncaughtExceptionHandler` logged nothing (confirmed)

```
7  libc++abi   std::__terminate
8  libc++abi   __cxxabiv1::failed_throw
```
`failed_throw` is what libc++abi runs when `_Unwind_RaiseException` finds no
landing pad. In that state `__cxa_current_exception_type()` is null, so
`_objc_terminate` takes the "there is no current exception" branch and calls the
**default** terminate handler. `NSSetUncaughtExceptionHandler` is registered on
the *other* branch. It was never called. This is not a bug in our code, it is
the wrong tool, and v8–v10 shipped it three times.

### 4. Why the `@try` nets missed

Frames 11–26 contain no frame of ours. v10 wrapped `application:willFinishLaunching`
and `application:didFinishLaunching`; v11 added a net on
`_handleDelegateCallbacksWithOptions:...` (frame 22). The exception is raised at
frames 15–21, *below* frame 22 in the call chain — which means the net was not
installed on that path. Either the delegate was not installed through
`-setDelegate:`, or the private method never got swizzled. We cannot tell which
from a stack, and it does not matter now.

### 5. What the binary says about App Groups, Keychain and iCloud

From `analysis/data/` (8,074 ObjC classes, 35,159 Swift type descriptors, taken
from the decrypted 7.1.34 binary):

**Keychain is almost certainly not your crash.** GoodNotes ships its own keychain
abstraction with a fallback chain already in it:

```
GNKeychain.CompositeKeychain
GNKeychain.FileBackedKeychain      <- works with no keychain at all
GNKeychain.NoOpKeychain
GNKeychain.KeychainDuplicator
GNKeychain.KeychainRecoveryResult
GNAppleKeychain.AppleKeychain
```

An app that carries a `FileBackedKeychain` and a `KeychainRecoveryResult` is an
app that expects Keychain to be unavailable and has a plan for it. `-34018` from
a re-signed team id is the normal case for this app, not a fatal one.

**App Groups is the more plausible side**, because GoodNotes 7 added library
partitioning, which is container-shaped:

```
GNLibraryPartitioning.LibraryPartitioning
GNLibraryPartitioning.LibraryPartitionSizeCache
GNLibraryPartitioning.ConflictErasureFlow
GNLibraryPartitioningError / LibraryPartitioningIOError
GNOnboardingV2.LibraryPartitioningRequiredStep
CommonCore.PersonalLibraryEntityBootstrapper
CommonCore.WorkspaceEntityBootstrapper
```

`LibraryPartitioningIOError` is an *error type*, which means that path models
failure — it does not simply force-unwrap a nil container. That is evidence
against the simplest version of the theory.

**iCloud** has the same shape: `CloudKitUserIdentityService`,
`CloudKitAccountHashProviderImpl`, `GNCloudICloudErrorRecoveryCoordinator`,
`NoOpGNCloudMigrationManager`, `NoOpGNCOnlineMigrationStateManager`. Lots of NoOp
variants, i.e. designed to run without CloudKit.

And the third-party SDKs bundled in the same binary are each a known
"configure yourself in `didFinishLaunching` and throw if you cannot" component:
Firebase (`FIRComponentContainer`, `FIRMessagingKeychain`), AppsFlyer
(`AFSDKAppGroupStorage`, `AFSDKKeychainFactory`), Facebook (`FBSDKKeychainStore`),
Google Sign-In (`GTMAppAuth.KeychainWrapper`), RevenueCat.

**One correction to what I told you in v11.** I suggested
`AppGroupFallback = docs` was the prime suspect. I went back and read it: it does
create the directory it hands back (`GNFallbackDirectory` →
`createDirectoryAtURL:withIntermediateDirectories:YES`). So it is not a
filesystem error. It is still a semantic change — the app sees an *empty*
container where it would otherwise see *nil*, and takes a different code path —
which is exactly why it is off by default now. But it was not obviously broken,
and I should not have implied it was.

**What I could not do in this round:** name `imageIndex 37`. That number is the
answer to "which module threw", and it only exists in the `usedImages` array of
the `.ips` you trimmed out. The bundle you uploaded this session is the old
single-file `GNUnlock.m`, not the app. With no binary and no `usedImages` here,
naming it would be a guess dressed up as analysis — which is the thing that
produced the last ten builds.

---

## What to do with this build

**Test 0 — free, no build, decides half the question.**
Sign the same IPA with LC Sign and **inject nothing**. Install, launch.
- It launches → the crash is ours, and v13's observe mode will name it.
- It still crashes → no dylib can fix it; it is the re-sign or the app, and the
  next step is the entitlements, not more code.

**Test 1 — v13 as shipped.**
Inject `GNUnlock.dylib`, launch once, then read any of the four log paths above.

What the log will contain, and what each line means:

```
GNUnlock v13 beacon - constructor reached     <- the dylib loaded and ran
sinks     : 3 open                            <- 0 here means only stderr has it
probe: SecTask API resolved by dlsym - no private header, no extern
                                              <- or "NOT available", in which case
                                                 the <ABSENT> lines below mean
                                                 "could not ask", not "absent"
probe: com.apple.security.application-groups = <ABSENT>
                                              <- the entitlement did not survive
                                                 signing. No hook can make the
                                                 container real.
probe: app group group.com.goodnotesapp.x -> nil
EXCEPTION name=NSInternalInconsistencyException reason=...
                                              <- the actual answer
```

**Test 2 — only if the log says the constructor ran and no EXCEPTION line
appears before the crash.** That means the throw happens even earlier than the
first `NSException` allocation, which would point at `NSException` being raised
before `GNInstallExceptionForensics()` runs. Send me the log; I will move the
hook to `+[NSException exceptionWithName:reason:userInfo:]` as well.

**If it simply works and the app launches**: tell me, and we go back to job 2 —
the unlock — with the launch crash finally out of the way. Everything from v8–v11
is still in `src/GNLegacy.m`; setting `ObserveOnly` to `false` turns it back on
one run level at a time, and now there will be a log to watch it happen.

---

## What would let me finish this in one round

Either one of these turns the remaining guesswork into arithmetic:

1. **The full `.ips`** — with `usedImages` intact. `imageIndex 37` becomes a name.
2. **The signed `.app` you actually install** (or just its `Goodnotes` binary
   plus `embedded.mobileprovision`). Then I can read the entitlements that
   survived LC Sign instead of asking the process to report them.

Neither needs a Mac. Both are smaller than the IPA.

---

## Build

```
./scripts/build.sh          # needs Xcode / macOS runner, produces out/GNUnlock.dylib
./scripts/stubcheck.sh      # no SDK needed: zig + the stub headers, ~15s
```

`stubcheck.sh` is a pre-flight, not a substitute: it proves the sources parse,
type check and generate real arm64 objects against a reconstruction of the SDK
surface this project uses, and it runs every invariant test including
`v12_lint.py --selftest`, which mutates the tree once per rule and requires each
rule to fire.

---

# History

## What changed in v11

v10 removed our own crash. What came next is the crash that was **behind** it:
the same `dispatch_once` lazy singleton that appeared in v8, now reachable
because the rebinder fault is gone.

```
 5  libobjc.A.dylib   _objc_terminate
 6  Goodnotes         (terminate handler)
 7  libc++abi         std::__terminate
 8  libc++abi         __cxxabiv1::failed_throw
 9  libc++abi         __cxa_throw
10  libobjc.A.dylib   objc_exception_throw
11  (imageIndex 37)
12  (imageIndex 37)
13  libdispatch       _dispatch_client_callout
14  libdispatch       _dispatch_once_callout
15  (imageIndex 37)
...
22  UIKitCore         -[UIApplication _handleDelegateCallbacksWithOptions:...]
```

### Three things that stack proves

**1. It is still not anti-tamper, and it is not a signature failure.**
`objc_exception_throw` raises some *Objective-C object*. A check that wants the
process dead calls `exit()`/`abort()`, or traps. It does not build an
`NSException` first.

**2. v10's report could not have fired on this path.** That is why the launch
still ended as an anonymous `SIGABRT` with no `gnunlock-lastcrash.txt`.

`failed_throw` is what libc++abi reaches when `_Unwind_RaiseException` returns
without finding a single handler. In that state `__cxa_current_exception_type()`
is null, so libobjc's `_objc_terminate` takes the "no current exception" branch
and calls the default handler - which is exactly what frames 4 and 5 are. The
`NSSetUncaughtExceptionHandler` handler in `GNSupport.m` lives on the *other*
branch. It was never called, so nothing was recorded.

**3. The `@try` wrap in v9/v10 was not in the chain.** There is no frame of ours
anywhere between frame 11 and frame 26. The wrapper only ever went on the app
delegate's two launch selectors, which means either the delegate was installed
through a path that is not `-[UIApplication setDelegate:]`, or the callback that
threw is not one of those two. Either way: one net, in the wrong place.

### Your three questions, answered with evidence rather than opinion

**"Which ResignFix hook is throwing?"** None of them can be, and not because
they behaved well - because **they were never installed**:

- `EnableGOTRebinding` is `false`, and on a Distribution signature every C level
  fix (`SecItemCopyMatching`, `SecItemAdd`, `SecStaticCodeCheckValidity`,
  `SecCodeCopySigningInformation`, `SecTaskCopyValueForEntitlement`) goes
  through `GNInterposeSymbol()`, which refuses to touch a code page and, with
  that key off, refuses to rebind either. It logs `skipped, app keeps working`
  and returns `NO`. So the keychain hook you suspected has not run on any build
  you have installed.

**"Should I disable SecItemCopyMatching?"** Nothing to disable - see above.

**"Do we need a fake receipt?"** No, and it would make things worse:
`DisableAppStoreReceipt` is `false`, so that hook is not installed either, and a
fabricated receipt is an object the app parses and rejects, not one it accepts.

That leaves exactly one behaviour change of ours that was live at that moment:
**`ResignFix.AppGroupFallback` = `docs`**, which answers the missing app group
with `Documents/AppGroups/<group id>` - an empty directory that looks like a
container and is not one. A lazy singleton that opens a store in a container is
precisely the shape of the throwing frames. That is a hypothesis, not a finding,
and v11 is built so that a relaunch settles it.

### What v11 actually does

| Change | Why |
|---|---|
| **UIKit boundary net** - wraps `-[UIApplication _handleDelegateCallbacksWithOptions:isSuspended:restoreState:]` (frame 22) | The frame directly under both launch callbacks. It does not care who the delegate is or how it was set, which is the failure that made two builds blind. |
| **Net counter** - `GNGuardNetCount()`, logged every launch | "0 nets live" is now a loud line instead of something you discover after the next crash. |
| **Throw tracer** - `objc_exception_throw` tap (`GNThrowTrace.m`) | The one call every ObjC exception passes through. Gives name / reason / userInfo and the throw site with image + offset. Default `auto`: it only installs when the `@try` nets are all missing, because it is the only v11 code that writes a data page during dyld init. Always calls the real function. |
| **Experiment ladder** - one variable per launch | The run level says "it is the container fallbacks"; it cannot say *which answer*. Five relaunches settle it, no re-sign, no Mac. |
| **Ladder ratchet fixed** | v8-v10 re-read `gnunlock.state` from `GNRunLevel()`, which by then held the `boot` this launch had just written. `GNPhaseIsEarly("boot")` is yes, so **every** launch looked like a failed one and a healthy build walked 3 -> 2 -> 1 -> 0 in four launches. The previous phase is now captured in `GNLogBoot()` (`gPreviousPhase`). If you have relaunched v10 more than a few times, its later runs were not testing level 3. |
| **Ladders made mutually exclusive** | Both step on the same signal; running both changes the level *and* the container answer in one relaunch, which names neither. |

### The experiment ladder

`Documents/gnunlock.experiment` holds `<ConfigVersion>:<step>:<trying|won|exhausted>`.

| step | what changes |
|---|---|
| 0 | baseline - the plist as shipped |
| 1 | app group answers `nil` (the honest "no container") |
| 2 | app group answers the app's own container |
| 3 | app group hook removed entirely |
| 4 | keychain hook removed (only meaningful once rebinding is on) |
| 5 | **control**: run level 0, nothing of ours installed at all |

A step is abandoned when the launch before it never reached
`UIApplicationDidFinishLaunchingNotification`. The first step that survives is
kept (`won`) and the ladder stops. If all six fail, it ends `exhausted` at the
baseline - and step 5 is the one that matters most: **if the app still dies with
nothing of ours installed, the crash is the re-sign or the app, not this dylib.**

One variable at a time is enforced, not intended: the state machine is pure C in
`src/GNExperimentLadder.h`, and `scripts/experiment_ladder_test.c` executes it -
one step per launch, terminates within 6, never moves after settling. That test
runs in `stubcheck.sh`, `build.sh` and CI.

### What you should see

```
guard: boundary net installed on -[UIApplication _handleDelegateCallbacks...]
guard: 1 net(s) live
throw trace: 1 @try net(s) live, so the cheap capture is enough - not rebinding ...
config: experiment step 0/6 - baseline (plist as shipped) (trying)
```

Then one of:

- **The app launches.** The exception was caught at the boundary, named, and
  swallowed. `Documents/gnunlock-lastcrash.txt` has `name`, `reason` and the
  symbolicated stack; the alert shows the first lines; the pasteboard has all of
  it. Send that text - it names the framework behind `imageIndex 37`.
- **The app still dies.** Look at `gnunlock.log` for `guard: WARNING no net
  installed`. If present, the throw tracer is the answer and it is already armed
  in `auto`; if you want it regardless, set `GuardTraceThrow` to `always` and
  relaunch once. `Documents/gnunlock-exceptions.txt` receives one entry per
  throw, and the last entry is the one that killed the launch.
- **It dies at step 5 too** - then nothing of ours is involved and the next thing
  to look at is entitlements / the signing profile, not this dylib.

### Not proven

- That the boundary selector exists with that exact name on iOS 27 - it does in
  **your** `.ips` (frame 22), which is the only version that matters here.
- Which hook, if any, is guilty. v11 does not guess; it is built so the next
  launch says so.
- That swallowing the exception leaves a usable app: a `dispatch_once` block that
  threw stays entered, so the second caller can block. If the app hangs instead
  of crashing, set `GuardSwallow=false` - the report is written either way.

---

## What changed in v10

v9 got past the anti-tamper question and died **inside this dylib**. That is
progress: for the first time the crash belonged to us, which means it can be
fixed by reading code instead of guessing.

### The crash

    EXC_BAD_ACCESS / SIGBUS
    subtype: KERN_PROTECTION_FAILURE at 0x00000001991bc4b0
    thread 0 (com.apple.main-thread):
      _platform_strcmp$VARIANT$Base
      GNRebindSymbolInAppImages
      GNInstallLaunchGuard
      GNUnlockEntry
      dyld4::LibSystemHelpers::callInitializer

Read it literally:

* `KERN_PROTECTION_FAILURE` is **mapped but not readable**. Not a wild pointer
  into nothing - a pointer into a page the process may not read. The address is
  in the dyld shared cache region, i.e. nowhere near this app's string tables.
* `strcmp` is the reader. Something handed it a "symbol name" that is not a
  symbol name, and it walked until it hit a guard page.
* It ran from `dyld4::...::callInitializer`, i.e. from the dylib's **constructor**,
  before `main`, before the app, before our log had a chance to flush a line.
* `GNRebind` should not have been running at all: `EnableGOTRebinding` is
  `false`. `GNInstallLaunchGuard()` called the rebinder **directly** for its
  abort()/exit() tracer, so the switch that was supposed to keep rebinding off
  never applied to the one caller that runs at dyld time.

### Four defects, found by reading the decoder against Apple's header

| # | Defect | What it did |
|---|---|---|
| 1 | **Import table stride was wrong.** `dyld_chained_import` (4 bytes), `dyld_chained_import_addend` (4 bytes) and `dyld_chained_import_addend64` (8 bytes) do not share a size. v9 advanced by 8 and 16 for formats 2 and 3. | It read the **addend array** - or the neighbouring entry - as if it were an import, used the result as a string offset, and produced a pointer outside the string pool. That pointer is what `strcmp` was reading. |
| 2 | **`hdr + symtab->stroff`** treated a *file offset* as a *memory offset*, and `n_un.n_strx` was never checked against `strsize`. | Only correct while a segment happens to satisfy `vmaddr == fileoff`. One bad index was enough to point the classic path anywhere. |
| 3 | **No bounds check before comparison.** Every decoded name went straight into `strcmp`. | `strcmp` stops at a NUL that is not required to be in this mapping, so "unterminated" and "crash" were the same thing. |
| 4 | **The rebind ran during dyld init** and bypassed its own config switch. | A fault there is unobservable and fatal: no log line, no bisect, no notice. |

### What v10 changes

| Change | Where |
|---|---|
| `GNImportEntrySize()` is the only place an import stride is defined, and it is checked against Apple's layout by the build | `GNRebind.m`, `scripts/rebind_lint.py` |
| `GNImportSymbolName()` refuses any ordinal, table or name offset that does not fit the blob **and** does not end in a NUL inside it | `GNRebind.m` |
| Every base pointer comes from `GNFileOffsetToAddress()`, which maps a file offset through the segment table and verifies the result is mapped and readable | `GNRebind.m`, `GNSupport.m` |
| Every name comparison goes through `GNReadableCStringEquals()`: find the readable run, find the terminator inside it, then compare bytes | `GNRebind.m` |
| Chain walking is per page and page-relative. v9 compared `page * page_size + start` against `page_size`, so **every page after the first was skipped** and most slots were never examined | `GNRebind.m` |
| `GNRebindSymbolInAppImages()` checks `EnableGOTRebinding` (and safe mode) **itself**, before touching any image | `GNRebind.m` |
| The abort()/exit() tracer is **scheduled for after launch** and needs both `GuardTraceAbort` and `EnableGOTRebinding`. `GuardTraceAbort` is now `false` by default | `GNGuard.m`, `config/GNUnlock.plist` |
| The classic indirect symbol table is skipped entirely for chained-fixups images - one image, one mechanism | `GNRebind.m` |

Net effect on the launch path: **nothing of ours rebinds anything in the
constructor any more.** With the shipped config the constructor logs, installs
the delegate wrapper (method lists only) and installs the data hooks. There is
no import-table walk before `main`.

### Verification (this time the checks are executable)

* **Real front end, not eyes.** Every source compiles to an arm64 Mach-O with
  the clang front end (`scripts/stubcheck.sh`), `-Wall -Wextra` clean.
* **The decoder is unit tested** - `scripts/rebind_decoder_test.py` extracts
  `GNImportEntrySize()` / `GNImportSymbolName()` **out of the source** and runs
  them against synthetic blobs in all three import formats. It asserts each
  ordinal resolves to its own entry, that the wrong stride is caught, and that
  every out-of-range input returns NULL instead of a pointer.
* **The fixture is independent.** It lays blobs out with Apple's sizes written
  by hand, not with the function under test - otherwise a wrong stride would
  corrupt the fixture too and cancel itself out.
* **Mutation tested.** Re-injecting the v9 stride makes the decoder test fail
  (`format 2 ordinal 1 ... - strcmp`); deleting the terminator check makes it
  fail; removing the config gate or moving the tracer back into the constructor
  makes `rebind_lint.py` fail. Both scripts run in `build.sh` and
  `stubcheck.sh`.
* **Still not proven:** that the app gets past launch. That needs the device.

### What to expect from this build

Install, launch, and read `Documents/gnunlock.log`:

    guard: abort / exit tracing disabled (GuardTraceAbort=false)
    run level: 3 - ...
    memory policy: ... rebinding disabled

If the app now starts, the launch crash was ours and it is gone. If it dies
again, the crash is no longer inside the constructor: the guard wraps the
delegate callbacks, so a launch exception is caught, named and put on screen -
and `GuardSwallow=false` reproduces the original death exactly.

To re-enable the C level fixes (keychain / SecCode / SecTask) later, in this
order: `EnableGOTRebinding=true`, launch, then `GuardTraceAbort=true`, launch.
Each step is a separate launch so a failure names its own cause.

---

## What changed in v9

v8 built, injected, and the app still died at launch - the same `SIGABRT`, from
a *different* cause than v7. This time we have a stack. Here is what it says.

### The crash is an exception, not an integrity kill

    SIGABRT
    asi: libsystem_c.dylib: "abort() called"
    lastExceptionBacktrace:
      __exceptionPreprocess
      objc_exception_throw
      <image 38>  +66044
      <image 38>  +56896
      _dispatch_client_callout
      _dispatch_once_callout
      <image 38>  +56664
      <image 38>  +221920  <image 38> +221804  <image 38> +466432
      <main binary>  +5662488  +5522204  +731388  +758328
      -[UIApplication _handleDelegateCallbacksWithOptions:isSuspended:restoreState:]
      -[UIApplication _callInitializationDelegatesWithActions:forScene:payload:...]

Three things in that trace argue against an anti-tamper check, and one of them
is close to conclusive:

1. **`lastExceptionBacktrace` exists.** iOS writes that array only when an
   `NSException` was raised and left uncaught. The anti-tamper failure modes do
   not produce one: `exit()` / `abort()` straight from the check produce a bare
   `SIGABRT` with no exception backtrace, and Swift's `fatalError` / a failed
   force-unwrap traps with `SIGILL` or `SIGTRAP` and *no* `lastExceptionBacktrace`
   either. Whatever killed this app raised an Objective-C exception.
2. **It was raised inside `dispatch_once`.** That is a lazily initialised
   singleton - the shape Objective-C libraries use for "open the store / model /
   client once", not the shape a signature check uses. A check that decides "this
   binary is not mine" does not need lazy initialisation to do it.
3. **The throw site is in a framework the app called, three frames below its own
   delegate.** An exception raised by *our* hook would still be an exception, but
   it would be raised at our frame, not inside a framework's `dispatch_once`.

None of that rules out "the app raised because a re-signed app looks wrong to
it" - merely "it aborted because a check said no". Those are different fixes:
the first is about *what the app could not read*, the second about *neutering a
function*. v9 is built to tell them apart on the device instead of in prose.

### What v9 adds

| Change | Why |
|---|---|
| `GNGuard.m`: wraps `application:willFinishLaunchingWithOptions:` and `application:didFinishLaunchingWithOptions:` on the app delegate | the throwing code sits between `_handleDelegateCallbacks...` and the framework, so an exception raised there is caught here - and named, with `exception.name`, `exception.reason`, `userInfo` and the **symbolicated** stack. That single report answers "is image 38 one of GoodNotes' own frameworks or a system one" without needing `usedImages` at all |
| full dyld image table in the report | `"imageIndex": 38` becomes a path. The table is written by the process that has it, so a deleted `usedImages` stops mattering |
| report copied to the **pasteboard** | container access, a file manager, a working app and a Mac are all unavailable in this situation. Paste is not |
| `GuardSwallow` (default true) | the exception is recorded, then swallowed and the launch continues with `YES`. A launch that limps is more useful than one that dies. If it limps into a hang, set it false and the same report is recorded before the rethrow |
| `GuardTraceAbort` | rebinds `abort` / `exit` import slots **in app owned images only** (data pages, never code) and records the caller before calling the real one. This is the net for the case that would otherwise be invisible: a silent integrity kill by the app's own code. libobjc's own abort is *not* caught - it is inside a system image - because that path is already covered by the exception handler |
| the auto-bisect ladder now steps **without** a crashed launch | a caught exception drops one level and writes the bisect file, so one bad rung costs one launch, not one boot loop |
| `ResignFix.AppGroupFallbackMode` = `docs` / `nil` / `home` | the app group fallback invents an *empty* directory where the shared container used to be. An app that force-unwraps `nil` needs that; an app that trusts the URL and finds an empty store takes a different code path than the "container missing" one it tests for. Which of the three is right is a property of the app, so it is config |
| two new CI lints | `GNGuard.m` may not call `abort()` / `exit()` directly (its own slots are rebound, so that recurses), and the guard must be installed *before* the run level gate (level 0 included). The first is a workflow step; the second is `legacy-guard-first` in `scripts/v12_lint.py` as of v12 — in v9–v11 it was a line-number grep against `src/GNUnlock.m`, which is exactly what broke the v12 build |

### How to read the result

One launch should be enough to name the culprit. In order of usefulness:

1. **Sign the same IPA with no dylib at all** and install it.
   - dies with the same `SIGABRT` + `lastExceptionBacktrace` → the crash is the
     re-sign, not this dylib. Nothing in `GNUnlock` can fix a launch that dies
     before it is loaded; the fix becomes "make the app find what it is looking
     for" (container / keychain / receipt), not "hook a check".
   - boots fine → the crash is caused by something we install, and step 2 finds
     which group.
2. **Install v9 as-is and open it.** Either the app boots (and the alert tells
   you the level it dropped to), or it hangs, or it dies again.
   - boots, level still 3, no alert → no exception was caught, no `abort`
     traced: whatever happened is neither an exception in the delegate path nor
     an app-side `abort`. Send the `.ips` **with `usedImages`** and the log.
   - boots at a lower level → the caught report names the exception and the
     frames. That is the diagnosis; the level says which group to look at.
   - hangs → the swallow left a `dispatch_once` gate entered. Set
     `GuardSwallow` false: the report is still recorded and copied to the
     clipboard, and the app dies as before.
   - dies → read the clipboard / the `.ips`. If a `guard-abort` section is in
     the report, it was an app-side `abort()` and the stack names the checker.
3. **If it really is an integrity check**, the fix is *not* a runtime hook: on a
   Distribution signature we cannot write a code page, so "return early from the
   check" has to happen **before signing** - find the function statically, patch
   it on disk with `scripts/gnstatic.py`, re-sign. That is the same tool the
   unlock path already uses.

---

## What changed in v8

v7 got past `CODESIGNING / Invalid Page` and then the app died differently:
`SIGABRT`, an `NSException` thrown inside a `dispatch_once` block, three frames
below `-[UIApplication _handleDelegateCallbacksWithOptions:...]`. Nothing of
ours appears in that stack, which is the whole problem: a hook that hands the
app a bad value does not show up as a frame, only as a consequence.

So v8 does not try to guess which hook it was. It makes the app tell us:

| Change | Why |
|---|---|
| **Run levels 0-3** (`RunLevel`) | hooks are grouped so one launch can leave a whole group out |
| **Auto-bisect** (`AutoBisect`) | a launch that dies before `didFinishLaunching` costs **one** crashed launch and drops one level on the next boot; the ladder stops at the first level that boots |
| **On screen reporting** (`ShowLaunchNotice`) | the settled level, and the previous launch's `NSException` name, reason and symbolicated stack, are shown in an alert after launch - no container access, no Mac |
| `Documents/gnunlock-lastcrash.txt` | the uncaught exception handler writes that note before the abort |
| `-[NSUserDefaults initWithSuiteName:]` swizzle **removed** | it is an init-family selector: the caller consumes +1, a C function returns +0, and the old body called `init` a second time on `self` after the first call had already returned `nil`. See `GNResign.m` |
| `Hooks.SYDIdentifier` default **off** | it was a pass-through that changed nothing while `dlopen`ing a private framework from the constructor |
| every hook body wrapped in `@try` | a hook may be useless; it may not throw into the app's call stack |
| image table dumped at boot | `"imageIndex": 38` in a crash report becomes a name |
| `%s` uptime on every log line | "died at +0.9s" and "died at +12s" are different diagnoses |

The levels:

```
3  everything        container fallbacks + keychain / SecCode / SecTask
2  + containers      data hooks + app group / ubiquity fallbacks
1  data hooks        NSUserDefaults overrides only
0  inert             log and diagnostics only, nothing installed
```

How to read the result:

- boots at **3** → the crash was not ours, or it was in a path this launch did
  not take. Try to reproduce it and send the notice text.
- boots at **2** → the crash was in the C level interposition group. That group
  is skipped on a Distribution signature anyway (`EnableGOTRebinding` off), so
  this should not happen; if it does, the log says which `interpose` line ran.
- boots at **1** → the **app group fallback** is the suspect: the app gets a
  directory under `Documents/AppGroups/` instead of the real shared container
  and does not like what it finds there.
- boots at **0** and still dies → **not our code.** Nothing of ours is
  installed at level 0. The exception is the app's own, and the note explains
  why. That is also the answer to "does this dylib cause the crash".

`Documents/gnunlock.bisect` holds `<ConfigVersion>:<level>`, so the next build
starts the ladder over. Delete the file to go back to `RunLevel` immediately.

---

## The one rule this version is built around

> Writing to a code page in a re-signed app is not "risky". It is a guaranteed
> kill, and it is exactly what the `CODESIGNING` / `Invalid Page` crash was.

The mechanism, once, because everything else follows from it:

`vm_protect(..., VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)` on a page that
belongs to a signed image does not make the page writable in place. It creates a
**private anonymous copy** of it. Your bytes land in that copy, then you mark it
executable, and the first time the CPU fetches an instruction from it, pmap asks
"is this page covered by a valid code signature?" — it is not — and amfi kills
the task:

```
termination reason : CODESIGNING / Invalid Page
ktriageinfo        : Failed to fault in a page with execute permissions
```

The only process that tolerates it is one with `CS_DEBUGGED` (a
`get-task-allow` entitlement, i.e. a **Development** signature). That is a
property of the certificate, not of the code. On your **Distribution**
certificate it is never available.

v2 was doing exactly that, twelve times, on `SecItem*`, `SecStaticCode*` and
`SecTask*` — all of them inside the dyld shared cache. The page that died at
`0x1a2e9b680` (`SecTaskCreateFromSelf`) was collateral from the `SecTask*` hooks
in the same Security.framework image.

So v3 splits every mechanism into two classes:

| class | safety | used for |
|---|---|---|
| **code writes** | must be re-signed → impossible on Distribution | offline, before signing |
| **data writes** | invisible to the code signing check | everything at runtime |

That is the whole design. `src/GNCapability.m` is the gate, and every write path
asks it first.

---

## What changed in v7

v6 did not build, and it failed on a line that had already been fixed once, in
v4. That is the real subject of this section: not just the line, but why it came
back and why only one error at a time was ever visible.

**The regression.** `src/GNSupport.m` was back to

```c
#import <mach/mach_vm.h>
...
kern_return_t kr = mach_vm_region(...);
```

On iOS that header's entire contents are `#error mach_vm.h unsupported.`, so the
include aborts the translation unit and `mach_vm_region` is undeclared — one
include, two diagnostics:

```
mach_vm.h:1:2: error: mach_vm.h unsupported.
GNSupport.m:557:24: error: call to undeclared function 'mach_vm_region'
```

v4 had solved this by importing `<mach/vm_map.h>` and resolving the query at run
time. v7 restores exactly that shape: `vm_region_64` is looked up with `dlsym`
and, if it is not there, the query degrades to the segment's `initprot` — which
this function already used for regions it could not describe. Resolving it
instead of linking it also means the dylib has no link-time dependency on the
symbol at all.

**Why it came back.** Nothing checked that an include resolves. The per-slice
front-end pass added in v5 does compile every file, but it `exit 1`-ed on the
first failure — so v5 never got past `GNRebind.m:216` to reach `GNSupport.m`,
and every round trip through CI revealed exactly one line. Two changes:

- The front-end pass now compiles **every** file for **both** slices, collects
  the failures, prints all of them, and only then stops.
- A header check runs before any source is compiled: each `<...>` include is
  offered to the SDK on its own, and a header the SDK rejects or does not ship
  fails the build with one line naming that header. Includes behind
  `__has_include` are skipped — they are optional by construction.

**A trap that had never fired.** Now that compilation succeeds, the build
reaches its verification block, which had not run since v3. It used
`strings ... | grep -q`. Under `set -o pipefail`, `grep -q` exits on the first
match, `strings` takes SIGPIPE, and the pipeline reports 141 — so a *successful*
match reads as failure. Three checks (baked config, capability keys, install
name) were one compile away from failing the build for no reason. They now
search a file written once, not a pipe. Found by driving the whole script with a
stand-in toolchain, not by reading it.

**The assembly is no longer unverified.** v5 and v6 could only say the PAC
sequences were syntax-checked. They are now assembled for real: all four, with
the modifier coming from `x9`, go through an aarch64 assembler with PAuth
enabled, and the object file holds four distinct encodings with `Rn = x9`:

```
0xdac10128   pacia  x8,  x9
0xdac1052a   pacib  x10, x9
0xdac1092b   pacda  x11, x9
0xdac10d20   pacdb  x0,  x9
```

That is the architectural claim the design rests on, checked in the output
rather than asserted in a comment. It still does not prove the callee's `autia`
accepts the result — only the device can.

**How this was checked before shipping it.** A stub SDK was built that
reproduces the two things that actually break: a poisoned `<mach/mach_vm.h>` and
Apple's bare struct tags in `<mach-o/fixup-chains.h>`. Against it:

- all seven sources parse for arm64 and arm64e — 0 errors, 0 warnings, with the
  flags the build uses — and putting the regression back reproduces the exact v6
  failure at `GNSupport.m:557`, so the harness is calibrated against a known
  failure rather than trusted;
- three injected faults (a missing `struct`, a dropped `#include <string.h>`, a
  mistyped call) are each caught with file, line and the fix-it hint, so it is
  known to be sensitive and not merely quiet;
- the pre-Xcode-13 path is compiled too — no `<mach-o/fixup-chains.h>`, no
  `<ptrauth.h>`, no `<execinfo.h>` — which exercises the hand-written
  `GNAuthBindPtr` mirror, proven by breaking a field name in it and being told
  so;
- the PAC branches are forced on and compiled, because a non-Apple toolchain
  does not set `__has_feature(ptrauth_calls)` by itself — proven by breaking a
  key name in them and being told so;
- every source also goes through real code generation, not just the front end,
  for both variants.

None of that replaces the CI compile: the stub SDK is a reconstruction and the
real SDK is the authority on what the real SDK accepts. What it does mean is
that the next CI run starts from a tree whose known error classes were checked
mechanically instead of by eye.

---

## What changed in v6

v5 did not build. The per-slice front-end pass added in v5 is the reason it
failed fast and named the file, which is the one good thing about it:

```
src/GNRebind.m:216:13: error: must use 'struct' tag to refer to type
        'dyld_chained_ptr_arm64e_auth_bind'
```

Apple declares every dyld type as a bare struct tag. There is no typedef behind
`dyld_chained_ptr_arm64e_auth_bind` — only `struct dyld_chained_ptr_arm64e_auth_bind`
— so naming it without the keyword is a hard error. This class of mistake only
appears once the iOS SDK is on the include path, which is why nothing on the
Linux side would ever have caught it.

**The tag is now spelled once.** `GNRebind.m` has

```c
#ifdef GN_HAVE_FIXUP_CHAIN_STRUCTS
typedef struct dyld_chained_ptr_arm64e_auth_bind GNAuthBindPtr;
#else
typedef struct { /* the same declaration, field for field */ } GNAuthBindPtr;
#endif
```

and the decoder names `GNAuthBindPtr`. No call site mentions an Apple type, so
no call site can be missing a keyword. A `sizeof` guard makes the struct
growing a compile error rather than a memcpy that reads past the word.

Guarded, both in `scripts/build.sh` and in CI: any Apple dyld struct type named
outside a `struct` declaration fails the build. The check has to match the same
thing the compiler does, which is why it is a lint step and not a comment.

**Two things the review turned up, which are the reason this is not just a
one-word fix:**

1. **The v5 bit offsets were wrong.** v5 documented the auth bind as
   `ordinal:16 zero:8 …`, which put `diversity` at 24, `addrDiv` at 40, `key` at
   41 and `next` at 43. The header says `zero:16`, so the real layout is
   diversity at 32, addrDiv at 48, key at 49, `next` at 51 — the same `next` as a
   plain bind. A slot decoding under the v5 fallback came out as
   `div=0xEF00 addrDiv=0 key=3 next=2039` for a slot that is
   `div=0xBEEF addrDiv=1 key=3 next=2047`. On a modern SDK v5 went through
   Apple's struct and was therefore right in practice; the fallback path and the
   documentation were not. Both now come from the same declaration.
2. **The pointer-format numbers were wrong.** The file had
   `ARM64E_USERLAND 10` and `ARM64E_FIRMWARE 11`. In the header those are **9**
   and **10** (11 is `X86_64_KERNEL_CACHE`). So a segment tagged 10 — kernel
   firmware, stride 4, laid out differently — was classified as userland and
   walked with stride 8. It is now refused: the walker skips it and logs. This
   never mattered for an iOS app image, which is exactly why it was never found.

---

## What changed in v4 and v5

Two CI runs failed in a row, both on the arm64 slice that only the *other* one
exercises. Neither failure was in the mechanism; both were in the code that
reads the Mach-O.

**v4 — `mach_vm.h`.** On iOS that header is a single line, `#error mach_vm.h
unsupported`. So `#import <mach/mach_vm.h>` aborted the translation unit and
`mach_vm_region` was never declared — and in C99 an implicit declaration is a
hard error, which is why one trap produced two diagnostics. `src/GNSupport.m`
now imports `<mach/vm_map.h>` and resolves the trap with `dlsym` at run time,
keeping the segment `initprot` as the fallback it already had. **v5 then lost
this fix and v7 had to restore it — see "What changed in v7" for why the build
never noticed.**

**v5 — `ptrauth_sign_unauthenticated`.** `GNRebind.m` is the only file that
signs a pointer, and it signed with a discriminator read out of the chained
fixup. `ptrauth_sign_unauthenticated` lowers to
`__builtin_ptrauth_sign_unauthenticated`, whose discriminator operand has to be
an **integer constant expression**, so arm64e rejected the call:

```
src/GNRebind.m:255:70: error: expression is not an integer constant expression
```

That restriction is the front end's, not the hardware's. A PAC instruction
takes its modifier from a general purpose register — `pacIA Xd, Xn` — which is
how dyld signs these same slots while fixing up an arm64e image. `GNSignPointer()`
is now that sequence written out, one variant per key (`pacia` / `pacib` /
`pacda` / `pacdb`), with the discriminator coming from the chain.

The same pass fixed a bug that had been hiding behind the compile error:

- An auth bind is **not** laid out like a plain bind: it reuses the bits a plain
  bind spends on `zero` and `addend` for `diversity` / `addrDiv` / `key`. v5
  wrote those as bits 24/40/41 and `next` at 43; that was a mis-transcription of
  the `zero` field as 8 bits when the header says **16**, and it is wrong. The
  published layout is `ordinal:16 zero:16 diversity:16 addrDiv:1 key:2 next:11
  bind:1 auth:1`, i.e. diversity at 32, addrDiv at 48, key at 49 and **`next` at
  51 — the same place as a plain bind**. v6 decodes through Apple's own
  `dyld_chained_ptr_arm64e_auth_bind` (`<mach-o/fixup-chains.h>`) and the
  hand-written mirror used on older SDKs is transcribed from that header, so the
  two cannot disagree.
- A slot that cannot be signed — an arm64 slice looking at an auth slot — is
  now **left alone** instead of being written with an unsigned pointer. An
  unsigned pointer in an `__auth_got` slot is not a weak hook, it is a crash on
  the first call.
- A pointer format the walker cannot vouch for (the arm64e kernel and firmware
  layouts) is now skipped instead of being walked with a guessed stride. A wrong
  stride does not fail loudly; it walks into the neighbouring slot and rewrites
  a pointer that belongs to something else.
- The build no longer hides a slice failure. `build_arch` runs its body in a
  context where `set -e` is disabled (it is tested by an `if`), so a failing
  `clang` used to fall through and surface as `lipo: can't open input file`.
  It now checks the status, and an arm64e failure is fatal unless you opt out
  with `ALLOW_ARM64_ONLY=1`.

v5 also adds a per-slice front-end pass before the link, so a slice-specific
error names the file instead of hiding inside the combined compile.

---

## What changed in v3

- **All `BytePatches` / `Anchors` that rewrote executable memory: removed.**
  Both arrays ship empty, and both code paths now refuse to write when the
  process is not debug-signed — with a log line, not a crash.
- **The `SecTaskCreateFromSelf` anchor: gone.** The effect it was after (forcing
  the SyncedDefaults identifier) is now a single ObjC message, in
  `Hooks → SYDIdentifier`. No shared cache page involved.
- **C level re-sign fixes no longer inline hook.** They go through
  `GNInterposeSymbol()`: debug signature → classic hook; Distribution → rewrite
  the app's own `__got` / `__auth_got` / `__la_symbol_ptr` slots (data pages), or
  skip and log.
- **System images are refused outright**, on any certificate — a target inside
  `/System`, `/usr/lib` or the shared cache is never patchable by us, so the
  patch engine says so and moves on instead of killing the app.
- **New data-only hooks**: `NSUserDefaults` interception, SyncedDefaults
  identifier override, and forged HTTP responses via a registered `NSURLProtocol`
  (public API — not a hook at all).
- **New offline patcher**, `scripts/gnstatic.py`: applies byte patches and strips
  foreign dylibs **inside the IPA, before signing**, with byte verification. This
  is the only supported way to change app code under a Distribution certificate.
- **`libsubstrate.dylib` / `LoadControl.dylib` from the IPA are removed** by the
  same script, load commands and files both.

---

## Repo layout

```
.github/workflows/build-dylib.yml   lint job + macos-14 build, uploads the dylib
config/GNUnlock.plist               baked into the dylib at build time
config/entitlements.icloud.plist    the iCloud entitlements to sign with instead
src/GNReadAudit.m                   who asked a repaired door, and did it change
scripts/build.sh                    local build (same script CI runs)
scripts/plist_expect.py             the shipped plist's defaults, one home, mutation tested
scripts/bake_plist.py               plist -> C header
scripts/gnstatic.py                 offline IPA patcher / dylib stripper / selftest
analysis/tools/anchor.py            cstring -> function offset -> patch file
patches.example.json                patch file format for gnstatic.py
src/GNUnlock.m                      entry point / lifecycle
src/GNCapability.m                  CS_DEBUGGED probe, the write gate
src/GNSupport.m                     log, crash-loop state, Mach-O, memory writes
src/GNRebind.m                      data-only symbol interception
src/GNResign.m                      re-sign crash fixes
src/GNGuard.m                       launch forensics (boundary net + delegate net)
src/GNThrowTrace.m                  objc_exception_throw tap (opt-in)
src/GNPrivateSecTask.h              the only place the private SecTask API is named
src/GNPrivateSecTask.m              dlsym resolution of those symbols, Foundation free
src/GNProbe.m                       entitlements + container answers, read only
src/GNExperimentLadder.h            experiment ladder state machine, pure C
scripts/experiment_ladder_test.c    executes that state machine
scripts/v11_lint.py                 v11 invariants + mutation selftest
src/GNPatch.m                       byte patches, anchors, swizzles, recon
src/GNHooks.m                       defaults / SyncedDefaults / forged responses
analysis/                           reverse engineering from the earlier pass
```

---

## Build

Push to `main` and take the artifact, or locally:

```bash
bash scripts/build.sh
# -> out/GNUnlock.dylib   (arm64 + arm64e, install_name already set)
```

The build fails instead of shipping something broken. Before compiling it checks
that the plist parses and that `AllowCodePatching` is still `false`; after
linking it checks the install name, that no Substrate symbol leaked in, that the
v3 capability keys really got baked in, and that no `VM_PROT_WRITE|VM_PROT_EXECUTE`
request exists anywhere in the sources.

### Pre-flight without a Mac

```bash
pip install ziglang
./scripts/stubcheck.sh
# ok      GNCapability.m  (14240 bytes)
# ok      GNHooks.m       ...
```

`scripts/stubcheck.sh` compiles every source to a real arm64 object with the
clang front end that ships inside zig, against `scripts/stubsdk/` — a small
reconstruction of Foundation / UIKit / Security / CoreFoundation that declares
only what this project calls, plus a `<mach/mach_vm.h>` that `#error`s exactly
the way iOS does.

It takes about a second and a half, and it reproduces the two mistakes that
actually cost builds here:

| Injected fault | What it reports |
|---|---|
| `#import <mach/mach_vm.h>` + a `mach_vm_region` call (v6) | `mach/mach_vm.h: error: mach_vm.h unsupported.` **and** `call to undeclared function 'mach_vm_region'`, with line numbers |
| `dyld_chained_ptr_arm64e_auth_bind x;` without `struct` (v5) | `must use 'struct' tag to refer to type ...` with the fix-it |

It is a pre-flight, not the truth: the stub SDK is a reconstruction, so it cannot
prove that the real SDK declares everything the stub does. The macOS job is still
the authoritative build — this just stops you paying a full CI round trip for a
typo.

---

## Inject with LC Sign

1. Add the dylib at **`Frameworks/GNUnlock.dylib`**.
2. Turn on "sign injected libraries / frameworks".
3. Sign with the Distribution certificate, install.

Then read `Documents/gnunlock.log` (Files app, or `idevicesyslog | grep GNUnlock`).

The first two lines after the banner are the ones that matter:

```
capability: signature=distribution CS_DEBUGGED=no AllowCodePatching=no -> codePatching BLOCKED
memory policy: signature=distribution codePatching=blocked gotRebinding=disabled
```

`codePatching BLOCKED` is the proof that this build cannot repeat the v2 crash.

---

## Step 0 — clean the IPA before you inject

The IPA you are working from is not stock: it already carries
`libsubstrate.dylib` and `LoadControl.dylib` from an earlier pass. They are not
what produced *this* crash, but they are a live liability — Substrate's whole
model is inline hooking, which is the one thing a Distribution signature cannot
survive, and `LoadControl` is a loader shim that may `dlopen` its own list.

```bash
python3 scripts/gnstatic.py info   in.ipa          # see what is in there
python3 scripts/gnstatic.py strip  in.ipa -o clean.ipa
```

`strip` removes the `LC_LOAD_DYLIB` commands (compacting the load command area,
leaving every file offset intact), deletes the matching `.dylib` files, and
re-zips. You still keep your own `GNUnlock.dylib` — it is only in the bundle
because you are about to add it, so inject after stripping.

Confirm it worked:

```bash
python3 scripts/gnstatic.py info clean.ipa | grep -A8 dylibs
```

---

## Unlocking with a Distribution certificate

Four levers, cheapest and safest first. All of them are data-only.

### 1. Preference overrides (already on)

`Hooks → Defaults` interposes `-[NSUserDefaults objectForKey:]` and the typed
getters, so a key keeps returning our value even after the app writes its own.
The plist ships with the mock-entitlement keys from `analysis/FINDINGS.md`.

This cannot crash and it costs nothing if the app does not read those keys. It
is the cheap first attempt, not a guarantee: those keys belong to the QA purchase
service, and whether that service is assembled in a release build is unverified.

### 2. SyncedDefaults identifier (installed, pass-through)

`Hooks → SYDIdentifier` overrides
`+[SYDClientToDaemonConnection defaultStoreIdentifierForCurrentProcessWithApplicationIdentifier:]`
— the same effect the v2 anchor was after, as one ObjC message instead of a
shared-cache write.

It ships **enabled with an empty `Override`**, which means: hook installed, value
logged, original returned unchanged. A first launch therefore proves the hook is
live without changing anything. Fill in `Override` when the log shows the app
resolving an identifier it does not expect (typically after a re-sign, when
iCloud key-value sync misbehaves).

### 3. Forged HTTP responses (off by default)

The entitlement source is a server, so serve it yourself — with
`NSURLProtocol`, which is a supported Apple API, not a hook:

```xml
<key>URLForge</key>
<dict>
  <key>Enabled</key><true/>
  <key>Rules</key>
  <array>
    <dict>
      <key>Match</key><string>/entitlements</string>
      <key>Method</key><string>GET</string>
      <key>Status</key><integer>200</integer>
      <key>Body</key><string>{"currentPlans":{"base":{"planKey":"premium"}},"entitlements":{"pro_access":true,"crossplatform_access":true}}</string>
    </dict>
  </array>
</dict>
```

I do not have the real endpoint or payload schema in this repo — only the shape
from the string analysis (`currentPlans.base.planKey`, `entitlements.pro_access`
/ `crossplatform_access`, `quotas.ai.quota`). You need one capture of the real
response to fill this in. Until then this stays off.

### 4. Offline patch — the only way to change Swift code

The purchase stack is Swift with no `@objc` members (8,074 ObjC classes in the
binary, zero methods on `LivePurchaseService`), so there is nothing to swizzle.
The getter that decides "pro" is a Swift function, and the only way to change it
is to change the bytes **in the Mach-O, before it is signed**.

That is what `gnstatic.py patch` is for:

```bash
# 0. the decrypted app executable, straight out of the IPA
unzip -o clean.ipa Payload/Goodnotes.app/Goodnotes

# 1. find the function that owns the string you care about.
#    It prints the function start as a __TEXT-relative offset, plus the bytes
#    already there (that is your 'expect').
python3 analysis/tools/anchor.py Payload/Goodnotes.app/Goodnotes \
        --string missing_active_pro_entitlement
#   "missing_active_pro_entitlement"  cstrings=['0x...']
#      hit 0   ref=0x7d42b9c  func static=0x7d42b98  first bytes=fd 7b bf a9

# 2. turn that hit into a patch file, in one shot
python3 analysis/tools/anchor.py Payload/Goodnotes.app/Goodnotes \
        --string missing_active_pro_entitlement --hit 0 \
        --image-name Goodnotes \
        --bytes 20008052c0035fd6 --json patches.json

# 3. apply it: byte check, write, repack. Then sign the result with LC Sign.
python3 scripts/gnstatic.py patch clean.ipa -o patched.ipa --patches patches.json
```

`patches.example.json` shows the file format if you would rather write it by hand.

Which string to anchor on is the judgement call, and it is the one part I cannot
do from here: `paywall_pro_only`, `missing_active_pro_entitlement`,
`special_edition_subscription`, `com.goodnotes.gn6_one_time_unlock_3999` and
`LIFETIME(entitlement=` are all in `analysis/FINDINGS.md` with their reference
sites. Start with an `Action: log` anchor in the plist if you want the runtime
view of the same hit before committing to an offline patch.

`20008052c0035fd6` is `mov w0, #1 ; ret`. `expect` is not optional in practice:
it is the difference between "patched the right function" and "wrote eight bytes
into the middle of something else in a 260 MB binary". If it does not match, the
script refuses and writes nothing.

Because the edit happens before signing, the new signature covers the new bytes
and there is no COW page, no amfi kill, no crash-loop breaker needed.

---

## Verification status — read this before flashing

What is tested here:

- **v9: every source file is compiled, not just read.** All 9 translation units
  are built to real arm64 Mach-O objects with clang (through zig's bundled
  compiler) against a stub SDK that declares Foundation / UIKit / Security /
  CoreFoundation with the SDK's signatures, with `-fobjc-arc -fblocks` and
  `-Wall -Wextra`. The four files that changed in v8 are warning-free. The
  authoritative compile is still the CI build — the stub SDK is a reconstruction
  and cannot prove anything the real SDK offers is present — but it does prove
  the sources parse, type check and generate code.
- `scripts/gnstatic.py selftest` runs in CI and on every build: it builds a
  synthetic Mach-O, applies a patch with byte verification, refuses a mismatched
  one, strips two dylib load commands, and re-parses the header.
- The plist is parsed and its safety keys asserted on every build.
- The source is compiled for arm64 and arm64e by the workflow, and every
  translation unit is front-end checked per slice before the link — that is what
  caught v4, v5 and v6.
- **v11: `scripts/v11_lint.py` + `--selftest`.** Seven invariants, each naming a
  defect that actually shipped (the ratchet, the single net, the tracer not
  calling through, the tracer not being opt-in, two ladders moving at once, and
  the resolve path drifting away from the tested state machine). `--selftest`
  mutates the sources and requires each check to fail for its stated reason —
  a gate that cannot fail is theatre.
- **v11: `scripts/experiment_ladder_test.c` executes the ladder.** The state
  machine was moved into `src/GNExperimentLadder.h` (pure C) so that the test
  runs *the shipped code*, not a transcription of it. It asserts: one step per
  launch, terminates within 6 launches, never moves after `won`/`exhausted`, and
  never returns a step outside the range. Mutating `next >= count` to
  `next > count` makes it fail on 15 assertions, which is how it was checked.
- The v6 auth-bind decode is compiled and run here against **Apple's own**
  `<mach-o/fixup-chains.h>` (fetched from `apple-oss-distributions/dyld`) as
  well as against the fallback mirror with no header at all. Both builds produce
  identical field values for hand-built words: diversity at 32, addrDiv at 48,
  key at 49, next at 51, for both format 1 and format 12, with the 16/24 bit
  ordinal split, plain binds, 64-bit binds, and the auth-rebase rejection.
  The struct-tag error itself was reproduced first against a stub that declares
  the type as a bare tag, so the fix is tested against the failure, not against
  a description of it.
- The signing sequence is assembled, not just parsed: `pacia` / `pacib` /
  `pacda` / `pacdb` with the modifier in `x9` go through an aarch64 assembler
  with PAuth enabled, and the output contains four distinct encodings
  (`0xdac10128`, `0xdac1052a`, `0xdac1092b`, `0xdac10d20`), each with `Rn = x9`.
  What that still does not prove is that the callee's `autia` accepts the
  result; only the device can, which is one more reason `EnableGOTRebinding`
  ships off.
- Every source is also run through a stub SDK that poisons
  `<mach/mach_vm.h>` the way iOS does and declares Apple's dyld types as bare
  struct tags the way the SDK does, for both slices, with three injected faults
  to confirm that the harness actually reports what it should.
- The v4 lesson is now a lint in two places: any `mach_vm_*` in `src/` fails the
  build, and the `vm_region_64` lookup has to still be there.
- The two v9 invariants are lints in both `scripts/build.sh` and the CI lint
  job. The `abort()`/`exit()` recursion check is mutation tested: injecting a
  call into a copy of `GNGuard.m` fails it with the line number.
  The guard-before-gate ordering check was, in v9–v11, a `grep -n` comparison in
  the workflow - it was *not* mutation tested, and in v12 it became a build
  failure, because the two statements it counted had moved to `GNLegacy.m`. It
  is now the `legacy-guard-first` rule in `scripts/v12_lint.py`, which parses
  the function body and is mutation tested like the rest; a workflow step that
  greps source by line number is itself a lint failure (`ci-no-line-numbers`).
  The lint job itself was run locally - all 14 of its steps - against this tree
  before packaging.
- One stub-versus-SDK divergence was found this way and fixed: the stub
  declared `-callStackSymbols` on `NSThread` but not `+callStackSymbols`, so a
  call that is valid against the real SDK failed the pre-flight. The stub was
  corrected rather than the source.

What is **not** tested, because there is no device and no binary here:

- The dylib has not been run on a device. The compiler is the only reviewer the
  C got. That includes the v8 ladder and everything in `GNGuard.m`: the phase
  bookkeeping, the descent, the delegate wrapper, the pasteboard copy, the
  abort tracer and the alert have been reasoned through and compiled, but not
  executed, because there is no iOS device here. The first launch is the test.
- In particular, whether UIKit calls the delegate's launch selectors through
  the ObjC method list after `class_replaceMethod` is an assumption about the
  runtime (it is how every tweak swizzles UIKit, but it is still an assumption).
  The log line `guard: launch entry points wrapped` is the proof that the
  wrapper is in place; if that line is missing, the only net left is the
  uncaught exception handler in `GNSupport.m`.
- `GNRebind.m` (the `__got` walker) has not been exercised against a real
  chained-fixups image, and the auth-bind layout is now taken from Apple's
  struct definition rather than confirmed against a live walk. It is off by default for that reason. When you enable it,
  check the log for `rebind '<symbol>': N slot(s)` before trusting it.
- The mock-entitlement keys are a hypothesis until the log shows the app
  reading them.

I would rather say that plainly than hand you a build that claims to be verified.

---

## Config reference

| Key | Meaning |
|---|---|
| `ConfigVersion` | 17 — also stamps `gnunlock.bisect` and `gnunlock.experiment`, so a new build resets both ladders |
| `Enabled` | master switch |
| `RunLevel` | 0-3, how much of the dylib may run (see the top of this file) |
| `AutoBisect` | drop one level per launch that dies before the app finishes launching |
| `ShowLaunchNotice` | put the settled level and the last exception on screen after launch |
| `DryRun` | log what would be written, write nothing |
| `Delay` | seconds before the patch pipeline runs (keep > 0) |
| `AllowCodePatching` | **leave false.** Code writes need this *and* `CS_DEBUGGED` |
| `EnableGOTRebinding` | data-only symbol interception; off by default |
| `Recon` | dump images, `__text` bounds, all classes to `gnunlock-recon.txt` |
| `LogImages` | log the loaded image table with base/slide |
| `ProbeClasses` | dump the immediate-member block of named Swift classes |
| `BytePatches` | `{Image, Offset, Bytes, Action, Note}` — empty by default |
| `Anchors` | `{String, Action, Mode, Occurrence, MaxHits}` — empty by default |
| `Swizzles` | `{Class, Selector, Behavior, ClassMethod}` — data only, always safe |
| `Hooks.Defaults` | `{Key, Value}` pairs forced on every read |
| `Hooks.SYDIdentifier` | `{Enabled, Override}` |
| `Hooks.URLForge` | `{Enabled, Rules:[{Match, Method, Status, Body, ContentType}]}` |
| `BoolKeysTrue` / `BoolKeysFalse` / `DefaultsSet` | one-shot `NSUserDefaults` writes |
| `GuardEnabled` | launch forensics: wrap the app delegate's launch selectors, record what throws |
| `GuardSwallow` | true: record then continue the launch. false: record then rethrow |
| `GuardCatchWillFinish` / `GuardCatchDidFinish` | which launch selector to wrap |
| `GuardCatchBoundary` | wrap `-[UIApplication _handleDelegateCallbacksWithOptions:...]` - the net that does not depend on the delegate (v11) |
| `GuardTraceThrow` | `auto` / `always` / `never` - tap `objc_exception_throw` when the `@try` nets are missing (v11) |
| `GuardTraceThrowBudget` | how many throws to record per launch (default 40; the last entry is the fatal one) |
| `AllowDiagnosticRebinding` | lets the throw tracer rebind *that one* symbol without turning on `EnableGOTRebinding` (v11) |
| `ExperimentLadder` | one variable per launch, see "The experiment ladder" (v11) |
| `GuardCopyToPasteboard` | copy the full report (exception, stack, image table) to the pasteboard |
| `GuardTraceAbort` | trace `abort()` / `exit()` called by app owned code, then call the real one |
| `ResignFix.AppGroupFallbackMode` | `docs` / `nil` / `home` — what to answer when the app group is gone |
| `ResignFix.*` | individual re-sign fixes, see the plist comments |

`Action`: `log`, `ret0`, `ret1`, `nop`, `bytes`.
`Behavior`: `true`/`one`, `false`/`zero`, `orig`/`skip` — no signature needed,
both work at the ABI level whatever the declared return type is.

Resolution order (later wins, per top-level key): baked plist → `GNUnlock.plist`
in the bundle → `Documents/GNUnlock.plist`. The last one lets you change
behaviour without a rebuild while testing.

---

## Safe mode, replaced by the bisect ladder

v7's safe mode was all-or-nothing: one bad launch and the next boot disabled
everything, which tells you that something is wrong but not what. v8 replaces it
with the ladder described at the top: one level down per failed launch, and the
level it stops at *is* the diagnosis.

`Documents/gnunlock.state` still records the phase (`boot` → `hooks` → `hooked`
→ `alive` → `patching` → `ready:patched`). `hooked` and earlier mean the process
died before `UIApplicationDidFinishLaunching`, which is what triggers a descent.
`alive` and later mean the app was up, so a crash from there on does not cost a
level.

Delete `Documents/gnunlock.bisect` to start again from `RunLevel`.

---

## Reading a failure

| In the log | Means |
|---|---|
| `run level: N - ...` | which group of hooks is installed this launch |
| `auto-bisect: previous launch stopped at 'hooked', ...` | the ladder reacted to a launch crash; the level named here is the one being tried now |
| `UNCAUGHT EXCEPTION: Name: reason` | the app's own exception; the symbolicated stack follows it line by line |
| `last crash note written to Documents/...` | the same text is on screen on the next launch |
| `notice: presented` | the diagnosis alert was shown |
| `codePatching BLOCKED` | correct for a Distribution cert; nothing will be written |
| `write refused at 0x...` | a code write was attempted and blocked — the entry is pointless in memory, move it to `gnstatic.py` |
| `... is a system image ... REFUSED` | the target is in the shared cache; intercept the caller or go offline |
| `interpose 'X': ... skipped` | C level fix not installed; set `EnableGOTRebinding` if you need it |
| `rebind 'X': N slot(s)` | data-only interception worked, N call sites redirected |
| `swizzle: class 'X' not loaded` | the class does not exist in this build — check `analysis/data/objc_classes.txt` |
| `hooks/url: forged 200 for ...` | a response was served locally |
| no log file at all | dyld killed the process before our constructor; that is a signing problem, not a tweak problem |

## v22 — the build was rejected, and the thing it was protecting could not have worked

### What the front end said

```
src/GNXPCGate.m:56:24: error: conflicting types for 'xpc_connection_create_mach_service'
src/GNXPCGate.m:187:58: error: 'xpc_connection_create_mach_service' is unavailable: not available on iOS
```

Two errors, one cause. `<xpc/connection.h>` is in scope on iOS whether or not a
file includes it, Apple declares `xpc_connection_create_mach_service` there with
`__attribute__((unavailable))` on this platform, and v21 declared it a second time
with its own spelling of the ABI and then named it in an initialiser. A
re-declaration cannot agree with a declaration that says "this function does not
exist here", and naming the function — as a call, as an address, or as the second
half of an interpose tuple — is a front-end error before the link step is reached.

This is the same class of failure as v5's `struct dyld_chained_fixups_info`: it
only exists once the real SDK is on the include path, so a check that runs without
the SDK never sees it. v21's local pre-flight was green and the runner was not.

### Why it is removed rather than worked around

There is no in-process way to interpose a function the SDK refuses to name. It
could be resolved at run time with `dlsym` — the symbol is exported — but
interposing it then needs an inline hook, i.e. a write to a code page, and
`GNCapability.m` reports `codePatching BLOCKED` on a Distribution signature. The
two honest options were "remove it" and "ship a file that cannot compile".

So v22 removes it completely: the declaration, the replacement, the table entry,
the dlsym name, and the entry in the read-surface probe list in
`GNEntitlementSlot.m` (where it never belonged — it is not a door an entitlement is
read through). The log says so on every launch, in these words:

```
xpc-gate: the mach-service variant of xpc_connection_create is unavailable on iOS
          and is not named anywhere in this dylib - a CloudKit call that uses that
          variant specifically is not covered, and this line is here so the log
          never implies it is
```

That is a real gap in coverage, stated instead of papered over. What still sits
above a CloudKit connection is `NSXPCConnection`, the stub, and the quarantine of
every void-returning work method on every class a CloudKit image defines.

### How the remaining entry point is named

```objc
extern void *GNXPCCreateReplacee(const char *name, dispatch_queue_t targetq)
    __asm__("_xpc_connection_create") __attribute__((weak_import));
```

A private identifier bound to the runtime symbol by an asm label — the same shape
`GNThrowInterpose.m` and `GNEntitlementRepairInterpose.m` already use. There is no
SDK declaration for the compiler to compare against and no identifier for an
availability attribute to attach to, so the file cannot repeat v21's failure
whatever headers arrive transitively.

`weak_import` does the other half: a process without libxpc binds the tuple half to
0 and dyld ignores it — dyld's own `interpose()` opens with "ignore interposing on a
weak function that does not exist" — so a missing symbol is a log line, not a failed
load. Because reading the identifier goes through a binding that dyld has just
redirected, the "is it bound" check reads the *tuple half*, which is the raw stored
pointer.

### The second defect, found while fixing the first

v21's rethrow and both of its call-throughs found the real function like this:

```objc
dlsym(RTLD_DEFAULT, "objc_exception_throw")
```

dyld is entitled to apply an interpose table to a dlsym result — in dyld4 every
lookup path ends in `targetAddressForDlsym = interpose(state, ...)` — and on a
launch where that happens the "real function" is this dylib's own replacement. The
rethrow then calls itself until the stack ends, and nothing in v21 could have
noticed: the table is installed and the trampoline is armed, so the log says the
gate is live.

v18 had met this risk in the entitlement repair and guarded one file's worth of it
(`GNRefuseOwnReplacement`). v21 added two more interposing files and guarded
neither. v22 puts the check in one module, `GNInterposeReal.m`, and all three
call-throughs go through it:

1. ask `dlsym`, but refuse an answer that *is* the replacement;
2. if that answer is unusable, read the replacee half of our own `__interpose`
   tuple — the pointer dyld read in order to install the replacement, so if the
   replacement is running at all, that half holds the real function;
3. if neither is trustworthy, answer NULL and let the caller degrade, rather than
   call something and hope.

Every resolution is logged with which source answered:

```
throw-interpose: original for objc_exception_throw resolved through dlsym (0x...); nothing in this file calls it by name
xpc-gate: xpc_connection_create: dlsym answered this dylib's own replacement, so the tuple half is the real function (0x...)
```

In the common case the first line appears and behaviour is exactly v21's. If the
second line appears, that launch is one that would have recursed.

### What the log tells you now

| Line | Meaning |
|---|---|
| `xpc-gate: xpc_connection_create bound at 0x...` | the C route is live; every binding of it reaches this dylib |
| `xpc-gate: ... is not usable in this process (tuple half 0x0)` | libxpc is not in this process, or the symbol is not exported; only `NSXPCConnection` is gated |
| `xpc-gate: CloudKit connection 'com.apple.cloudd' -> 'com.zaka.gnunlock.blackhole'` | a connection was actually being made, and now it is dead |
| `throw-interpose: ... resolved through dlsym` | the rethrow path is the ordinary one |
| `throw-interpose: dlsym answered this dylib's own replacement ...` | dyld interposes dlsym here; the tuple half was used, and the rethrow is not recursive |
| `xpc-gate: the mach-service variant ... is not covered` | the boundary of this file, on every launch, so the word "installed" is never read as "everything is covered" |

### What was verified

* 28 sources compiled to arm64 objects against the stub SDK, the two new files
  included.
* `scripts/stubsdk/include/xpc/xpc.h` is new, and `<Foundation/Foundation.h>` in
  the stub now includes it for the same reason the real one does. Three probes
  require the stub to answer the way the SDK answers: naming the mach-service
  variant is rejected as *unavailable*, a hand-written `xpc_connection_create` is
  rejected as a *conflicting type*, and the asm-labelled form compiles.
* The probes were rebuilt in the process. They used to compile from stdin with
  `-fsyntax-only`, and zig 0.17 fails that path inside its own libubsan
  sub-compilation ("failed to rename ... FileNotFound") — so a probe that was
  supposed to be rejected was being rejected for a reason that had nothing to do
  with the language. Every probe now compiles to a file the way the sources are
  compiled, and a probe that must fail also has to carry the expected diagnostic
  text, so it cannot pass by failing for the wrong reason.
* `v12_lint` holds 79 invariants with 79 mutations caught, six of them new for
  v22: the unavailable name appears nowhere in `src/` (checked with comments
  stripped, because the asm-label form is exactly how a name would hide from the
  compiler), the replacee is declared through an asm label, the table names that
  identifier rather than the SDK's, the resolver refuses its own replacement, the
  resolver keeps the tuple fallback, and no interposing file resolves its own
  replacee any more.

### What was not verified

The device launch. Nothing here can prove the CKException is gone: this machine
has no GoodNotes, no shared cache and no signature, so a green build only means the
tree compiles and the invariants hold. The order to read the next log in is the
same as v21's, with one addition — if the launch still dies of the same exception
and `xpc-gate` shows no redirect line at all, the daemon conversation is not going
through either entry point this dylib can name, and the next question is what
`CKContainer` was doing when it threw, not how to intercept more of CloudKit.

---

---

## What this cannot do

- Fix a bundle that dyld refuses to load. That is signing.
- Patch a system framework, ever, on any certificate.
- Guess the entitlement endpoint or a Swift offset. Both need one run with the
  log (or a capture) to pin down.
- Survive an app update: offsets and identifiers are tied to 7.1.34. Re-run the
  anchor pass instead of reusing old numbers.

`analysis/FINDINGS.md` has the purchase chain map, the anchor table and the class
list from the earlier pass.
