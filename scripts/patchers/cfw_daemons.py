"""Daemon injection and cryptex path helpers."""

from .cfw_asm import *
import os
import plistlib

def parse_cryptex_paths(manifest_path):
    """Extract Cryptex DMG paths from BuildManifest.plist.

    Searches ALL BuildIdentities for:
    - Cryptex1,SystemOS -> Info -> Path
    - Cryptex1,AppOS -> Info -> Path

    vResearch IPSWs may have Cryptex entries in a non-first identity.
    """
    with open(manifest_path, "rb") as f:
        manifest = plistlib.load(f)

    # Search all BuildIdentities for Cryptex paths
    for bi in manifest.get("BuildIdentities", []):
        m = bi.get("Manifest", {})
        sysos = m.get("Cryptex1,SystemOS", {}).get("Info", {}).get("Path", "")
        appos = m.get("Cryptex1,AppOS", {}).get("Info", {}).get("Path", "")
        if sysos and appos:
            return sysos, appos

    print(
        "[-] Cryptex1,SystemOS/AppOS paths not found in any BuildIdentity",
        file=sys.stderr,
    )
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════
# LaunchDaemon injection
# ══════════════════════════════════════════════════════════════════


def inject_daemons(plist_path, daemon_dir):
    """Inject bash/dropbear/trollvnc entries into launchd.plist."""
    # Convert to XML first (macOS binary plist -> XML)
    subprocess.run(["plutil", "-convert", "xml1", plist_path], capture_output=True)

    with open(plist_path, "rb") as f:
        target = plistlib.load(f)

    # Inject our own daemons
    for name in ("bash", "dropbear", "trollvnc", "vphoned", "rpcserver_ios"):
        src = os.path.join(daemon_dir, f"{name}.plist")
        if not os.path.exists(src):
            print(f"  [!] Missing {src}, skipping")
            continue

        with open(src, "rb") as f:
            daemon = plistlib.load(f)

        key = f"/System/Library/LaunchDaemons/{name}.plist"
        target.setdefault("LaunchDaemons", {})[key] = daemon
        print(f"  [+] Injected {name}")

    # Strip fairplayd and fairplaydeviceidentityd daemons to prevent page faults/hangs
    daemons_dict = target.get("LaunchDaemons", {})
    keys_to_remove = []
    for key in daemons_dict.keys():
        key_lower = key.lower()
        if "fairplayd" in key_lower or "fairplaydeviceidentityd" in key_lower:
            keys_to_remove.append(key)

    for key in keys_to_remove:
        del daemons_dict[key]
        print(f"  [-] Disabled LaunchDaemon: {key}")

    with open(plist_path, "wb") as f:
        plistlib.dump(target, f, sort_keys=False)


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════

