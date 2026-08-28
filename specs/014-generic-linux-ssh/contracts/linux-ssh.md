# Linux/SSH transport contract

## Public operations

The client exposes typed methods only:

connection_probe(target), host_inventory(target),
filesystem_metadata_read(target, approved_root),
safe_file_read(target, approved_root, relative_path),
service_metadata_read(target, service_name),
web_server_metadata_read(target), runtime_metadata_read(target),
network_binding_read(target), storage_metadata_read(target), and
application_root_verification(target, approved_root).

No method accepts a shell string, command override, arbitrary remote path,
arbitrary provider host, sudo request, or caller-selected object prefix.

## Preconditions

The client validates target scope, credential metadata, operation ID, target
identity, expected fingerprint, and allowlists before any network call.

## Host verification

The client obtains a bounded host-key observation through the approved
verification path, computes its canonical fingerprint, and requires exact
equality with the target's pre-registered fingerprint. It then uses an
AppCare-owned target-specific known-hosts file and strict host-key checking for
the SSH command. Any mismatch aborts the operation and cannot fall back.

## Results

Results are normalized and bounded. They include status, reason code, target
binding, operation ID, counts, and safe records. They exclude credentials,
raw command text, raw remote output, and unbounded filenames.

## Side effects

The transport has no remote write side effects. The local implementation may
create or remove only disposable known-hosts/temporary state below the
AppCare-owned transport boundary. It must not write to a target host.

