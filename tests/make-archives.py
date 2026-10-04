#!/usr/bin/env python3
"""Create deterministic synthetic OCI/docker archives from fixture metadata only."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode()


def archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            tar.addfile(info, io.BytesIO(data))
    return output.getvalue()


root = Path(sys.argv[1])
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
layer = archive({p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()})
config = json_bytes({'architecture': 'arm64', 'os': 'linux', 'config': {},
                     'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + digest(layer)]},
                     'history': [{'created': '1970-01-01T00:00:00Z', 'created_by': 'synthetic-fixture'}]})
config_name = digest(config) + '.json'
docker_manifest = json_bytes([{'Config': config_name, 'RepoTags': ['cracken-fixture:local'], 'Layers': ['layer.tar']}])
(out/'docker.tar').write_bytes(archive({config_name: config, 'manifest.json': docker_manifest, 'layer.tar': layer}))
media_manifest = 'application/vnd.oci.image.manifest.v1+json'
manifest = json_bytes({'schemaVersion': 2, 'mediaType': media_manifest,
    'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': 'sha256:'+digest(config), 'size': len(config)},
    'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar', 'digest': 'sha256:'+digest(layer), 'size': len(layer)}]})
index = json_bytes({'schemaVersion': 2, 'manifests': [{'mediaType': media_manifest,
    'digest': 'sha256:'+digest(manifest), 'size': len(manifest), 'platform': {'architecture': 'arm64', 'os': 'linux'}}]})
(out/'oci.tar').write_bytes(archive({'oci-layout': json_bytes({'imageLayoutVersion': '1.0.0'}), 'index.json': index,
    'blobs/sha256/'+digest(config): config, 'blobs/sha256/'+digest(layer): layer, 'blobs/sha256/'+digest(manifest): manifest}))
