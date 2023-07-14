#!/usr/bin/python3 -u
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import tempfile
import sys
import subprocess
import hashlib

with tempfile.TemporaryDirectory() as d:
  try:

    with open("exp", "rb") as f:
        data = f.read()

    with open(f'{d}/exp', 'wb') as f:
      f.write(data)

    print('Let\'s go!')

    subprocess.check_call([
      '/usr/bin/qemu-system-x86_64',
      '-nographic',
      '-monitor', 'none',
      '-m', '512M',
      '-cpu', 'host',
      '-enable-kvm',
      '-s',
      '-no-reboot',
      '-kernel', './bzImage',
      '-drive', 'file=./rootfs.img,format=raw,if=virtio,readonly=on',
      '-drive', 'file=./flag,format=raw,if=virtio,readonly=on',
      '-append', 'console=ttyS0 kaslr kpti=1 root=/dev/vda init=/init panic=1 quiet',
      '-virtfs', f'local,readonly,mount_tag=exploit,security_model=none,path={d}',
    ])
  except Exception as e:
    print(f'Unexpected error!')
