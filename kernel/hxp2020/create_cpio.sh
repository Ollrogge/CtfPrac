pushd initramfs
find . -print0 | cpio --null -ov --format=newc | gzip -9 -n > ../my_initramfs.cpio.gz
popd

