pushd cpio_files
find . -print0 | cpio --null -ov --format=newc > ../my_initramfs.cpio
popd

