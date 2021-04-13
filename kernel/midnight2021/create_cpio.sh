
pushd cpio_files
find . | cpio --quiet -H newc -o | gzip -9 -n > ../my_initrd
popd
