#gcc -static -masm=intel -s exp.c -o exp -lpthread
#gcc -static -s sol1.c -o exp
#gcc -Xlinker -rpath=/lib -Xlinker -I/lib/ld-2.31.so -o exp sol1.c
#gcc -Xlinker -rpath=/lib -Xlinker -I/lib/ld-2.31.so -o exp2 sol1_2.c
gcc -static -s sol2.c -o exp
mv exp cpio_files
