data = '''
Index: 0, avg: 78.535400 
Index: 1, avg: 80.349609 
Index: 2, avg: 242.160645 
Index: 3, avg: 260.625488 
Index: 4, avg: 241.479980 
Index: 5, avg: 253.156006 
Index: 6, avg: 77.537109 
Index: 7, avg: 239.994873 
Index: 8, avg: 244.363281 
Index: 9, avg: 243.702148 
Index: 10, avg: 135.854248 
Index: 11, avg: 238.630371 
Index: 12, avg: 78.447754 
Index: 13, avg: 249.233154 
Index: 14, avg: 84.784424 
Index: 15, avg: 245.908203 
Index: 16, avg: 241.114990 
Index: 17, avg: 80.177490 
Index: 18, avg: 78.790771 
Index: 19, avg: 236.843994
Index: 20, avg: 239.920898
Index: 21, avg: 250.632812
Index: 22, avg: 78.851074
Index: 23, avg: 241.810303
Index: 24, avg: 78.463867
Index: 25, avg: 242.617188
Index: 26, avg: 83.313721
Index: 27, avg: 78.972656
Index: 28, avg: 243.222900
Index: 29, avg: 80.511475
Index: 30, avg: 240.274658
Index: 31, avg: 247.694824
Index: 32, avg: 237.447754
Index: 33, avg: 79.746094
Index: 34, avg: 242.966064
Index: 35, avg: 241.835693
Index: 36, avg: 258.164551
Index: 37, avg: 245.348633
Index: 38, avg: 78.951904
Index: 39, avg: 239.755371
Index: 40, avg: 262.263428
Index: 41, avg: 77.631104
Index: 42, avg: 248.975342
Index: 43, avg: 237.288574
Index: 44, avg: 76.246094
Index: 45, avg: 244.508545
Index: 46, avg: 76.266602
Index: 47, avg: 247.409668
Index: 48, avg: 74.764404
Index: 49, avg: 77.101318
Index: 50, avg: 253.333252
Index: 51, avg: 77.419189
Index: 52, avg: 91.610352
Index: 53, avg: 79.010742
Index: 54, avg: 80.728027
Index: 55, avg: 233.735107
Index: 56, avg: 83.004395
Index: 57, avg: 244.212891
Index: 58, avg: 73.508789
Index: 59, avg: 242.241699
Index: 60, avg: 243.808594
Index: 61, avg: 80.396484
Index: 62, avg: 75.869385
Index: 63, avg: 251.891846
Index: 64, avg: 247.974121
Index: 65, avg: 74.844238
Index: 66, avg: 240.980957
Index: 67, avg: 78.036865
Index: 68, avg: 77.182373
Index: 69, avg: 240.743164
Index: 70, avg: 90.146973
Index: 71, avg: 251.833984
Index: 72, avg: 80.455322
Index: 73, avg: 79.579590
Index: 74, avg: 79.908447
Index: 75, avg: 84.533203
Index: 76, avg: 87.218018
Index: 77, avg: 282.559570
Index: 78, avg: 85.518555
Index: 79, avg: 247.141846
Index: 80, avg: 244.307617
Index: 81, avg: 243.380615
Index: 82, avg: 251.504883
Index: 83, avg: 240.595703
Index: 84, avg: 79.556396
Index: 85, avg: 251.098145
Index: 86, avg: 74.790283
Index: 87, avg: 242.597168
Index: 88, avg: 75.871826
Index: 89, avg: 247.118164
Index: 90, avg: 239.154785
Index: 91, avg: 251.491211
Index: 92, avg: 246.347900
Index: 93, avg: 86.136963
Index: 94, avg: 77.264648
Index: 95, avg: 244.826172
Index: 96, avg: 233.086914
Index: 97, avg: 79.031738
Index: 98, avg: 242.546387
Index: 99, avg: 241.683105
Index: 100, avg: 108.669678
Index: 101, avg: 242.779541
Index: 102, avg: 74.584473
Index: 103, avg: 235.913330
Index: 104, avg: 235.949463
Index: 105, avg: 243.192627
Index: 106, avg: 76.136719
Index: 107, avg: 242.748779
Index: 108, avg: 72.053223
Index: 109, avg: 75.125977
Index: 110, avg: 74.959717
Index: 111, avg: 241.205566
Index: 112, avg: 75.428955
Index: 113, avg: 79.499268
Index: 114, avg: 76.067627
Index: 115, avg: 74.356934
Index: 116, avg: 76.640625
Index: 117, avg: 235.174805
Index: 118, avg: 73.937744
Index: 119, avg: 246.685547
Index: 120, avg: 86.423096
Index: 121, avg: 76.911621
Index: 122, avg: 78.292480
Index: 123, avg: 90.825439
Index: 124, avg: 276.517578
Index: 125, avg: 236.707275
Index: 126, avg: 71.258545
Index: 127, avg: 263.523926
Index: 128, avg: 79.042969
Index: 129, avg: 79.277832
Index: 130, avg: 238.838379
Index: 131, avg: 78.817871
Index: 132, avg: 240.259521
Index: 133, avg: 74.574463
Index: 134, avg: 76.028076
Index: 135, avg: 238.368896
Index: 136, avg: 76.720215
Index: 137, avg: 230.790771
Index: 138, avg: 73.390625
Index: 139, avg: 83.580811
Index: 140, avg: 73.872559
Index: 141, avg: 76.761963
Index: 142, avg: 77.777832
Index: 143, avg: 227.589844
'''

data = data.split('\n')

nums = [0]*144

i = 0
for l in data:
    if len(l) > 0:
        print(l)
        tmp = l.split(' ')[3]
        tmp2 = l.split(' ')[1][:-1]
        nums[i] = (int(tmp2), float(tmp))
        i += 1

print(nums)

idx = {}

flag = ""

for x in nums:
    i, avg = x

    i2 = i >> 3

    if avg < 110:
        if i2 not in idx:
            idx[i2] = []
            idx[i2].append(i & 7)
        else:
            idx[i2].append(i & 7)

print(idx)

for k in idx:
    bits = idx[k]
    num = 0
    for i in bits:
        num ^= (1 << i)

    flag += chr(num)


print(flag)

