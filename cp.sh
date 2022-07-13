fuzzer=$1
round=$2
for (( i=1; i<=$round; i++ )); do
	echo $i
docker cp symcc_nm${i}:/out/corpus symcc_nm${i}
docker cp symcc_readelf${i}:/out/corpus symcc_readelf${i}
docker cp symcc_objdump${i}:/out/corpus symcc_objdump${i}
docker cp symcc_size${i}:/out/corpus symcc_size${i}
docker cp symcc_tcpdump${i}:/out/corpus symcc_tcpdump${i}
docker cp symcc_tiff2pdf${i}:/out/corpus symcc_tiff2pdf${i}
docker cp symcc_libarchive${i}:/out/corpus symcc_libarchive${i}
done
