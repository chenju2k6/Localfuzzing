declare -a programs1=("tcpdump" "tiff2pdf" "libarchive" "objdump" "nm" "readelf" "size")
declare -A options=( ["x509"]="" ["objdump"]="-D" ["nm"]="-C" ["size"]="" ["readelf"]="-a" ["xml"]="" ["tcpdump"]="-r" ["tiff"]="" ["tiff2pdf"]="" ["openjpeg"]="" ["libarchive"]="" ["libjpeg"]="" ["libpng"]="" ["woff2"]="" ["vorbis"]="" ["proj"]="" ["re2"]="" ["harfbuzz"]="" ["lcms"]="" ["openthread"]="" ["jsoncpp"]="" ["freetype"]="")

cpu_count=$1
round=$2
for program in "${programs1[@]}"; do
for (( c=1; c<=$round; c++ )); do
  docker run --ulimit core=0 -d --name symcc_${program}${c} --cpuset-cpus "${cpu_count}" symcc timeout 24h /bin/bash /out/fuzz_symcc.sh ${program} ${options[${program}]}
  cpu_count=$((cpu_count+1))
done
done
echo $cpu_count

