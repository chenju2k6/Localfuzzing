#AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CRASHES=1 /afl/afl-fuzz -i input_$1 -o output -d -m none -t 1000+ -p fast -l 2 -c ./$1.cmplog$2 -- ./$1.$2 $3 2147483647
pro=$1
opt=$2
#AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CRASHES=1 /afl/afl-fuzz -i input_$1 -o corpus -d -m none -t 1000+ -p fast -l 2 -c ./$1.cmplog -- ./$1 $2 @@ &
AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CRASHES=1 /afl/afl-fuzz -M afl-master -i input_$1  -o corpus -m none -t 1000+ -- ./$1 $2 @@ &
AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CRASHES=1 /afl/afl-fuzz -S afl-secondary -i input_$1  -o corpus -m none -t 1000+ -- ./$1 $2 @@ &
RUST_LOG=info /Kirenenko/target/release/fastgen --sync_afl  -i input_${pro} -o corpus -t ./${pro}.track -- ./${pro}.fast ${opt} @@
