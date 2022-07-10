#AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CRASHES=1 /afl/afl-fuzz -i input_$1 -o output -d -m none -t 1000+ -p fast -l 2 -c ./$1.cmplog$2 -- ./$1.$2 $3 2147483647
AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CRASHES=1 /afl/afl-fuzz -M afl-master -i input_$1  -o corpus -m none -t 1000+ -- ./$1 $2 @@ &
AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CRASHES=1 /afl/afl-fuzz -S afl-secondary -i input_$1 -o corpus -m none -t 1000+ -- ./$1 $2 @@ &
while [ ! -f /out/corpus/afl-secondary/fuzzer_stats ]
do
  sleep 2 # or less like 0.2
  echo "sleep untill find"
done
/root/.cargo/bin/symcc_fuzzing_helper -o /out/corpus -a afl-secondary -n symcc -- ./$1.symcc $2 @@
