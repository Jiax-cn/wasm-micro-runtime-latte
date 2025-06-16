#!/bin/bash

function timediff() {
    start_time=$1
    end_time=$2
    
    start_s=${start_time%.*}
    start_nanos=${start_time#*.}
    end_s=${end_time%.*}
    end_nanos=${end_time#*.}
    
    if [ "$end_nanos" -lt "$start_nanos" ];then
        end_s=$(( 10#$end_s - 1 ))
        end_nanos=$(( 10#$end_nanos + 10**9 ))
    fi
    
    # get timediff
    time=$(( 10#$end_s - 10#$start_s )).`printf "%03d\n" $(( (10#$end_nanos - 10#$start_nanos) ))`
    
    echo $time
}

start=$(date +"%s.%N")

for i in `seq 1 1000`:
do 
    ./iwasm ./trainer_latte.wasm
done

end=$(date +"%s.%N")

timediff $start $end