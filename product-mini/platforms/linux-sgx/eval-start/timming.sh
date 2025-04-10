#!/bin/bash

function timediff() {

    # time format:date +"%s.%N", such as 1502758855.907197692
    start_time=$1
    end_time=$2
    
    start_s=${start_time%.*}
    start_nanos=${start_time#*.}
    end_s=${end_time%.*}
    end_nanos=${end_time#*.}
    
    # end_nanos > start_nanos? 
    # Another way, the time part may start with 0, which means
    # it will be regarded as oct format, use "10#" to ensure
    # calculateing with decimal
    if [ "$end_nanos" -lt "$start_nanos" ];then
        end_s=$(( 10#$end_s - 1 ))
        end_nanos=$(( 10#$end_nanos + 10**9 ))
    fi
    
# get timediff
    time=$(( 10#$end_s - 10#$start_s )).`printf "%03d\n" $(( (10#$end_nanos - 10#$start_nanos) ))`
    
    echo $time
}

for size in {1..5}
do 
    r_size=$(($size * 200000))

    rm -f /home/jiax/Desktop/wasm_workspace/portmr/tools/latte_builder/helloworld.wasm

    /home/jiax/Desktop/wasm_workspace/portmr/tools/insert_custom_section/latte_builder "$r_size"

    ./rebuild.sh > out.log

    start=$(date +"%s.%N")

    # Now exec some command
    for i in `seq 1 100`:
    do 
        ./iwasm ./latte_helloworld.wasm
    done

    end=$(date +"%s.%N")

    timediff $start $end
done
