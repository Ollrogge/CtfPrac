#!/bin/bash

if [[ -z $1 ]]; then
    echo "Need path"
    exit 0
fi

for f in ./output/blazing_fast_workout_planner/crashes/${1}/*; do
    ./target/runner/x86_64-unknown-linux-gnu/debug/blazing_fast_workout_planner $f

done
