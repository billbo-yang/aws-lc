#!/bin/bash

if [ $# -eq 0 ]
then
    echo "Please provide the path to the test vectors directory."
    exit 1
fi
test_vectors_dir="$1"

for i in $(find ${test_vectors_dir} -name "testvector-request.json"); do
    out_dir=$(sed 's/testvector-request\.json/testvector-response\.json/g' <<< ${i})
    echo "Processing input file: ${i}"
    echo "Writing to file: ${out_dir}"
    ./acvptool -json ${i} > ${out_dir}
done

echo "done"
   
