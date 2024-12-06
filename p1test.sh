#!/bin/bash

# Function to run the test case and verify the loading
run_test() {
    input=$1
    output=$2
    test_name=$3
    actual_output="actual_output_$test_name.txt"
    diff_output="diff_output_$test_name.txt"

    # Print test details
    echo "Running : $test_name"
    command_line_input=$(cat "$input")

    # Run the program with the command line arguments and capture the actual output
    ./pkgmain $command_line_input > "$actual_output"

    # Compare the actual output with the expected output
    if diff -u "$actual_output" "$output" > "$diff_output"; then
        echo -e "\033[32mPASSED: $test_name\033[0m"
    else
        echo -e "\033[31mFAILED: $test_name\033[0m"
    fi
    echo "----------------------------------------------------------------"
}

# Run all test cases
run_tests() {
    echo "Running file loading test cases..."
    echo "----------------------------------------------------------------"
    echo ""
    # Test cases
    run_test "tests/loading_tests/test_1/test_1.in" "tests/loading_tests/test_1/test_1.out" "Incorrect file format" 
    run_test "tests/loading_tests/test_2/test_2.in" "tests/loading_tests/test_2/test_2.out" "Correct file format"
    run_test "tests/loading_tests/test_3/test_3.in" "tests/loading_tests/test_3/test_3.out" "Empty bpkg file" 
    run_test "tests/loading_tests/test_4/test_4.in" "tests/loading_tests/test_4/test_4.out" "Typos in the file elements" 
    run_test "tests/loading_tests/test_5/test_5.in" "tests/loading_tests/test_5/test_5.out" "Extra information at the end of the file" 
    run_test "tests/loading_tests/test_6/test_6.in" "tests/loading_tests/test_6/test_6.out" "Size of the fields are valid" 
    run_test "tests/loading_tests/test_7/test_7.in" "tests/loading_tests/test_7/test_7.out" "Inconsistent trailing spaces for hashes" 
    run_test "tests/loading_tests/test_8/test_8.in" "tests/loading_tests/test_8/test_8.out" "Type of the fields of bpkg object" 
    run_test "tests/loading_tests/test_9/test_9.in" "tests/loading_tests/test_9/test_9.out" "Chunks are missing a field offset" 
    run_test "tests/loading_tests/test_10/test_10.in" "tests/loading_tests/test_10/test_10.out" "Hashes numbers dont match up" 
    run_test "tests/loading_tests/test_11/test_11.in" "tests/loading_tests/test_11/test_11.out" "The number of chunks has to be even" 
    run_test "tests/loading_tests/test_12/test_12.in" "tests/loading_tests/test_12/test_12.out" "Chunks are missing"
    run_test "tests/loading_tests/test_13/test_13.in" "tests/loading_tests/test_13/test_13.out" "Inconsistent trailing spaces for chunks"
    run_test "tests/loading_tests/test_14/test_14.in" "tests/loading_tests/test_14/test_14.out" "Size of one of the chunks is missing"
    run_test "tests/loading_tests/test_15/test_15.in" "tests/loading_tests/test_15/test_15.out" "n instead of nhashes"
    run_test "tests/loading_tests/test_16/test_16.in" "tests/loading_tests/test_16/test_16.out" "hashes are even"
    run_test "tests/loading_tests/test_17/test_17.in" "tests/loading_tests/test_17/test_17.out" "hash value of chunk is missing"

    echo ""
    echo ""
    echo ""
    echo ""
    echo "Running the merkle tree tests..."
    echo "----------------------------------------------------------------"
    echo ""
    run_test "tests/merkletests/test_1/test_1.in" "tests/merkletests/test_1/test_1.out" "Empty obj used on -min_hashes" 
    run_test "tests/merkletests/test_2/test_2.in" "tests/merkletests/test_2/test_2.out" "Empty obj used on -chunk_check" 
    run_test "tests/merkletests/test_3/test_3.in" "tests/merkletests/test_3/test_3.out" "Invalid value of hash - not in hashes or chunks"
    run_test "tests/merkletests/test_4/test_4.in" "tests/merkletests/test_4/test_4.out" "Invalid min completed hashes-own implementation"
    run_test "tests/merkletests/test_5/test_5.in" "tests/merkletests/test_5/test_5.out" "Missing hash values"
    run_test "tests/merkletests/test_6/test_6.in" "tests/merkletests/test_6/test_6.out" "Duplicate hash values"
    run_test "tests/merkletests/test_7/test_7.in" "tests/merkletests/test_7/test_7.out" "Data file empty"
    run_test "tests/merkletests/test_8/test_8.in" "tests/merkletests/test_8/test_8.out" "Cannot find data file"
    run_test "tests/merkletests/test_9/test_9.in" "tests/merkletests/test_9/test_9.out" "Correct min hashes"
}

# Run the tests
run_tests
