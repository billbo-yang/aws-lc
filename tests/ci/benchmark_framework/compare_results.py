# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import sys
import pandas as pd
import numpy as np


# helper function to read json or csv file data obtained from the speed tool into a pandas dataframe
def read_data(file):
    if file.endswith(".json"):
        df = pd.read_json(file)
    else:
        # this assumes we're using a csv generated by convert_json_to_csv.py
        df = pd.read_csv(file, skiprows=1, index_col=0)
    return df


def main():
    if len(sys.argv) != 4:
        print("Usage: compare_results.py [file1] [file2] [output filename]", file=sys.stderr)
        sys.exit(1)

    file1 = sys.argv[1]
    file2 = sys.argv[2]

    if not (file1.endswith(".json") or file1.endswith(".csv")) and not (file2.endswith(".json") or file2.endswith(".csv")):
        print("Provided files must either be .json files or .csv files", file=sys.stderr)
        sys.exit(1)

    # read contents of files into a dataframe in preparation for comparison
    # note: we're assuming that the provided input is derived from the json output of the speed tool
    df1 = read_data(file1)
    df2 = read_data(file2)

    # only compare benchmarks that appear in both of the files
    # We need this because the speed tool at the time of writing has some tests that are disabled for OpenSSL
    # we're using .iloc[:, 0] here because we're filtering out rows where the content of the 0th index column in one df isn't in the other
    # details of .iloc can be found here: https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.iloc.html
    # .shape[0] represents the number of rows in the dataframe
    # details of .shape can be found here: https://pandas.pydata.org/pandas-docs/version/0.23/generated/pandas.DataFrame.shape.html
    if df1.shape[0] > df2.shape[0]:
        df1 = df1[df1.iloc[:, 0].isin(df2.iloc[:, 0])]
    elif df2.shape[0] > df1.shape[0]:
        df2 = df2[df2.iloc[:, 0].isin(df1.iloc[:, 0])]

    # reset any broken indices in the dataframe from the above
    df1.reset_index(drop=True, inplace=True)
    df2.reset_index(drop=True, inplace=True)

    # 2nd column of the dataframe represents the number of calls
    df1_numCalls = df1.iloc[:, 1]
    df2_numCalls = df2.iloc[:, 1]

    # put both dataframes side by side for comparison
    dfs = pd.concat([df1, df2], axis=1)

    # we want things that have a +15% regression
    compared = np.where(((df2_numCalls - df1_numCalls)/df1_numCalls*100 <= -15), df1.iloc[:, 0], np.nan)

    compared_df = dfs.loc[dfs.iloc[:, 0].isin(compared)]
    compared_df["Percentage Difference"] = ((compared_df.iloc[:, 5] - compared_df.iloc[:, 1])/compared_df.iloc[:, 1]*100)

    # if the compared dataframe isn't empty, there are significant regressions present
    if not compared_df.empty:
        output_file = sys.argv[3]
        if not output_file.endswith(".csv"):
            output_file += ".csv"

        # write dataframe to a csv file
        with open(output_file, "w") as f:
            f.write("{},,,,{},,,,\n".format(file1, file2))
        compared_df.to_csv(output_file, index=False, mode='a')

        # write details of regression in human-readable format to metadata.txt
        with open("metadata.txt", "a") as f:
            for index, row in compared_df.iterrows():
                f.write("Performance of {} is {}% slower in {} than {}.\n".format(
                    row[0],
                    abs(row['Percentage Difference']),
                    file2, file1))

        # exit with an error code to denote there is a regression
        print("Regression detected between {} and {}".format(file1, file2), file=sys.stderr)
        exit(5)


main()
