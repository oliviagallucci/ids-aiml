# Given a directory with the machine learning CSVs from the 
# CIC IDS 2017 Intrusion Detection Evaluation Dataset (Canadian Institute for Cybersecurity)
# this script pre-processes the data and converts it into testing and training data in the arff format.
# Ready to be used by Weka, a tool for data classification created by The University of Waikato.
#
# Author: Derek Chan and Olivia Gallucci

import argparse
import os
import sys
import numpy as np
import pandas as pd
import concurrent.futures
from threading import RLock
from typing import Dict, Tuple, List
from sklearn.model_selection import train_test_split

# #################
# 
# pre-processes and normalizes a given DataFrame by 
# - removing leading spaces in col names, 
# - handling duplicate columns, 
# - filtering out attack types ("Infiltration" and "Heartbleed"), 
# - removing the label col for normalization, 
# - dropping the "Destination Port" col, 
# - applying min-max normalization to the remaining vals, 
# - replacing NaN vals w 0s, and 
# - adjusting labels based on the provided 'idsType,' such as: 
#   - treating all attacks as abnormal behavior or 
#   - updating web attack labels, 
# - ultimately returning the preprocessed DataFrame.
# 
# #################

def formatAndNormalizeDataFrame(idsType: str, attackTypes: List[str], dataFrame: pd.DataFrame) -> pd.DataFrame:
    # remove leading spaces in col names
    strippedDF = dataFrame.rename(columns=lambda col: col.strip())

    # remove duplicate col
    duplicateColumns = [col for col in strippedDF.columns if "." in col] 
    deduplicatedDF = None
    for col in duplicateColumns:
        deduplicatedDF = strippedDF.drop(col, axis=1)

    # # remove Infiltration and Heartbleed attacks bc
    # # we d/n have enough data to classify
    # filteredDF = deduplicatedDF[deduplicatedDF["Label"] != "Infiltration"]
    # filteredDF = filteredDF[filteredDF["Label"] != "Heartbleed"]

    # remove label col before normalization
    labelCol = deduplicatedDF["Label"]
    labelLessDF = deduplicatedDF.drop("Label", axis=1)

    # remove Destination Port col, 
    # there are too many unique ports, 
    # and they are nominal vals
    destinationPortlessDF = labelLessDF.drop("Destination Port", axis=1)

    # normalize vals w min-max normalization to remove bias 
    # I use min-max here because the distribution of the data 
    # may help w classification
    normalizedDF=(destinationPortlessDF-destinationPortlessDF.min()) / \
    (destinationPortlessDF.max()-destinationPortlessDF.min())

    # when we divide by 0 it results in a NaN, 
    # this replaces NaNs w 0s
    normalizedDF.fillna(0, inplace=True) 

    # Treat Infiltration and Heartbleed as "Benign" to simulate hidden attacks
    labelCol = labelCol.apply(lambda x: "BENIGN" if x == "Infiltration" or x == "Heartbleed" else x)
    
    if idsType == "anomaly":
        # treat all attacks as abnormal behavior
        labelCol = labelCol.apply(lambda x: "abnormal" if x != "BENIGN" else x)
    else:
        # update all web attacks to the same type of 
        # attack and remove spaces from the attack names
        labelCol = labelCol.apply(lambda x: "WebAttack" if "web attack" in x.lower() else x.replace(" ", ""))

    if(attackTypes != None):
        # Treat non attackType attacks as "benign" attacks
        labelCol = labelCol.apply(lambda x: "BENIGN" if attackTypes.count(x) == 0 else x)

    # re add label col
    normalizedDF["Label"] = labelCol
    return normalizedDF

# #################
# 
# input: DataFrame containing labeled data
# - separates it into groups based on val in the "Label" col
# - updates an attack dict w/ these groups, ensuring thread safety using a lock, 
# - combining data rows if label already exists in dict 
#   - or creating a new entry if it d/n
# 
# #################

def separateAttacksFromBenign(dataFrame: pd.DataFrame, attackDict: Dict[str, pd.DataFrame], attackDictLock: RLock):
    # separate dataFrame into groups by the label val
    groups = dataFrame.groupby(["Label"]) 

    # acquire a lock to ensure thread safety when updating the attack dict
    with attackDictLock:
        # for each label add it to the dict of attacks. 
        for label in groups.groups.keys():
            # if it already exists, combine the data rows.
            if label in attackDict.keys(): 
                # if it exists, concatenate data rows for 
                # the current label w/ the existing data
                attackDict[label] = pd.concat([attackDict.get(label), groups.get_group(label)])
            else:
                # if label DNE, create new entry in attack 
                # dict w current label's data
                attackDict[label] = groups.get_group(label)

# #################
# 
# input: takes an attack dict and two quantities 
# - split data w/in dict into training and testing DataFrames 
#   - while ensuring a balanced ratio of benign data in the training set,
# - and then return training and testing DataFrames
# 
# #################

def generateTrainingAndTestingDataFrame(
        attackDict: Dict[str, pd.DataFrame], qtyTrainingBenign: int, qtyTrainingEachAttack: int, attackType: str
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
    # split the data into training and testing sets, ensuring a balanced ratio of benign data in the training set.
    # 80% of the random sample will be used for training, the rest will be for testing.

    # split the benign data into training and testing sets, where 80% will be used for training and 20% for testing.
    trainingDF, testingDF = train_test_split(
        # random sample with oversampling
        attackDict.get("BENIGN").sample(qtyTrainingBenign + qtyTrainingBenign // 4), 
        test_size=0.2
    ) 
    # iterate through each label (attack type) in the attack dictionary.
    for label in attackDict.keys():
        if label != "BENIGN":  # skip the benign labels as they were already processed above.
            # split the attack data into training and testing sets, with the same 80-20 split ratio.
            trainingAttackDF, testingAttackDF = train_test_split( 
                # random sample with oversampling
                attackDict.get(label).sample(qtyTrainingEachAttack + qtyTrainingEachAttack//4), 
                test_size=0.2
            )
            # concatenate the training and testing sets with the corresponding label (attack type).
            trainingDF = pd.concat([trainingDF, trainingAttackDF])
            testingDF = pd.concat([testingDF, testingAttackDF])

    # return the resulting training and testing DataFrames.
    return trainingDF, testingDF

# #################
# 
# define a function to generate an ARFF format file from a DataFrame
# 
# #################

def generateARFF(dataFrame: pd.DataFrame, fileName: str) -> str:
    # initialize empty list to store ARFF file header lines
    trainingHeaderLines = []

    # add ARFF file header lines, including relation name
    trainingHeaderLines.append(f"@RELATION {fileName}\n\n")

    # iterate thru ea col in DataFrame
    for col in dataFrame.columns:
        if col == "Label":
            # for "Label" column, create a list of unique vals
            uniqueValues = [value for value in dataFrame[col].unique()]
                
            # create str w nominal values for "Label" attribute
            nominalValueString = "{" + ",".join(uniqueValues) + "}"
            # add ARFF attribute line for "Label" col
            trainingHeaderLines.append(f"@ATTRIBUTE Label {nominalValueString}\n")
        else:
            # for other cols, add ARFF attribute w 
            # col name (spaces removed) and data type
            trainingHeaderLines.append(f"@ATTRIBUTE {col.replace(' ', '')} NUMERIC\n")
    
    # add blank line to separate the header from data section
    trainingHeaderLines.append("\n")

    # add "@DATA" line to indicate the start of data section
    trainingHeaderLines.append("@DATA\n\n")

    # define file location for ARFF file
    fileLocation = f"./data/processedCSVs/{fileName}.arff"

    # create dir structure if it DNE
    os.makedirs(os.path.dirname(fileLocation), exist_ok=True)

    # open ARFF file for writing
    with open(fileLocation, "w") as arffFile:
        # write ARFF header lines to the file
        arffFile.writelines(trainingHeaderLines)

        # shuffle data in DataFrame before writing it to file
        shuffledDF = dataFrame.sample(frac=1)

        # save shuffled data to the ARFF file w appropriate formatting
        np.savetxt(arffFile, shuffledDF.values, delimiter=",", fmt="%s")
    
    # return msg indicating the location where the ARFF file was saved
    return f"{fileName} saved to {fileLocation}"

# #################
# 
# add data from a file to the attack dictionary
# 
# #################

def addFileDataToAttackDict(idsType: str, attackTypes: List[str], fileName: str, attackDict: Dict[str, pd.DataFrame], attackDictLock: RLock):
    rawDF = None
    try:
        # attempt to read the CSV file into a DataFrame
        rawDF = pd.read_csv(fileName)
    except:
        # if there's an err reading the file, 
        # print an err msg and exit the script
        print(f"Could not open {fileName}")
        exit(1)

    # format and normalize the DataFrame obtained from the CSV file
    formattedAndNormalizedDF = formatAndNormalizeDataFrame(idsType, attackTypes, rawDF)

    # separate attacks from benign data and add it to the attack dictionary
    separateAttacksFromBenign(formattedAndNormalizedDF, attackDict, attackDictLock)

# #################
# 
# Main control flow for the script: 
# - checks for correct num of cmg args
# - parses args
# - initializes data structures and locks for concurrent processing, 
# - reads and processes a list of files in a specified directory 
#   concurrently using a thread pool, 
# - generates training and testing DataFrames from the collected data,
# - generates ARFF files for machine learning
# 
# #################

def main():
    # check if the correct num of cmd args are provided
    parser = argparse.ArgumentParser()
    parser.add_argument("--idsType", "-idst", dest="idsType")
    parser.add_argument("--attackType", "-a", dest="attackType")
    parser.add_argument("--unprocessedDataPath", "-dp", dest="unprocessedDataPath")
    parser.add_argument("--benignTrainingQty", "-bq", dest="benignTrainingQty", type=int)
    parser.add_argument("--eachAttackTrainingQty", "-eaq", dest="eachAttackTrainingQty", type=int)
    parser.add_argument("--maxThreads", "-t", dest="maxThreads", type=int)

    args = parser.parse_args()
    # if len(sys.argv) != 6:
    #     print("Incorrect number of arguments passed")
    #     print("Usage:\tpython3 preprocessing.py [idsType] [maxThreads] [path/to/csv/directory]" + \
    #           " [qtyBenignTraining] [qtyEachAttackTraining]")
    #     exit(1)

    # parse cmd args
    idsType = args.idsType
    attackType = args.attackType
    maxThreads = args.maxThreads
    directoryName = args.unprocessedDataPath
    qtyBenign = args.benignTrainingQty
    qtyEachAttack = args.eachAttackTrainingQty

    if idsType == None or\
    maxThreads == None or \
    directoryName == None or \
    qtyBenign == None or \
    qtyEachAttack == None:
        print("Incorrect number of arguments passed")
        print("usage: preprocessing.py [-h] [--idsType IDSTYPE] [--attackType [ATTACKTYPE]] " + \
              "[--unprocessedDataPath UNPROCESSEDDATAPATH] [--benignTrainingQty BENIGNTRAININGQTY] " + \
              "[--eachAttackTrainingQty EACHATTACKTRAININGQTY] [--maxThreads MAXTHREADS]")
        exit(1)
    
    if idsType != "anomaly" and idsType != "misuse":
        print("idsType can only be anomaly or misuse")
        exit(1)

    if idsType == "anomaly" and attackType != None:
        print("attackType should only be used with a misuse idsType")
        exit(1)

    attackTypes = attackType.split("_") if attackType != None else None

    # create lock for thread synchronization
    attackDictLock = RLock()
    
    # initialize empty dict to store attack data
    attackDict = dict() # this is a [str, np.DataFrame] dict

    fileList = None
    try:
        # attempt to retrieve a list of files in the specified dir
        fileList = os.listdir(directoryName)
    except:
        # if err accessing the dir, 
        # print err mss and exit
        print(f"Cannot access {directoryName}")
        exit(1)

    with concurrent.futures.ThreadPoolExecutor(maxThreads) as threadPool:
        for fileName in fileList:
            # submit tasks to the thread pool to process ea file concurrently
            threadPool.submit(
                addFileDataToAttackDict, 
                idsType, 
                attackTypes if idsType == "misuse" else None,
                os.path.join(directoryName, fileName), 
                attackDict, 
                attackDictLock
            )

    # generate training and testing DataFrames from collected attack data
    trainingDF, testingDF = generateTrainingAndTestingDataFrame(
        attackDict, qtyBenign, qtyEachAttack, attackTypes if idsType == "misuse" else None
    )
    
    # generate ARFF files from training and testing DataFrames
    print(generateARFF(trainingDF, f"{idsType}{attackType if attackType != None else ''}TrainingData"))
    print(generateARFF(testingDF, f"{idsType}{attackType if attackType != None else ''}TestingData"))

# #################
# 
# Entry point of the script
# - calls main() when script is run directly
# 
# #################

if __name__=="__main__":
    main()
