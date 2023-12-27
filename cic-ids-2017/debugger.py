# Module used to debug
#
# Author: Derek Chan

import pandas as pd

def printCols(df: pd.DataFrame):
    for col in df.columns:
        print(col)