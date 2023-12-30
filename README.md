<div align="center">

# ids-aiml 🕵️

  ![Detective GIF](images/banner.gif)

  An IDS designed to detect network attacks using decision trees and neural networks.  

  <a href="https://github.com/oliviagallucci/README">![GitHub](https://img.shields.io/badge/github-EA4AAA.svg?style=for-the-badge&logo=github&logoColor=white)</a>
  <a href="https://github.com/oliviagallucci/ids-aiml/blob/main/LICENSE">![MIT license](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)</a>
  <a href="">![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)</a>
  <a href="https://github.com/sponsors/oliviagallucci">![Github-sponsors](https://img.shields.io/badge/sponsor-pink?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)</a>

</div>


## Project Overview

This GitHub repository contains the code and documentation for an Intrusion Detection System (IDS) developed by Derek Chan and Olivia Gallucci under the supervision of Dr. Leon Reznik. The IDS is designed to detect network attacks using decision trees and neural networks. 

## Usage Steps

### Step 1: Clone the Repository

Clone this GitHub repository to your local machine:

```bash
git clone https://github.com/your-username/ids-aiml
```

### Step 2: Navigate to the Project Directory

```bash
cd ids-aiml
```

### Step 3: Explore the Project Structure

Take a moment to explore the project structure as well as the [Weka user guide](https://oliviagallucci.com/ids-security-using-decision-trees-and-neural-networks/#weka-user-guide). Read the steps in the "Data preparation" and "Operation" sections to know how we preprocessed the data using the provided Python script (`preprocessing.py`).

### Step 4: Set Up Environment

Ensure you have Python installed along with the required libraries (pandas, numpy, sklearn, concurrent.futures). Weka is also required for the neural network module.

### Step 5: Misuse IDS

#### Design

- Use the provided Python script for misuse IDS (`misuse_ids.py`).
- Adjust parameters based on your requirements.

#### Operation

- Run the script to train and test the misuse IDS.
- Review the generated results and metrics.

### Step 6: Anomaly IDS

#### Design

- Utilize the provided [Python script](cic-ids-2017/preprocessing.py) for anomaly IDS (`anomaly_ids.py`).
- Adjust parameters as needed.

#### Operation

- Execute the script to train and test the anomaly IDS.
- Examine the results and metrics.

### Step 7: Neural Network

#### Design

- Refer to the [Weka user guide](https://oliviagallucci.com/ids-security-using-decision-trees-and-neural-networks/#weka-user-guide) for loading and preprocessing data for neural network training.
- Set hyperparameters for the Multilayer Perceptron (MLP) as described in the README.

#### Operation

- Use Weka Explorer to train and test the MLP neural network.
- Evaluate the model's performance based on accuracy and other metrics.

### Step 8: Data Analysis with Weka

- Follow the [Weka user guide's instructions](https://oliviagallucci.com/ids-security-using-decision-trees-and-neural-networks/#weka-user-guide) for loading data, preprocessing, building a machine learning model, and evaluating the model.

### Step 9: Tests and Results

- Explore the provided [test results](https://oliviagallucci.com/ids-security-using-decision-trees-and-neural-networks/#ids-results) for the IDS systems, including accuracy, training time, and memory footprint.

## Additional Information

For any questions or issues, please feel free to reach out to the project contributors listed in the README. Thank you for your interest in our intrusion detection system project! 

## Releases

* 1.0.0-alpha - testing is done by developers only

## Acknowledgements

* Derek Chen ([@dc8866](https://github.com/dc8866)) - [https://www.linkedin.com/in/yinon-chan/](https://www.linkedin.com/in/yinon-chan/)
* Olivia Gallucci ([@oliviagallucci](https://github.com/oliviagallucci)) - [https://oliviagallucci.com](https://oliviagallucci.com/)

## Warranty

### MIT 

The creator(s) of this tool provides no warranty or assurance regarding its performance, dependability, or suitability for any specific purpose.

The tool is furnished on an "as is" basis without any form of warranty, whether express or implied, encompassing, but not limited to, implied warranties of merchantability, fitness for a particular purpose, or non-infringement.

The user assumes full responsibility for employing this tool and does so at their own peril. The creator(s) holds no accountability for any loss, damage, or expenses sustained by the user or any third party due to the utilization of this tool, whether in a direct or indirect manner.

Moreover, the creator(s) explicitly renounces any liability or responsibility for the accuracy, substance, or availability of information acquired through the use of this tool, as well as for any harm inflicted by viruses, malware, or other malicious components that may infiltrate the user's system as a result of employing this tool.

By utilizing this tool, the user acknowledges that they have perused and understood this warranty declaration and agree to undertake all risks linked to its utilization.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
