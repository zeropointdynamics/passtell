# PassTell

This repository includes the artifacts for our paper "[Automatic Recovery of
Fine-grained Compiler Artifacts at the Binary Level](https://www.usenix.org/conference/atc22/presentation/du)".

Our artifacts include the dataset for our experiment in Section 6.1, Section
6.2 and 6.4, our coarse-grained compiler configuration classifier for Section
6.1, and our fine-grained compiler pass classifier for Section 6.2 and
Section 6.4.

Our artifacts require a Linux machine (or Windows Subsystem for Linux) with
the minimum of 32GB of RAM and 16GB of storage. Since our classifiers use
only shallow learning, a discrete GPU is not required. On our desktop machine
with an AMD Ryzen 7 3700X processor, the coarse-grained classifier took between
one to two hours to finish, and the fine-grained classifier took about an hour.

## File Structure
- `passtell_dataset.tar.xz`: The archive of the datasets used in the experiments
of PassTell, including: 
    - `balanced_dataset.csv`: The dataset for coarse-grained compiler configuration
    classification. As discussed in Section 6.1, this dataset is a balanced subset
    of the dataset used in NeuralCI.
    - `data.csv`: The dataset for fine-grained compiler pass classification used
    in Section 6.2.
    - `data_dynamic.csv`: The dataset for dynamic feature evaluation used in
    Section 6.4. As discussed in Section 6.4, this dataset is a subset of `data.csv`
    that only includes functions whose dynamic feature coverage are at least 70\%.
- `config_classifier.py`: The coarse-grained compiler configuration classifier.
- `passtell.py`: The fine-grained compiler pass classifier.
- `static_opcode_features.py`: Library module required for `passtell.py`.

## Dependencies
Our artifacts require the following dependencies:
- A 64-bit Linux machine with at least 32GB of RAM and 16GB of storage. We have
tested our artifacts on Arch Linux (rolling release, updated in May 2022), 
Ubuntu 20.04 (Windows Subsystem for Linux), and Fedora Workstation 36.
- Python 3. For Ubuntu and other Linux distributions that do not have a default
`python` command, setting the symbolic link from `python` to `python3` is
required. On Ubuntu, this can be done by installing the `python-is-python3`
package. Some distributions such as Fedora do not have the Python C API.
Installing the Python C API is also required. On Fedora, this can be done by
instaling the `python3-devel` package.
- Graphviz.
- The Python libraries included in `requirements.txt`. The libraries can be
installed using command `pip install -r requirements.txt`.

## Extracting the Dataset
Before running any experiment, extract the three CSV files in
`passtell_dataset.tar.xz`. Place the CSV files in the same directory as the
Python classifier files.

## Running the Coarse-grained Classifier
To reproduce the results for Section 6.1, run `python config_classifier.py`.
We use the MLJAR AutoML wrapper of LightGBM to conveniently reproduce the
confusion matrix. The classifier may report errors due to different `numpy`
version numbers, but such errors would not affect the classification. Once the
classifier terminates, the F-1 score can be found in `AutoML_1/README.md` as
the `metric_value`, and the normalized confusion matrix (Figure 2) can be
found in `AutoML_1/ 1_Default_LightGBM/confusion_matrix_normalized.png`.

Note that while Section 6.1 also includes the results from NeuralCI, the
code of NeuralCI is not part of our artifacts.

## Running the Fine-grained Classifier

### Static Features
To reproduce the results for Section 6.2, run
`python passtell.py --train_csv data.csv`. After the program terminates,
the classification results can be found in
`passtell_model/pass_classification_results.csv`. The figures showing
top features for each pass are also included in the `passtell_model`
directory. Note that due to the randomized training and testing set split,
fixes in our classifier, and different versions of the libraries, the number
of training and testing samples may have a minor variation. Similarly, due to
randomized training set, the exact top features for each pass may differ from
the top features we show in the paper (Figure 4 and Figure 5). However, the
classification results should remain similar and should still support our
findings in the paper.

### Static and Dynamic Features
To reproduce the results using both static and dynamic features for Section
6.4, run `python passtell.py --train_csv data_dynamic.csv --dynamic`. Note
that the classifier will always overwrite the result directory
`passtell_model`, so if needed, please back up the previous
`passtell_model` directory before running a new experiment. To generate
the results using only static features for Section 6.4, run the classifier
again without the `--dynamic` flag.

### Classifying Additional Binaries
After training the model using the `--train_csv` option, PassTell could be
used to classify any binary file using the `--tell` option (e.g.,
`passtell --tell my_binary --output results.csv`). The output CSV file
includes the compiler pass it detects for each function. Note that since
the classifier uses `objdump` to decompile the binary, the binary file
must include debug symbols.