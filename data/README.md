# Data Module

This module contains datasets and related resources used for smart contract fuzzing experiments. It provides sample inputs, test cases, and other data files necessary for evaluating and benchmarking fuzzing tools and techniques.

Currently, we have only supported for Smartbugs dataset (including 69 samples for Smartbugs-Curated and 114 samples for Smartbugs-Wild) for testing purpose.

# Example Usages

## Get supported datasets

```python
# (Optional) if you work outside the module root
# import sys
# sys.path.append(r"/path/to/workspace/")

from sc_fuzzing.data import DataLoader
print(DataLoader().get_supported_datasets())

""" Example Output
['smartbugs_wild', 'smartbugs_curated']
"""
```
## Load dataset metadata

### Smartbugs-Curated
```python
print(DataLoader().get_metadata("smartbugs_curated").head())
""" Example Output
                              name                                       project_path  primary_contract compiler_version           label
0                 fibonaccibalance  /full/path/to/sc_fuzzing/data/module/smartbugs...  FibonacciBalance           0.4.22  access_control
1  arbitrary_location_write_simple  /full/path/to/sc_fuzzing/data/module/smartbugs...            Wallet           0.4.25  access_control
2      incorrect_constructor_name1  /full/path/to/sc_fuzzing/data/module/smartbugs...           Missing           0.4.24  access_control
3      incorrect_constructor_name2  /full/path/to/sc_fuzzing/data/module/smartbugs...           Missing           0.4.24  access_control
4      incorrect_constructor_name3  /full/path/to/sc_fuzzing/data/module/smartbugs...           Missing           0.4.24  access_control
"""
```

### Smartbugs-Wild
> The SmartBugs-Wild dataset does not include labels by default, so we created them manually. A smart contract is labeled as `1` (vulnerable) if any vulnerabilities were detected by any of the tools in [Smartbugs-results](https://github.com/smartbugs/smartbugs-results).
```python
print(DataLoader().get_metadata("smartbugs_wild").head())
""" Example Output
                                                name                                       project_path primary_contract compiler_version  label
0  coostoken_24ebfc20bb2e1daadd98d28341ab37d0c154...  /full/path/to/sc_fuzzing/data/module/smartbugs...        COOSToken           0.4.20      0
1  loopringtoken_ef68e7c694f40c8202821edf525de378...  /full/path/to/sc_fuzzing/data/module/smartbugs...    LoopringToken           0.4.13      1
2  uppsalatoken_c86d054809623432210c107af2e3f619d...  /full/path/to/sc_fuzzing/data/module/smartbugs...     UppsalaToken           0.4.23      0
3  avinoctoken_f1ca9cb74685755965c7458528a36934df...  /full/path/to/sc_fuzzing/data/module/smartbugs...      AVINOCToken           0.4.24      1
4  poctoken_c9c4d9ec2b44b241361707679d3db0876ac10ca6  /full/path/to/sc_fuzzing/data/module/smartbugs...         POCToken           0.4.24      1
"""
```