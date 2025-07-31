import os
import pandas as pd

BASE_DATA_PATH = os.path.dirname(os.path.abspath(__file__))
SUPPORTED_DATASETS = ["smartbugs_wild", "smartbugs_curated"]


def get_metadata(dataset_name: str):
    """
    get metadata for the specified dataset.
    Args:
        dataset_name (str): Name of the dataset to get metadata for. Supported values are "smartbugs_wild" and "smartbugs_curated".
    Returns:
        pd.DataFrame: DataFrame containing metadata for the specified dataset.
    Raises:
        ValueError: If the dataset name is not supported.
    """

    match dataset_name:
        case "smartbugs_wild":
            meta_data_path = os.path.join(BASE_DATA_PATH, "smartbugs_wild_filter.csv")
        case "smartbugs_curated":
            meta_data_path = os.path.join(BASE_DATA_PATH, "smartbugs_curated.csv")
        case _:
            raise ValueError(
                f"Unsupported dataset: {dataset_name}. Supported datasets are: {SUPPORTED_DATASETS}"
            )

    metadata_df = pd.read_csv(meta_data_path)

    metadata_df["project_path"] = metadata_df["project_path"].apply(
        lambda x: os.path.join(BASE_DATA_PATH, x)
    )
    return metadata_df


class DataLoader:

    def get_metadata(self, dataset_name: str):
        return get_metadata(dataset_name)

    def get_supported_datasets(self):
        """
        Get the list of supported datasets.
        Returns:
            list: A list of supported dataset names.
        """
        return SUPPORTED_DATASETS
