import os

def get_current_working_directory(file: os.PathLike) -> str:
    """
    Returns the current working directory.
    """
    return os.path.abspath(os.path.dirname(file))