import yaml
import os

# class for the loader of the introducer
class IntroducerLoader:
    def __init__(self, config_path=f"socp/modularImp/introducers.yaml"):
        # define config path from initialisation
        self.config_path = os.path.abspath(config_path)

    def load(self):
        """
        Function to load the introducer
        """
        if not os.path.exists(self.config_path): # if the config path does not exist
            raise FileNotFoundError(f"Introducer config not found: {self.config_path}")

        # read the data from the config path
        with open(self.config_path, "r") as f:
            data = yaml.safe_load(f)
            
        return data.get("introducer_servers", [])